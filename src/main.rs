use std::{
    collections::{HashMap, HashSet},
    error::Error,
    ffi::OsString,
    fs::{self, File},
    io::BufReader,
    os::windows::ffi::OsStringExt,
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

use log::{error, info, warn};
use serde::Deserialize;
use simplelog::{CombinedLogger, ConfigBuilder, LevelFilter, TermLogger, WriteLogger};
use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE as WinHandle, LUID},
        Security::{
            AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_DEBUG_NAME,
            SE_PRIVILEGE_ENABLED, TOKEN_ACCESS_MASK, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
        },
        System::{
            Diagnostics::ToolHelp::{
                CREATE_TOOLHELP_SNAPSHOT_FLAGS, CreateToolhelp32Snapshot, PROCESSENTRY32W,
                Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
            },
            ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS},
            SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX},
            Threading::{
                GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_ACCESS_RIGHTS,
                PROCESS_QUERY_INFORMATION, PROCESS_TERMINATE, TerminateProcess,
            },
        },
    },
    core::{Error as WinError, PCWSTR},
};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

mod system;
use crate::system::check_process;

const DEFAULT_CONFIG: &str = include_str!("../default_config.json");

/// Configuration structure loaded from `config.json`.
///
/// Defines thresholds and rules for process monitoring and termination.
#[derive(Deserialize, Debug)]
pub struct Config {
    /// Maximum allowed working set growth rate in megabytes per second (MB/s).
    max_working_set_growth_mb_per_sec: f64,
    /// Minimum available physical memory in megabytes (MB) before termination is considered.
    min_available_memory_mb: u64,
    /// Maximum allowed page faults per second.
    max_page_faults_per_sec: u64,
    /// Number of consecutive violations before a process is terminated.
    violations_before_termination: u32,
    /// List of process names (case-insensitive) exempt from termination.
    whitelist: Vec<String>,
    /// Path to the log file for service output.
    log_file_path: String,
    /// Log level (e.g., "debug", "info", "warn", "error", "off").
    log_level: String,
}

/// Stores historical resource usage data for a process.
///
/// Used to track memory growth and page faults over time.
#[derive(Debug)]
struct ProcessData {
    /// Previous working set size in bytes.
    prev_working_set: u64,
    /// Timestamp of the last measurement.
    prev_time: Instant,
    /// Previous page fault count.
    prev_page_faults: u32,
    /// Number of working set growth violations.
    working_set_violations: u32,
    /// Number of page fault rate violations.
    page_fault_violations: u32,
}

/// Trait for abstracting Windows API calls.
///
/// Provides a mockable interface for system calls, enabling unit testing and dependency injection.
pub trait WindowsApi {
    /// Creates a snapshot of running processes.
    fn create_toolhelp32_snapshot(
        &self,
        flags: CREATE_TOOLHELP_SNAPSHOT_FLAGS,
        process_id: u32,
    ) -> Result<WinHandle, WinError>;

    /// Retrieves the first process entry from a snapshot.
    fn process32_first_w(
        &self,
        snapshot: WinHandle,
        entry: &mut PROCESSENTRY32W,
    ) -> Result<(), WinError>;

    /// Retrieves the next process entry from a snapshot.
    fn process32_next_w(
        &self,
        snapshot: WinHandle,
        entry: &mut PROCESSENTRY32W,
    ) -> Result<(), WinError>;

    /// Opens a handle to a process with specified access rights.
    fn open_process(
        &self,
        desired_access: PROCESS_ACCESS_RIGHTS,
        inherit_handle: bool,
        process_id: u32,
    ) -> Result<WinHandle, WinError>;

    /// Retrieves memory usage information for a process.
    fn get_process_memory_info(
        &self,
        process: WinHandle,
        counters: &mut PROCESS_MEMORY_COUNTERS,
        size: u32,
    ) -> Result<(), WinError>;

    /// Terminates a process with the specified exit code.
    fn terminate_process(&self, process: WinHandle, exit_code: u32) -> Result<(), WinError>;

    /// Closes an open handle.
    fn close_handle(&self, handle: WinHandle) -> Result<(), WinError>;

    /// Retrieves system-wide memory status.
    fn global_memory_status_ex(&self, mem_info: &mut MEMORYSTATUSEX) -> Result<(), WinError>;

    /// Opens a token for a process with specified access rights.
    fn open_process_token(
        &self,
        process: WinHandle,
        desired_access: TOKEN_ACCESS_MASK,
        token_handle: &mut WinHandle,
    ) -> Result<(), WinError>;

    /// Looks up the LUID for a privilege name.
    fn lookup_privilege_value_w(
        &self,
        system_name: Option<&str>,
        name: PCWSTR,
        luid: &mut LUID,
    ) -> Result<(), WinError>;

    /// Adjusts privileges on a process token.
    fn adjust_token_privileges(
        &self,
        token_handle: WinHandle,
        disable_all_privileges: bool,
        new_state: Option<*const TOKEN_PRIVILEGES>,
        buffer_length: u32,
        previous_state: Option<*mut TOKEN_PRIVILEGES>,
        return_length: Option<*mut u32>,
    ) -> Result<(), WinError>;
}

/// Real implementation of the `WindowsApi` trait using actual Windows API calls.
pub struct RealWindowsApi;

impl WindowsApi for RealWindowsApi {
    fn create_toolhelp32_snapshot(
        &self,
        flags: CREATE_TOOLHELP_SNAPSHOT_FLAGS,
        process_id: u32,
    ) -> Result<WinHandle, WinError> {
        unsafe { CreateToolhelp32Snapshot(flags, process_id) }
    }
    fn process32_first_w(
        &self,
        snapshot: WinHandle,
        entry: &mut PROCESSENTRY32W,
    ) -> Result<(), WinError> {
        unsafe { Process32FirstW(snapshot, entry) }
    }
    fn process32_next_w(
        &self,
        snapshot: WinHandle,
        entry: &mut PROCESSENTRY32W,
    ) -> Result<(), WinError> {
        unsafe { Process32NextW(snapshot, entry) }
    }
    fn open_process(
        &self,
        desired_access: PROCESS_ACCESS_RIGHTS,
        inherit_handle: bool,
        process_id: u32,
    ) -> Result<WinHandle, WinError> {
        unsafe { OpenProcess(desired_access, inherit_handle, process_id) }
    }
    fn get_process_memory_info(
        &self,
        process: WinHandle,
        counters: &mut PROCESS_MEMORY_COUNTERS,
        size: u32,
    ) -> Result<(), WinError> {
        unsafe { GetProcessMemoryInfo(process, counters, size) }
    }
    fn terminate_process(&self, process: WinHandle, exit_code: u32) -> Result<(), WinError> {
        unsafe { TerminateProcess(process, exit_code) }
    }
    fn close_handle(&self, handle: WinHandle) -> Result<(), WinError> {
        unsafe { CloseHandle(handle) }
    }
    fn global_memory_status_ex(&self, mem_info: &mut MEMORYSTATUSEX) -> Result<(), WinError> {
        unsafe { GlobalMemoryStatusEx(mem_info) }
    }
    fn open_process_token(
        &self,
        process: WinHandle,
        desired_access: TOKEN_ACCESS_MASK,
        token_handle: &mut WinHandle,
    ) -> Result<(), WinError> {
        unsafe { OpenProcessToken(process, desired_access, token_handle) }
    }
    fn lookup_privilege_value_w(
        &self,
        _system_name: Option<&str>,
        name: PCWSTR,
        luid: &mut LUID,
    ) -> Result<(), WinError> {
        unsafe { LookupPrivilegeValueW(None, name, luid) }
    }
    fn adjust_token_privileges(
        &self,
        token_handle: WinHandle,
        disable_all_privileges: bool,
        new_state: Option<*const TOKEN_PRIVILEGES>,
        buffer_length: u32,
        previous_state: Option<*mut TOKEN_PRIVILEGES>,
        return_length: Option<*mut u32>,
    ) -> Result<(), WinError> {
        unsafe {
            AdjustTokenPrivileges(
                token_handle,
                disable_all_privileges,
                new_state,
                buffer_length,
                previous_state,
                return_length,
            )
        }
    }
}

// Service context holding the API and configuration
pub struct ServiceContext {
    api: Box<dyn WindowsApi>,
    config: Config,
}

impl ServiceContext {
    /// Creates a new `ServiceContext` with the specified API and configuration.
    ///
    /// # Arguments
    /// * `api` - A boxed trait object implementing `WindowsApi` for system calls.
    /// * `config` - The configuration defining monitoring thresholds and rules.
    ///
    /// # Errors
    /// Returns an error if the configuration is invalid.
    fn new(api: Box<dyn WindowsApi>, config: Config) -> Result<Self, Box<dyn Error>> {
        Ok(ServiceContext { api, config })
    }
}

/// Retrieves the directory containing the current executable.
///
/// # Errors
/// Returns an error if the executable path cannot be determined or has no parent directory.
fn get_exe_dir() -> Result<PathBuf, Box<dyn Error>> {
    let exe_path = std::env::current_exe()?;
    Ok(exe_path
        .parent()
        .ok_or("No parent directory for executable")?
        .to_path_buf())
}

/// Determines the path to the configuration file.
///
/// Uses the first command-line argument if provided, otherwise defaults to "config.json"
/// in the executable's directory.
///
/// # Arguments
/// * `arguments` - Slice of command-line arguments as `OsString`s.
///
/// # Errors
/// Returns an error if the executable directory cannot be determined when using the default path.
fn get_config_path(arguments: &[OsString]) -> Result<String, Box<dyn Error>> {
    if arguments.len() > 1 {
        Ok(arguments[1].to_string_lossy().into_owned())
    } else {
        Ok(get_exe_dir()?
            .join("config.json")
            .to_string_lossy()
            .into_owned())
    }
}

/// Reads the configuration from a JSON file.
///
/// Converts whitelist entries to lowercase for case-insensitive matching and sorts them for binary search.
/// Falls back to an embedded default configuration if the file at `path` cannot be opened.
///
/// # Arguments
/// * `path` - Path to the configuration file.
///
/// # Errors
/// Returns an error if the file cannot be opened and the embedded default JSON is invalid.
fn read_config(path: &str) -> Result<Config, Box<dyn Error>> {
    let mut config: Config = match File::open(path) {
        Ok(file) => {
            info!("Loaded config from {}", path);
            let reader = BufReader::new(file);
            match serde_json::from_reader(reader) {
                Ok(cfg) => cfg,
                Err(err) => {
                    warn!(
                        "Failed to parse config file {}: {}, using embedded default config",
                        path, err
                    );
                    match serde_json::from_str(DEFAULT_CONFIG) {
                        Ok(cfg) => cfg,
                        Err(default_err) => {
                            error!("Embedded default config is invalid: {}", default_err);
                            return Err(default_err.into());
                        }
                    }
                }
            }
        }
        Err(err) => {
            warn!(
                "Failed to open config file {}: {}, using embedded default config",
                path, err
            );
            match serde_json::from_str(DEFAULT_CONFIG) {
                Ok(cfg) => cfg,
                Err(default_err) => {
                    error!("Embedded default config is invalid: {}", default_err);
                    return Err(default_err.into());
                }
            }
        }
    };

    // Convert whitelist to lowercase for case-insensitive comparison
    config.whitelist = config
        .whitelist
        .into_iter()
        .map(|s: String| s.to_lowercase())
        .collect();
    config.whitelist.sort();
    Ok(config)
}

/// Sets up file logging with RFC 3339 timestamps.
///
/// Creates the log file directory if it does not exist and initializes the logger.
///
/// # Arguments
/// * `log_file` - Path to the log file.
/// * `log_level` - Logging level (e.g., `LevelFilter::Info`).
///
/// # Errors
/// Returns an error if the log file cannot be created or logging initialization fails.
fn setup_logging(log_file: &str, log_level: LevelFilter) -> Result<(), Box<dyn Error>> {
    let log_path = PathBuf::from(log_file);
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let config = ConfigBuilder::new().set_time_format_rfc3339().build();
    CombinedLogger::init(vec![WriteLogger::new(
        log_level,
        config,
        File::create(log_file)?,
    )])?;
    info!(
        "Logging initialized at {} with level {:?}",
        log_path.display(),
        log_level
    );
    Ok(())
}

/// Converts a wide-character (UTF-16) string to a Rust `String`.
///
/// Truncates at the first null character if present.
///
/// # Arguments
/// * `wide` - Slice of UTF-16 code units.
fn wide_to_string(wide: &[u16]) -> String {
    let len = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    OsString::from_wide(&wide[..len])
        .to_string_lossy()
        .into_owned()
}

/// Retrieves the total physical memory in bytes.
///
/// # Arguments
/// * `ctx` - Service context containing the API.
///
/// # Returns
/// Total memory in bytes, or 0 if the call fails (with an error logged)
pub fn get_total_memory(ctx: &ServiceContext) -> u64 {
    let mut mem_info = MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    if ctx.api.global_memory_status_ex(&mut mem_info).is_ok() {
        mem_info.ullTotalPhys
    } else {
        error!("Failed to get total memory, defaulting to 0");
        0
    }
}

/// Retrieves the available physical memory in bytes.
///
/// # Arguments
/// * `ctx` - Service context containing the API.
///
/// # Returns
/// Available memory in bytes, or 0 if the call fails (with an error logged).
fn get_available_memory(ctx: &ServiceContext) -> u64 {
    let mut mem_info = MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    if ctx.api.global_memory_status_ex(&mut mem_info).is_ok() {
        mem_info.ullAvailPhys
    } else {
        error!("Failed to get available memory, defaulting to 0");
        0
    }
}

/// Adjusts sleep duration based on system memory load using exponential scaling.
///
/// Sleep time decreases as memory load increases, ensuring faster response during high load.
///
/// # Arguments
/// * `ctx` - Service context containing the API.
///
/// # Returns
/// A `Duration` between 0.1s and 30s, or 5s if memory info is unavailable.
fn adjust_sleep_duration(ctx: &ServiceContext) -> Duration {
    const MAX_SLEEP_SECS: f64 = 30.0; // Maximum sleep time at 0% load
    const MIN_SLEEP_SECS: f64 = 0.1; // Minimum sleep time at 100% load
    const K: f64 = 3.0; // Scaling factor for steepness

    let mut mem_info = MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    if ctx.api.global_memory_status_ex(&mut mem_info).is_ok() {
        let memory_load = f64::from(mem_info.dwMemoryLoad) / 100.0; // 0.0 to 1.0
        // Exponential decay: S = S_max * e^(-k * L)
        let sleep_secs = MAX_SLEEP_SECS * (-K * memory_load).exp();
        // Clamp between min and max sleep times
        Duration::from_secs_f64(sleep_secs.clamp(MIN_SLEEP_SECS, MAX_SLEEP_SECS))
    } else {
        Duration::from_secs(5) // Default fallback if memory info unavailable
    }
}

/// Enables the `SE_DEBUG_NAME` privilege for the current process.
///
/// Required to access detailed information about all processes.
///
/// # Arguments
/// * `ctx` - Service context containing the API.
///
/// # Errors
/// Returns an error if privilege adjustment fails.
pub fn enable_se_debug_privilege(ctx: &ServiceContext) -> Result<(), Box<dyn Error>> {
    let mut token: WinHandle = WinHandle(std::ptr::null_mut());
    unsafe {
        ctx.api
            .open_process_token(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token)?;
    }

    let mut luid: LUID = unsafe { std::mem::zeroed() };
    ctx.api
        .lookup_privilege_value_w(None, SE_DEBUG_NAME, &mut luid)?;

    let tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    ctx.api
        .adjust_token_privileges(token, false, Some(&tp), 0, None, None)?;
    ctx.api.close_handle(token)?;

    Ok(())
}

/// Monitors and terminates processes exceeding resource usage thresholds.
///
/// This function takes a snapshot of running processes, tracks their memory usage and page faults,
/// and terminates those that violate configured limits after a specified number of violations.
/// System and whitelisted processes are skipped.
///
/// # Arguments
/// * `ctx` - The service context containing the API and configuration.
/// * `process_data` - A map of process IDs to their historical data.
/// * `total_memory` - Total physical memory (currently unused).
/// * `now` - The current time for calculating growth rates.
/// * `system_processes` - A map of system process IDs to their names.
/// * `first_run` - Flag indicating if this is the initial monitoring cycle.
///
/// # Errors
/// Returns an error if any Windows API call fails.
fn monitor_and_terminate(
    ctx: &ServiceContext,
    process_data: &mut HashMap<u32, ProcessData>,
    _total_memory: u64,
    now: Instant,
    system_processes: &mut HashMap<u32, String>, // PID -> process name
    first_run: &mut bool,
) -> Result<(), Box<dyn Error>> {
    let available_memory_mb = get_available_memory(ctx) >> 20;
    let snapshot = ctx.api.create_toolhelp32_snapshot(TH32CS_SNAPPROCESS, 0)?;
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut current_pids = HashSet::new();

    if ctx.api.process32_first_w(snapshot, &mut entry).is_ok() {
        loop {
            let pid = entry.th32ProcessID;
            current_pids.insert(pid);
            let process_name = wide_to_string(&entry.szExeFile).to_lowercase();

            let handle = ctx
                .api
                .open_process(PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE, false, pid)
                .map_err(|_| "Failed to open process")?;

            // On first run, populate system_processes map
            if *first_run {
                if let Ok(process_info) = check_process(handle) {
                    if process_info.is_system || process_info.is_critical {
                        system_processes.insert(pid, process_name.clone());
                    }
                } else {
                    error!("Failed to check process properties for PID: {pid}");
                }
            }

            // Skip if in system_processes cache or whitelist
            if system_processes.contains_key(&pid)
                || ctx.config.whitelist.binary_search(&process_name).is_ok()
            {
                ctx.api.close_handle(handle)?;
                if ctx.api.process32_next_w(snapshot, &mut entry).is_err() {
                    break;
                }
                continue;
            }

            let mut mem_counters = PROCESS_MEMORY_COUNTERS {
                cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
                ..Default::default()
            };
            let mem_counters_size = mem_counters.cb;
            if ctx
                .api
                .get_process_memory_info(handle, &mut mem_counters, mem_counters_size)
                .is_err()
            {
                warn!("Failed to get memory info for PID {pid}");
                ctx.api.close_handle(handle)?;
                if ctx.api.process32_next_w(snapshot, &mut entry).is_err() {
                    break;
                }
                continue;
            }

            let working_set = mem_counters.WorkingSetSize as u64;
            let page_faults = mem_counters.PageFaultCount;

            if let Some(data) = process_data.get_mut(&pid) {
                let elapsed = now - data.prev_time;
                if elapsed > Duration::from_secs(0) {
                    let delta_working_set = working_set.saturating_sub(data.prev_working_set);
                    let growth_mb_per_sec =
                        (delta_working_set as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64();
                    let delta_page_faults = page_faults.saturating_sub(data.prev_page_faults);
                    let page_fault_rate = f64::from(delta_page_faults) / elapsed.as_secs_f64();

                    if available_memory_mb < ctx.config.min_available_memory_mb
                        && growth_mb_per_sec > ctx.config.max_working_set_growth_mb_per_sec
                    {
                        data.working_set_violations += 1;
                        if data.working_set_violations >= ctx.config.violations_before_termination {
                            // Double-check ownership and critical status before termination
                            if let Ok(process_info) = check_process(handle) {
                                if !process_info.is_critical && !process_info.is_system {
                                    info!(
                                        "Terminating PID {} ({}) due to excessive working set growth ({} MB/s) after {} violations",
                                        pid,
                                        process_name,
                                        growth_mb_per_sec,
                                        data.working_set_violations
                                    );
                                    if ctx.api.terminate_process(handle, 1).is_err() {
                                        error!("Failed to terminate PID {pid}");
                                    }
                                } else {
                                    warn!(
                                        "Skipped termination of critical/system PID {pid} ({process_name})"
                                    );
                                }
                            } else {
                                error!("Failed to check process properties for PID: {pid}");
                            }
                        }
                    } else {
                        data.working_set_violations = 0;
                    }

                    if page_fault_rate > ctx.config.max_page_faults_per_sec as f64 {
                        data.page_fault_violations += 1;
                        if data.page_fault_violations >= ctx.config.violations_before_termination {
                            if let Ok(process_info) = check_process(handle) {
                                if !process_info.is_critical && !process_info.is_system {
                                    info!(
                                        "Terminating PID {} ({}) due to high page fault rate ({} faults/s) after {} violations",
                                        pid,
                                        process_name,
                                        page_fault_rate,
                                        data.page_fault_violations
                                    );
                                    if ctx.api.terminate_process(handle, 1).is_err() {
                                        error!("Failed to terminate PID {pid}");
                                    }
                                } else {
                                    warn!(
                                        "Skipped termination of critical/system PID {pid} ({process_name})"
                                    );
                                }
                            } else {
                                error!("Failed to check process properties for PID: {pid}");
                            }
                        }
                    } else {
                        data.page_fault_violations = 0;
                    }
                }
                data.prev_working_set = working_set;
                data.prev_page_faults = page_faults;
                data.prev_time = now;
            } else {
                process_data.insert(
                    pid,
                    ProcessData {
                        prev_working_set: working_set,
                        prev_time: now,
                        prev_page_faults: page_faults,
                        working_set_violations: 0,
                        page_fault_violations: 0,
                    },
                );
            }

            ctx.api.close_handle(handle)?;
            if ctx.api.process32_next_w(snapshot, &mut entry).is_err() {
                break;
            }
        }
    }

    if *first_run {
        *first_run = false; // Mark first run as complete
    }

    process_data.retain(|&pid, _| current_pids.contains(&pid));
    ctx.api.close_handle(snapshot)?;
    Ok(())
}

// Define the Windows service entry point
define_windows_service!(ffi_service_main, freeze_buster_service);

/// Main service logic for `FreezeBusterService`.
///
/// Handles service lifecycle and delegates to `run_service`.
fn freeze_buster_service(arguments: Vec<OsString>) {
    if let Err(e) = run_service(arguments) {
        error!("Service failed: {e}");
    }
}

/// Runs the service, managing process monitoring and termination.
///
/// Initializes the service context, sets up logging, and runs the monitoring loop until stopped.
///
/// # Arguments
/// * `arguments` - Command-line arguments, where the first argument can specify a config file path.
///
/// # Errors
/// Returns an error if service initialization, logging setup, or execution fails.
fn run_service(arguments: Vec<OsString>) -> Result<(), Box<dyn Error>> {
    // Bootstrap logging to stderr with a default level (e.g., Info)
    let bootstrap_config = ConfigBuilder::new().set_time_format_rfc3339().build();
    CombinedLogger::init(vec![TermLogger::new(
        LevelFilter::Info,
        bootstrap_config.clone(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Never,
    )])?;

    let config_path = get_config_path(&arguments)?;
    let config = read_config(&config_path)?;

    let log_level = match config.log_level.to_lowercase().as_str() {
        "debug" => LevelFilter::Debug,
        "info" => LevelFilter::Info,
        "trace" => LevelFilter::Trace,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        "off" => LevelFilter::Off,
        other => {
            error!("Invalid log level in config: {}", other);
            return Err(format!("Invalid log level: {}", other).into());
        }
    };

    setup_logging(&config.log_file_path, log_level)?;
    info!("Using config from {}: {:?}", config_path, config);

    let api = Box::new(RealWindowsApi);
    let ctx = ServiceContext::new(api, config)?;
    if let Err(e) = enable_se_debug_privilege(&ctx) {
        warn!(
            "Failed to enable SE_DEBUG_NAME privilege: {}. Running with limited access.",
            e
        )
    }

    // Allocate stop on the heap and leak it to give it a 'static lifetime
    let stop: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(false)));

    let status_handle =
        service_control_handler::register("FreezeBusterService", move |control_event| {
            match control_event {
                ServiceControl::Stop => {
                    info!("Received stop signal");
                    stop.store(true, Ordering::SeqCst);
                    ServiceControlHandlerResult::NoError
                }
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        })?;

    // Set service to Running state
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(0),
        process_id: None,
    })?;

    let mut process_data = HashMap::new();
    let total_memory = get_total_memory(&ctx);
    let mut system_processes = HashMap::new();
    let mut first_run = true;
    let mut retry_count = 0;

    while !stop.load(Ordering::SeqCst) {
        let now = Instant::now();
        if let Err(e) = monitor_and_terminate(
            &ctx,
            &mut process_data,
            total_memory,
            now,
            &mut system_processes,
            &mut first_run,
        ) {
            error!("Monitoring error: {e}");
            retry_count += 1;
            if retry_count > 3 {
                error!("Too many monitoring failures, shutting down.");
                break;
            }
        } else {
            retry_count = 0;
        }
        let sleep_duration = adjust_sleep_duration(&ctx);
        thread::sleep(sleep_duration);
    }

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(0),
        process_id: None,
    })?;

    info!("Service stopped.");
    Ok(())
}

/// Entry point for the `FreezeBusterService`.
///
/// Starts the Windows service dispatcher for "FreezeBusterService".
///
/// # Errors
/// Returns an error if the service dispatcher fails to start.
fn main() -> Result<(), Box<dyn Error>> {
    // Start the service
    service_dispatcher::start("FreezeBusterService", ffi_service_main)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Write};

    use tempfile::TempDir;

    use super::*;

    // Helper function to create a temp config file
    fn create_temp_config(content: &str) -> (TempDir, String) {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("config.json");
        let mut file = File::create(&file_path).unwrap();
        file.write_all(content.as_bytes()).unwrap();
        (dir, file_path.to_string_lossy().into_owned())
    }

    #[test]
    fn test_read_config_valid() {
        let config_json = r#"
            {
                "max_working_set_growth_mb_per_sec": 10.0,
                "min_available_memory_mb": 512,
                "max_page_faults_per_sec": 1000,
                "violations_before_termination": 3,
                "whitelist": ["notepad.exe", "explorer.exe"],
                "log_file_path": "log.txt",
                "log_level": "info"
            }
        "#;
        let (_dir, path) = create_temp_config(config_json);

        let result = read_config(&path);
        assert!(result.is_ok());

        let config = result.unwrap();
        assert_eq!(config.max_working_set_growth_mb_per_sec, 10.0);
        assert_eq!(config.min_available_memory_mb, 512);
        assert_eq!(config.max_page_faults_per_sec, 1000);
        assert_eq!(config.violations_before_termination, 3);
        assert_eq!(config.whitelist, vec!["explorer.exe", "notepad.exe"]); // Sorted and lowercase
        assert_eq!(config.log_file_path, "log.txt");
        assert_eq!(config.log_level, "info");
    }

    #[test]
    fn test_read_config_invalid_json() {
        let config_json = "invalid json content";
        let (_dir, path) = create_temp_config(config_json);

        let result = read_config(&path);
        assert!(
            result.is_ok(),
            "Should fall back to default config for invalid JSON"
        );

        let config = result.unwrap();
        assert_eq!(config.max_working_set_growth_mb_per_sec, 10.0);
        assert_eq!(config.min_available_memory_mb, 500);
        assert_eq!(config.max_page_faults_per_sec, 1000);
        assert_eq!(config.violations_before_termination, 3);
        assert_eq!(config.whitelist, vec!["explorer.exe", "notepad.exe"]);
        assert_eq!(
            config.log_file_path,
            "C:\\ProgramData\\FreezeBuster\\service.log"
        );
        assert_eq!(config.log_level, "warn");
    }

    #[test]
    fn test_read_config_missing_fields() {
        let config_json = r#"
        {
            "min_available_memory_mb": 512,
            "whitelist": ["notepad.exe"]
        }
        "#; // Missing required fields
        let (_dir, path) = create_temp_config(config_json);

        let result = read_config(&path);
        assert!(
            result.is_ok(),
            "Should fall back to default config for missing fields"
        );

        let config = result.unwrap();
        assert_eq!(config.max_working_set_growth_mb_per_sec, 10.0);
        assert_eq!(config.min_available_memory_mb, 500);
        assert_eq!(config.max_page_faults_per_sec, 1000);
        assert_eq!(config.violations_before_termination, 3);
        assert_eq!(config.whitelist, vec!["explorer.exe", "notepad.exe"]);
        assert_eq!(
            config.log_file_path,
            "C:\\ProgramData\\FreezeBuster\\service.log"
        );
        assert_eq!(config.log_level, "warn");
    }

    #[test]
    fn test_read_config_empty_file() {
        let (_dir, path) = create_temp_config("");
        println!("DEFAULT_CONFIG: '{}'", DEFAULT_CONFIG);
        let result = read_config(&path);
        if result.is_err() {
            println!("Error from read_config: {:?}", result.as_ref().err());
        }
        assert!(
            result.is_ok(),
            "Should fall back to default config for empty file"
        );

        let config = result.unwrap();
        assert_eq!(config.max_working_set_growth_mb_per_sec, 10.0);
        assert_eq!(config.min_available_memory_mb, 500);
        assert_eq!(config.max_page_faults_per_sec, 1000);
        assert_eq!(config.violations_before_termination, 3);
        assert_eq!(config.whitelist, vec!["explorer.exe", "notepad.exe"]);
        assert_eq!(
            config.log_file_path,
            "C:\\ProgramData\\FreezeBuster\\service.log"
        );
        assert_eq!(config.log_level, "warn");
    }

    #[test]
    fn test_service_context_new_valid() {
        let config = Config {
            max_working_set_growth_mb_per_sec: 10.0,
            min_available_memory_mb: 512,
            max_page_faults_per_sec: 1000,
            violations_before_termination: 3,
            whitelist: vec!["Notepad.EXE".to_string().to_lowercase()],
            log_file_path: "log.txt".to_string(),
            log_level: "info".to_string(),
        };
        let api = Box::new(RealWindowsApi);
        let result = ServiceContext::new(api, config);
        assert!(result.is_ok());
        let ctx = result.unwrap();
        assert_eq!(ctx.config.whitelist, vec!["notepad.exe"]);
        assert_eq!(ctx.config.log_file_path, "log.txt");
        assert_eq!(ctx.config.log_level, "info");
    }

    #[test]
    fn test_read_config_fallback_to_default() {
        let path = "non_existent_config.json";
        let result = read_config(path);
        assert!(result.is_ok(), "Should fall back to default config");
        let config = result.unwrap();
        assert_eq!(config.max_working_set_growth_mb_per_sec, 10.0);
        assert_eq!(config.min_available_memory_mb, 500);
        assert_eq!(config.max_page_faults_per_sec, 1000);
        assert_eq!(config.violations_before_termination, 3);
        assert_eq!(config.whitelist, vec!["explorer.exe", "notepad.exe"]);
        assert_eq!(
            config.log_file_path,
            "C:\\ProgramData\\FreezeBuster\\service.log"
        );
        assert_eq!(config.log_level, "warn");
    }

    #[test]
    fn test_read_config_whitelist_case_insensitivity() {
        let config_json = r#"
        {
            "max_working_set_growth_mb_per_sec": 10.0,
            "min_available_memory_mb": 512,
            "max_page_faults_per_sec": 1000,
            "violations_before_termination": 3,
            "whitelist": ["Notepad.EXE", "EXPLORER.exe"],
            "log_file_path": "log.txt",
            "log_level": "info"
        }
        "#;
        let (_dir, path) = create_temp_config(config_json);
        let config = read_config(&path).unwrap();
        assert_eq!(config.whitelist, vec!["explorer.exe", "notepad.exe"]);
    }

    #[test]
    fn test_default_config_validity() {
        let default_config = r#"
        {
            "max_working_set_growth_mb_per_sec": 10.0,
            "min_available_memory_mb": 512,
            "max_page_faults_per_sec": 1000,
            "violations_before_termination": 3,
            "whitelist": [],
            "log_file_path": "log.txt",
            "log_level": "info"
        }
        "#;
        let config = serde_json::from_str(default_config).expect("Default config should be valid");
        let Config { whitelist, .. } = config;
        assert_eq!(whitelist, Vec::<String>::new());
        assert_eq!(config.log_file_path, "log.txt");
        assert_eq!(config.log_level, "info");
    }

    #[test]
    fn test_read_config_invalid_types() {
        let config_json = r#"
        {
            "max_working_set_growth_mb_per_sec": "invalid",
            "min_available_memory_mb": 512,
            "max_page_faults_per_sec": 1000,
            "violations_before_termination": 3,
            "whitelist": [],
            "log_file_path": "log.txt",
            "log_level": "info"
        }
        "#;
        let (_dir, path) = create_temp_config(config_json);
        let result = read_config(&path);
        assert!(
            result.is_ok(),
            "Should fall back to default config for invalid types"
        );

        let config = result.unwrap();
        assert_eq!(config.max_working_set_growth_mb_per_sec, 10.0);
        assert_eq!(config.min_available_memory_mb, 500);
        assert_eq!(config.max_page_faults_per_sec, 1000);
        assert_eq!(config.violations_before_termination, 3);
        assert_eq!(config.whitelist, vec!["explorer.exe", "notepad.exe"]);
        assert_eq!(
            config.log_file_path,
            "C:\\ProgramData\\FreezeBuster\\service.log"
        );
        assert_eq!(config.log_level, "warn");
    }

    #[test]
    fn test_get_config_path_from_args() {
        let args = vec![
            OsString::from("freezebuster.exe"),
            OsString::from("C:\\custom\\config.json"),
        ];
        let path = get_config_path(&args).unwrap();
        assert_eq!(path, "C:\\custom\\config.json");
    }

    #[test]
    fn test_get_config_path_default() {
        let args = vec![OsString::from("freezebuster.exe")];
        let path = get_config_path(&args).unwrap();
        assert!(
            path.ends_with("config.json"),
            "Path should end with 'config.json': {}",
            path
        );
        assert!(!path.is_empty(), "Path should not be empty");
    }

    #[test]
    fn test_wide_to_string() {
        let wide = vec![72, 101, 108, 108, 111, 0]; // "Hello" in UTF-16
        let result = wide_to_string(&wide);
        assert_eq!(result, "Hello");

        let empty = vec![0];
        let result = wide_to_string(&empty);
        assert_eq!(result, "");
    }

    // Mock ProcessData for testing growth calculations
    #[test]
    fn test_process_data_growth_calculation() {
        use std::time::{Duration, Instant};

        let start_time = Instant::now();
        let elapsed = Duration::from_secs(1);
        let prev_time = start_time.checked_sub(elapsed).unwrap();

        let process_data = ProcessData {
            prev_working_set: 10_485_760, // 10 MB
            prev_time,
            prev_page_faults: 100,
            working_set_violations: 0,
            page_fault_violations: 0,
        };

        let now = start_time;
        let current_working_set = 20_971_520; // 20 MB
        let current_page_faults = 150;

        let elapsed = now.duration_since(process_data.prev_time).as_secs_f64();
        let delta_working_set = current_working_set - process_data.prev_working_set;
        let growth_mb_per_sec = (delta_working_set as f64 / (1024.0 * 1024.0)) / elapsed;
        let delta_page_faults = current_page_faults - process_data.prev_page_faults;
        let page_fault_rate = f64::from(delta_page_faults) / elapsed;

        assert!(growth_mb_per_sec > 9.0 && growth_mb_per_sec < 11.0);
        assert_eq!(page_fault_rate as u32, 50); // 50 page faults per second
    }

    #[cfg(test)]
    mod mock_tests;
}
