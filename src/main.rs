use std::{
    collections::{HashMap, HashSet},
    error::Error,
    ffi::OsString,
    fs::File,
    os::windows::ffi::OsStringExt,
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

use log::{error, info, warn};
use serde::Deserialize;
use simplelog::{CombinedLogger, ConfigBuilder, LevelFilter, WriteLogger};
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

/// Configuration structure loaded from `config.json`.
///
/// Defines thresholds and rules for process monitoring and termination.
#[derive(Deserialize, Debug)]
struct Config {
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
        unsafe { Process32FirstW(snapshot, entry).map(|_| ()) }
    }
    fn process32_next_w(
        &self,
        snapshot: WinHandle,
        entry: &mut PROCESSENTRY32W,
    ) -> Result<(), WinError> {
        unsafe { Process32NextW(snapshot, entry).map(|_| ()) }
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
        unsafe { GetProcessMemoryInfo(process, counters, size).map(|_| ()) }
    }
    fn terminate_process(&self, process: WinHandle, exit_code: u32) -> Result<(), WinError> {
        unsafe { TerminateProcess(process, exit_code).map(|_| ()) }
    }
    fn close_handle(&self, handle: WinHandle) -> Result<(), WinError> {
        unsafe { CloseHandle(handle).map(|_| ()) }
    }
    fn global_memory_status_ex(&self, mem_info: &mut MEMORYSTATUSEX) -> Result<(), WinError> {
        unsafe { GlobalMemoryStatusEx(mem_info).map(|_| ()) }
    }
    fn open_process_token(
        &self,
        process: WinHandle,
        desired_access: TOKEN_ACCESS_MASK,
        token_handle: &mut WinHandle,
    ) -> Result<(), WinError> {
        unsafe { OpenProcessToken(process, desired_access, token_handle).map(|_| ()) }
    }
    fn lookup_privilege_value_w(
        &self,
        _system_name: Option<&str>,
        name: PCWSTR,
        luid: &mut LUID,
    ) -> Result<(), WinError> {
        unsafe { LookupPrivilegeValueW(None, name, luid).map(|_| ()) }
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
            .map(|_| ())
        }
    }
}

// Service context holding the API and configuration
pub struct ServiceContext {
    api: Box<dyn WindowsApi>,
    config: Config,
}

impl ServiceContext {
    /// Creates a new `ServiceContext` with the given API and configuration file path.
    ///
    /// # Arguments
    /// * `api` - A boxed trait object implementing `WindowsApi`.
    /// * `config_path` - Path to the JSON configuration file.
    ///
    /// # Errors
    /// Returns an error if the configuration file cannot be read or parsed.
    fn new(api: Box<dyn WindowsApi>, config_path: &str) -> Result<Self, Box<dyn Error>> {
        Ok(ServiceContext {
            api,
            config: read_config(config_path)?,
        })
    }
}

/// Reads the configuration from a JSON file.
///
/// Converts whitelist entries to lowercase for case-insensitive matching and sorts them for binary search.
///
/// # Arguments
/// * `path` - Path to the configuration file.
///
/// # Errors
/// Returns an error if the file cannot be opened or the JSON is invalid.
fn read_config(path: &str) -> Result<Config, Box<dyn Error>> {
    let file = File::open(path)?;
    let mut config: Config = serde_json::from_reader(file)?;
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
/// # Arguments
/// * `log_file` - Path to the log file.
///
/// # Errors
/// Returns an error if the log file cannot be created or logging initialization fails.
fn setup_logging(log_file: &str) -> Result<(), Box<dyn Error>> {
    let config = ConfigBuilder::new().set_time_format_rfc3339().build();
    CombinedLogger::init(vec![WriteLogger::new(
        LevelFilter::Warn,
        config,
        File::create(log_file)?,
    )])?;
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
fn get_total_memory(ctx: &ServiceContext) -> u64 {
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

/// Enables the SE_DEBUG_NAME privilege for the current process.
///
/// Required to access detailed information about all processes.
///
/// # Arguments
/// * `ctx` - Service context containing the API.
///
/// # Errors
/// Returns an error if privilege adjustment fails.
fn enable_se_debug_privilege(ctx: &ServiceContext) -> Result<(), Box<dyn Error>> {
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

/// Main service logic for FreezeBusterService.
///
/// Handles service lifecycle and delegates to `run_service`.
fn freeze_buster_service(arguments: Vec<std::ffi::OsString>) {
    if let Err(e) = run_service(arguments) {
        error!("Service failed: {e}");
    }
}

/// Runs the service, managing process monitoring and termination.
///
/// # Arguments
/// * `arguments` - Command-line arguments (currently unused).
///
/// # Errors
/// Returns an error if service initialization or execution fails.
fn run_service(_arguments: Vec<std::ffi::OsString>) -> Result<(), Box<dyn Error>> {
    let api = Box::new(RealWindowsApi);
    let ctx = ServiceContext::new(api, "config.json")?;
    enable_se_debug_privilege(&ctx)?;

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

/// Entry point for the FreezeBusterService.
///
/// Initializes logging and starts the service dispatcher.
///
/// # Errors
/// Returns an error if logging setup or service startup fails.
fn main() -> Result<(), Box<dyn Error>> {
    let config_path = "config.json";

    // Initialize logging to service.log
    let log_path = "service.log";
    setup_logging(log_path)?;

    let api = Box::new(RealWindowsApi);
    let ctx = ServiceContext::new(api, config_path)?;

    info!(
        "FreezeBusterService starting with config: {0:?}",
        ctx.config
    );

    // Start the service
    service_dispatcher::start("FreezeBusterService", ffi_service_main)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Write, path::Path};

    use serde_json;
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
                "whitelist": ["notepad.exe", "explorer.exe"]
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
        assert_eq!(config.whitelist, vec!["explorer.exe", "notepad.exe"]); // Note: sorted and lowercase
    }

    #[test]
    fn test_read_config_invalid_json() {
        let config_json = "invalid json content";
        let (_dir, path) = create_temp_config(config_json);

        let result = read_config(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_config_missing_file() {
        let result = read_config("non_existent_config.json");
        assert!(result.is_err());
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

    #[test]
    fn test_adjust_sleep_duration() {
        // This is tricky to test precisely due to system calls, but we can verify boundaries
        let duration = adjust_sleep_duration();
        assert!(duration.as_secs_f64() >= 0.1); // MIN_SLEEP_SECS
        assert!(duration.as_secs_f64() <= 30.0); // MAX_SLEEP_SECS
    }

    // Mock ProcessData for testing growth calculations
    #[test]
    fn test_process_data_growth_calculation() {
        use std::time::{Duration, Instant};

        let start_time = Instant::now();
        let elapsed = Duration::from_secs(1);
        let prev_time = start_time - elapsed;

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
        let page_fault_rate = delta_page_faults as f64 / elapsed;

        assert!(growth_mb_per_sec > 9.0 && growth_mb_per_sec < 11.0);
        assert_eq!(page_fault_rate as u32, 50); // 50 page faults per second
    }

    // Integration test suggestion (cannot run in standard test environment)
    #[test]
    #[ignore]
    fn test_monitor_and_terminate() {
        // This would require:
        // 1. Mocking Windows API calls (CreateToolhelp32Snapshot, etc.)
        // 2. Simulating process memory usage
        // 3. Verifying termination logic
        // Suggested approach:
        // - Use a mocking crate like `mockall`
        // - Create mock processes with controlled memory growth
        // - Test whitelist, violation counting, and termination logic
        let config = Config {
            max_working_set_growth_mb_per_sec: 5.0,
            min_available_memory_mb: 1024,
            max_page_faults_per_sec: 1000,
            violations_before_termination: 2,
            whitelist: vec!["test.exe".to_string()],
        };
        let mut process_data = HashMap::new();
        let total_memory = 8_589_934_592; // 8 GB
        let now = Instant::now();
        let mut system_processes = HashMap::new();
        let mut first_run = true;

        // Mock setup would go here
        let result = monitor_and_terminate(
            &config,
            &mut process_data,
            total_memory,
            now,
            &mut system_processes,
            &mut first_run,
        );
        assert!(result.is_ok());
    }
}
