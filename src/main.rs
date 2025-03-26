mod system;

use std::{
    collections::{HashMap, HashSet},
    error::Error,
    ffi::OsString,
    fs::File,
    os::windows::ffi::OsStringExt,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

// For logging
use log::{error, info, warn};
// For serialization:deserialization of the configuration
use serde::Deserialize;
use simplelog::{CombinedLogger, ConfigBuilder, LevelFilter, WriteLogger};
use windows::Win32::{
    Foundation::{CloseHandle, HANDLE, LUID},
    Security::{
        AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_DEBUG_NAME,
        SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
    },
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
            TH32CS_SNAPPROCESS,
        },
        ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS},
        SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX},
        Threading::{
            GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION,
            PROCESS_TERMINATE, TerminateProcess,
        },
    },
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

use crate::system::check_process;

/// Configuration structure loaded from config.json
#[derive(Deserialize, Debug)]
struct Config {
    max_working_set_growth_mb_per_sec: f64, // Max growth rate of working set (MB/sec)
    min_available_memory_mb: u64,           // Minimum available physical memory (MB)
    max_page_faults_per_sec: u64,
    violations_before_termination: u32,
    whitelist: Vec<String>,
}

/// Stores previous resource usage data for a process
struct ProcessData {
    prev_working_set: u64, // Previous working set size (bytes)
    prev_time: Instant,    // Time of last measurement
    prev_page_faults: u32,
    working_set_violations: u32,
    page_fault_violations: u32,
}

// Define the Windows service entry point
define_windows_service!(ffi_service_main, freeze_buster_service);

fn main() -> Result<(), Box<dyn Error>> {
    // Read configuration from config.json
    let config_path = "config.json";
    let config = read_config(config_path)?;

    // Initialize logging to service.log
    let log_path = "service.log";
    setup_logging(log_path)?;

    info!("FreezeBusterService starting with config: {:?}", config);

    // Start the service
    service_dispatcher::start("FreezeBusterService", ffi_service_main)?;
    Ok(())
}

/// Service logic
fn freeze_buster_service(arguments: Vec<std::ffi::OsString>) {
    if let Err(e) = run_service(arguments) {
        error!("Service failed: {}", e);
    }
}

fn enable_se_debug_privilege() -> Result<(), Box<dyn Error>> {
    let mut token: HANDLE = HANDLE(std::ptr::null_mut());
    unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token)?;
    }

    let mut luid: LUID = unsafe { std::mem::zeroed() };
    unsafe {
        LookupPrivilegeValueW(None, SE_DEBUG_NAME, &mut luid)?;
    }

    let tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    unsafe {
        AdjustTokenPrivileges(token, false, Some(&tp as *const _), 0, None, None)?;
        CloseHandle(token)?;
    }

    Ok(())
}

fn run_service(_arguments: Vec<std::ffi::OsString>) -> Result<(), Box<dyn Error>> {
    let config = read_config("config.json")?;
    enable_se_debug_privilege()?;

    let status_handle = service_control_handler::register(
        "FreezeBusterService",
        |control_event| match control_event {
            ServiceControl::Stop => {
                info!("Received stop signal");
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        },
    )?;

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
    let total_memory = get_total_memory();
    let mut system_processes = HashMap::new();
    let mut first_run = true;

    let stop = AtomicBool::new(false);
    while !stop.load(Ordering::SeqCst) {
        let now = Instant::now();
        if let Err(e) = monitor_and_terminate(
            &config,
            &mut process_data,
            total_memory,
            now,
            &mut system_processes,
            &mut first_run,
        ) {
            error!("Monitoring error: {}", e)
        }
        let sleep_duration = adjust_sleep_duration();
        std::thread::sleep(sleep_duration);
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

/// Reads the configuration from a JSON file
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

/// Sets up file logging with timestamps
fn setup_logging(log_file: &str) -> Result<(), Box<dyn Error>> {
    let config = ConfigBuilder::new().set_time_format_rfc3339().build();
    CombinedLogger::init(vec![WriteLogger::new(
        LevelFilter::Warn,
        config,
        File::create(log_file)?,
    )])?;
    Ok(())
}

/// Retrieves the total physical memory in bytes.
///
/// Returns 0 if the call fails, logging an error.
fn get_total_memory() -> u64 {
    let mut mem_info = MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    if unsafe { GlobalMemoryStatusEx(&mut mem_info) }.is_ok() {
        mem_info.ullTotalPhys
    } else {
        error!("Failed to get total memory, defaulting to 0");
        0
    }
}

/// Retrieves the available physical memory in bytes.
///
/// Returns 0 if the call fails, logging an error.
fn get_available_memory() -> u64 {
    let mut mem_info = MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    if unsafe { GlobalMemoryStatusEx(&mut mem_info) }.is_ok() {
        mem_info.ullAvailPhys
    } else {
        error!("Failed to get available memory, defaulting to 0");
        0
    }
}

/// Adjusts sleep duration using exponential scaling based on memory load.
///
/// Sleep time decreases exponentially as memory load increases, ensuring rapid response
/// during high pressure and reduced overhead during low pressure.
fn adjust_sleep_duration() -> Duration {
    const MAX_SLEEP_SECS: f64 = 30.0; // Maximum sleep time at 0% load
    const MIN_SLEEP_SECS: f64 = 0.1; // Minimum sleep time at 100% load
    const K: f64 = 3.0; // Scaling factor for steepness

    let mut mem_info = MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    if unsafe { GlobalMemoryStatusEx(&mut mem_info) }.is_ok() {
        let memory_load = mem_info.dwMemoryLoad as f64 / 100.0; // 0.0 to 1.0
        // Exponential decay: S = S_max * e^(-k * L)
        let sleep_secs = MAX_SLEEP_SECS * (-K * memory_load).exp();
        // Clamp between min and max sleep times
        Duration::from_secs_f64(sleep_secs.clamp(MIN_SLEEP_SECS, MAX_SLEEP_SECS))
    } else {
        Duration::from_secs(5) // Default fallback if memory info unavailable
    }
}

/// Monitors processes and terminates them based on primary and fallback strategies.
fn monitor_and_terminate(
    config: &Config,
    process_data: &mut HashMap<u32, ProcessData>,
    _total_memory: u64,
    now: Instant,
    system_processes: &mut HashMap<u32, String>, // PID -> process name
    first_run: &mut bool,
) -> Result<(), Box<dyn Error>> {
    let available_memory_mb = get_available_memory() >> 20;
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }?;
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut current_pids = HashSet::new();

    if unsafe { Process32FirstW(snapshot, &mut entry) }.is_ok() {
        loop {
            let pid = entry.th32ProcessID;
            current_pids.insert(pid);
            let process_name = wide_to_string(&entry.szExeFile).to_lowercase();

            let handle =
                unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE, false, pid) }
                    .map_err(|_| "Failed to open process")?;

            // On first run, populate system_processes map
            if *first_run {
                if let Ok(process_info) = check_process(handle) {
                    if process_info.is_system || process_info.is_critical {
                        system_processes.insert(pid, process_name.clone());
                    }
                } else {
                    error!("Failed to check process properties for PID: {}", pid);
                }
            }

            // Skip if in system_processes cache or whitelist
            if system_processes.contains_key(&pid)
                || config.whitelist.binary_search(&process_name).is_ok()
            {
                unsafe { CloseHandle(handle) }?;
                if unsafe { Process32NextW(snapshot, &mut entry) }.is_err() {
                    break;
                }
                continue;
            }

            let mut mem_counters = PROCESS_MEMORY_COUNTERS {
                cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
                ..Default::default()
            };
            if unsafe { GetProcessMemoryInfo(handle, &mut mem_counters, mem_counters.cb) }.is_err()
            {
                warn!("Failed to get memory info for PID {}", pid);
                unsafe { CloseHandle(handle) }?;
                if unsafe { Process32NextW(snapshot, &mut entry) }.is_err() {
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
                        (delta_working_set as f64 / (2 << 20) as f64) / elapsed.as_secs_f64();
                    let delta_page_faults = page_faults.saturating_sub(data.prev_page_faults);
                    let page_fault_rate = delta_page_faults as f64 / elapsed.as_secs_f64();

                    if available_memory_mb < config.min_available_memory_mb
                        && growth_mb_per_sec > config.max_working_set_growth_mb_per_sec
                    {
                        data.working_set_violations += 1;
                        if data.working_set_violations >= config.violations_before_termination {
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
                                    if unsafe { TerminateProcess(handle, 1) }.is_err() {
                                        error!("Failed to terminate PID {}", pid);
                                    }
                                } else {
                                    warn!(
                                        "Skipped termination of critical/system PID {} ({})",
                                        pid, process_name
                                    );
                                }
                            } else {
                                error!("Failed to check process properties for PID: {}", pid);
                            }
                        }
                    } else {
                        data.working_set_violations = 0;
                    }

                    if page_fault_rate > config.max_page_faults_per_sec as f64 {
                        data.page_fault_violations += 1;
                        if data.page_fault_violations >= config.violations_before_termination {
                            if let Ok(process_info) = check_process(handle) {
                                if !process_info.is_critical && !process_info.is_system {
                                    info!(
                                        "Terminating PID {} ({}) due to high page fault rate ({} faults/s) after {} violations",
                                        pid,
                                        process_name,
                                        page_fault_rate,
                                        data.page_fault_violations
                                    );
                                    if unsafe { TerminateProcess(handle, 1) }.is_err() {
                                        error!("Failed to terminate PID {}", pid);
                                    }
                                } else {
                                    warn!(
                                        "Skipped termination of critical/system PID {} ({})",
                                        pid, process_name
                                    );
                                }
                            } else {
                                error!("Failed to check process properties for PID: {}", pid);
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

            unsafe { CloseHandle(handle) }?;
            if unsafe { Process32NextW(snapshot, &mut entry) }.is_err() {
                break;
            }
        }
    }

    if *first_run {
        *first_run = false; // Mark first run as complete
    }

    process_data.retain(|&pid, _| current_pids.contains(&pid));
    unsafe { CloseHandle(snapshot) }?;
    Ok(())
}

fn wide_to_string(wide: &[u16]) -> String {
    OsString::from_wide(wide).to_string_lossy().into_owned()
}
