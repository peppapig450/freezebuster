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

    info!("FreezeBusterService starting with config: {config:?}");

    // Start the service
    service_dispatcher::start("FreezeBusterService", ffi_service_main)?;
    Ok(())
}

/// Service logic
fn freeze_buster_service(arguments: Vec<std::ffi::OsString>) {
    if let Err(e) = run_service(arguments) {
        error!("Service failed: {e}");
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
        AdjustTokenPrivileges(token, false, Some(&raw const tp), 0, None, None)?;
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
            error!("Monitoring error: {e}");
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
        let memory_load = f64::from(mem_info.dwMemoryLoad) / 100.0; // 0.0 to 1.0
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
                    error!("Failed to check process properties for PID: {pid}");
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
                warn!("Failed to get memory info for PID {pid}");
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
                        (delta_working_set as f64 / f64::from(2 << 20)) / elapsed.as_secs_f64();
                    let delta_page_faults = page_faults.saturating_sub(data.prev_page_faults);
                    let page_fault_rate = f64::from(delta_page_faults) / elapsed.as_secs_f64();

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
    let len = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    OsString::from_wide(&wide[..len])
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;
    use tempfile::TempDir;

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
        let process_data = ProcessData {
            prev_working_set: 10_485_760, // 10 MB
            prev_time: Instant::now() - Duration::from_secs(1),
            prev_page_faults: 100,
            working_set_violations: 0,
            page_fault_violations: 0,
        };

        let now = Instant::now();
        let current_working_set = 20_971_520; // 20 MB
        let current_page_faults = 150;

        let elapsed = now - process_data.prev_time;
        let delta_working_set = current_working_set - process_data.prev_working_set;
        let growth_mb_per_sec =
            (delta_working_set as f64 / (2 << 20) as f64) / elapsed.as_secs_f64();
        let delta_page_faults = current_page_faults - process_data.prev_page_faults;
        let page_fault_rate = delta_page_faults as f64 / elapsed.as_secs_f64();

        assert!(growth_mb_per_sec > 9.0 && growth_mb_per_sec < 11.0); // Approx 10 MB/s
        assert_eq!(page_fault_rate as u32, 50); // 50 faults/sec
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
