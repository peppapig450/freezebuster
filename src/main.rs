use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::hash::Hash;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32First, Process32Next, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_TERMINATE, TerminateProcess,
};

// For serialization:deserialization of the configuration
use serde::Deserialize;
// For logging
use log::{error, info, warn};
use simplelog::{CombinedLogger, ConfigBuilder, LevelFilter, WriteLogger};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

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

    info!("FreezeBusterService starting...");

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

fn run_service(_arguments: Vec<std::ffi::OsString>) -> Result<(), Box<dyn Error>> {
    let config = read_config("config.json")?;

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
    let mut mem_info = MEMORYSTATUSEX::default();
    mem_info.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
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
    let mut mem_info = MEMORYSTATUSEX::default();
    mem_info.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
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

    let mut mem_info = MEMORYSTATUSEX::default();
    mem_info.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
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
