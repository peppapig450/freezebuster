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
    whitelist: Vec<String>,
}

/// Stores previous resource usage data for a process
struct ProcessData {
    prev_working_set: u64, // Previous working set size (bytes)
    prev_time: Instant,    // Time of last measurement
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
        LevelFilter::Info,
        config,
        File::create(log_file)?,
    )])?;
    Ok(())
}
