use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32First, Process32Next, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows::Win32::System::SystemInformation::{
    GetSystemInfo, GlobalMemoryStatusEx, MEMORYSTATUSEX, SYSTEM_INFO,
};
use windows::Win32::System::Threading::{
    GetProcessIoCounters, GetProcessTimes, IO_COUNTERS, OpenProcess, PROCESS_QUERY_INFORMATION,
    PROCESS_TERMINATE, TerminateProcess,
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
