#[cfg(test)]
mod mock_tests {
    use crate::{Config, ProcessData, ServiceContext, WindowsApi, adjust_sleep_duration};
    use crate::{
        enable_se_debug_privilege, get_available_memory, get_total_memory, monitor_and_terminate,
    };
    use mockall::mock;
    use std::collections::HashMap;
    use std::time::{Duration, Instant};
    use windows::{
        Win32::{
            Foundation::{HANDLE as WinHandle, LUID},
            Security::{
                SE_DEBUG_NAME, TOKEN_ACCESS_MASK, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
            },
            System::{
                Diagnostics::ToolHelp::{CREATE_TOOLHELP_SNAPSHOT_FLAGS, PROCESSENTRY32W},
                ProcessStatus::PROCESS_MEMORY_COUNTERS,
                SystemInformation::MEMORYSTATUSEX,
                Threading::{GetCurrentProcess, PROCESS_ACCESS_RIGHTS},
            },
        },
        core::{Error as WinError, PCWSTR},
    };

    // SafeHandle wrapper
    #[derive(Debug, Clone, Copy, PartialEq)]
    struct SafeHandle(WinHandle);
    unsafe impl Send for SafeHandle {}
    unsafe impl Sync for SafeHandle {}
    impl From<SafeHandle> for WinHandle {
        fn from(safe: SafeHandle) -> Self {
            safe.0
        }
    }
    impl From<WinHandle> for SafeHandle {
        fn from(handle: WinHandle) -> Self {
            SafeHandle(handle)
        }
    }

    // Helper function for szExeFile
    fn make_exe_file(name: &str) -> [u16; 260] {
        let mut arr = [0u16; 260];
        let utf16: Vec<u16> = name.encode_utf16().collect();
        for (i, &c) in utf16.iter().enumerate() {
            if i >= 260 {
                break;
            }
            arr[i] = c;
        }
        arr
    }

    // Corrected mock definition
    mock! {
        pub WindowsApi {}
        impl WindowsApi for WindowsApi {
            fn create_toolhelp32_snapshot(&self, flags: CREATE_TOOLHELP_SNAPSHOT_FLAGS, process_id: u32) -> Result<WinHandle, WinError>;
            fn process32_first_w(&self, snapshot: WinHandle, entry: &mut PROCESSENTRY32W) -> Result<(), WinError>;
            fn process32_next_w(&self, snapshot: WinHandle, entry: &mut PROCESSENTRY32W) -> Result<(), WinError>;
            fn open_process(&self, desired_access: PROCESS_ACCESS_RIGHTS, inherit_handle: bool, process_id: u32) -> Result<WinHandle, WinError>;
            fn get_process_memory_info(&self, process: WinHandle, counters: &mut PROCESS_MEMORY_COUNTERS, size: u32) -> Result<(), WinError>;
            fn terminate_process(&self, process: WinHandle, exit_code: u32) -> Result<(), WinError>;
            fn close_handle(&self, handle: WinHandle) -> Result<(), WinError>;
            fn global_memory_status_ex(&self, mem_info: &mut MEMORYSTATUSEX) -> Result<(), WinError>;
            fn open_process_token(&self, process: WinHandle, desired_access: TOKEN_ACCESS_MASK, token_handle: &mut WinHandle) -> Result<(), WinError>;
            fn lookup_privilege_value_w<'a>(&self, system_name: Option<&'a str>, name: PCWSTR, luid: &mut LUID) -> Result<(), WinError>;
            fn adjust_token_privileges(&self, token_handle: WinHandle, disable_all_privileges: bool, new_state: Option<*const TOKEN_PRIVILEGES>, buffer_length: u32, previous_state: Option<*mut TOKEN_PRIVILEGES>, return_length: Option<*mut u32>) -> Result<(), WinError>;
        }
    }

    #[test]
    fn test_adjust_sleep_duration() {
        let mut mock_api = MockWindowsApi::new();
        mock_api
            .expect_global_memory_status_ex()
            .returning(|mem_info| {
                mem_info.dwMemoryLoad = 0;
                mem_info.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
                Ok(())
            });
        let ctx = ServiceContext {
            api: Box::new(mock_api),
            config: Config {
                max_working_set_growth_mb_per_sec: 10.0,
                min_available_memory_mb: 512,
                max_page_faults_per_sec: 1000,
                violations_before_termination: 3,
                whitelist: vec![],
            },
        };
        let duration = adjust_sleep_duration(&ctx);
        assert!(
            (duration.as_secs_f64() - 30.0).abs() < 1e-6,
            "Expected ~30s, got {:?}",
            duration
        );
    }

    #[test]
    fn test_get_total_memory() {
        let mut mock_api = MockWindowsApi::new();
        mock_api
            .expect_global_memory_status_ex()
            .returning(|mem_info| {
                mem_info.ullTotalPhys = 8_589_934_592; // 8 GB
                mem_info.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
                Ok(())
            });
        let ctx = ServiceContext {
            api: Box::new(mock_api),
            config: Config {
                max_working_set_growth_mb_per_sec: 10.0,
                min_available_memory_mb: 512,
                max_page_faults_per_sec: 1000,
                violations_before_termination: 3,
                whitelist: vec![],
            },
        };
        assert_eq!(get_total_memory(&ctx), 8_589_934_592);
    }

    #[test]
    fn test_get_available_memory_failure() {
        let mut mock_api = MockWindowsApi::new();
        mock_api
            .expect_global_memory_status_ex()
            .returning(|_| Err(WinError::from_win32()));
        let ctx = ServiceContext {
            api: Box::new(mock_api),
            config: Config {
                max_working_set_growth_mb_per_sec: 10.0,
                min_available_memory_mb: 512,
                max_page_faults_per_sec: 1000,
                violations_before_termination: 3,
                whitelist: vec![],
            },
        };
        assert_eq!(get_available_memory(&ctx), 0);
    }

    #[test]
    fn test_enable_se_debug_privilege() {
        let mut mock_api = MockWindowsApi::new();
        let token_handle = SafeHandle(WinHandle(1 as *mut _));

        mock_api
            .expect_open_process_token()
            .withf(|process, da, _| {
                *process == unsafe { GetCurrentProcess() } && da.0 == TOKEN_ADJUST_PRIVILEGES.0
            })
            .returning(move |_, _, th| {
                *th = token_handle.into();
                Ok(())
            });
        mock_api
            .expect_lookup_privilege_value_w()
            .withf(|sn, name, _| {
                sn.is_none()
                    && unsafe { name.as_wide() }
                        == "SeDebugPrivilege"
                            .encode_utf16()
                            .collect::<Vec<u16>>()
                            .as_slice()
            })
            .returning(|_, _, luid| {
                *luid = LUID {
                    LowPart: 1,
                    HighPart: 0,
                };
                Ok(())
            });
        mock_api
            .expect_adjust_token_privileges()
            .withf(move |th, disable, ns, bl, ps, rl| {
                *th == token_handle.into()
                    && !*disable
                    && ns.is_some()
                    && *bl == 0
                    && ps.is_none()
                    && rl.is_none()
            })
            .returning(|_, _, _, _, _, _| Ok(()));
        mock_api
            .expect_close_handle()
            .withf(move |h| *h == token_handle.into())
            .returning(|_| Ok(()));

        let ctx = ServiceContext {
            api: Box::new(mock_api),
            config: Config {
                max_working_set_growth_mb_per_sec: 10.0,
                min_available_memory_mb: 512,
                max_page_faults_per_sec: 1000,
                violations_before_termination: 3,
                whitelist: vec![],
            },
        };
        let result = enable_se_debug_privilege(&ctx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_monitor_and_terminate_whitelist() {
        let mut mock_api = MockWindowsApi::new();
        let snapshot_handle = SafeHandle(WinHandle(1 as *mut _));
        let process_handle = SafeHandle(WinHandle(2 as *mut _));

        mock_api
            .expect_create_toolhelp32_snapshot()
            .returning(move |_, _| Ok(snapshot_handle.into()));
        let entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            th32ProcessID: 123,
            szExeFile: make_exe_file("notepad.exe"),
            ..Default::default()
        };
        mock_api.expect_process32_first_w().returning(move |_, e| {
            *e = entry.clone();
            Ok(())
        });
        mock_api
            .expect_process32_next_w()
            .returning(|_, _| Err(WinError::from_win32()));
        mock_api
            .expect_open_process()
            .returning(move |_, _, _| Ok(process_handle.into()));
        mock_api.expect_close_handle().returning(|_| Ok(()));
        mock_api
            .expect_global_memory_status_ex()
            .returning(|mem_info| {
                mem_info.ullAvailPhys = 1 << 30; // 1 GB available
                mem_info.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
                Ok(())
            });

        let config = Config {
            max_working_set_growth_mb_per_sec: 10.0,
            min_available_memory_mb: 512,
            max_page_faults_per_sec: 1000,
            violations_before_termination: 3,
            whitelist: vec!["notepad.exe".to_string()],
        };
        let ctx = ServiceContext {
            api: Box::new(mock_api),
            config,
        };
        let mut process_data = HashMap::new();
        let mut system_processes = HashMap::new();
        let mut first_run = true;

        let result = monitor_and_terminate(
            &ctx,
            &mut process_data,
            0,
            Instant::now(),
            &mut system_processes,
            &mut first_run,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_monitor_and_terminate_violation() {
        let mut mock_api = MockWindowsApi::new();
        let snapshot_handle = SafeHandle(WinHandle(1 as *mut _));
        let process_handle = SafeHandle(WinHandle(2 as *mut _));

        mock_api
            .expect_create_toolhelp32_snapshot()
            .returning(move |_, _| Ok(snapshot_handle.into()));
        let entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            th32ProcessID: 123,
            szExeFile: make_exe_file("test"),
            ..Default::default()
        };
        mock_api.expect_process32_first_w().returning(move |_, e| {
            *e = entry.clone();
            Ok(())
        });
        mock_api
            .expect_process32_next_w()
            .returning(|_, _| Err(WinError::from_win32()));
        mock_api
            .expect_open_process()
            .returning(move |_, _, _| Ok(process_handle.into()));
        mock_api
            .expect_get_process_memory_info()
            .returning(|_, counters, _| {
                counters.WorkingSetSize = 20_971_520; // 20 MB
                counters.PageFaultCount = 150;
                Ok(())
            });
        mock_api
            .expect_global_memory_status_ex()
            .returning(|mem_info| {
                mem_info.ullAvailPhys = 256 * 1024 * 1024; // 256 MB available
                mem_info.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
                Ok(())
            });
        mock_api
            .expect_terminate_process()
            .withf(move |h, ec| *h == process_handle.into() && *ec == 1)
            .returning(|_, _| Ok(()));
        mock_api.expect_close_handle().returning(|_| Ok(()));

        let config = Config {
            max_working_set_growth_mb_per_sec: 5.0,
            min_available_memory_mb: 512,
            max_page_faults_per_sec: 1000,
            violations_before_termination: 1,
            whitelist: vec![],
        };
        let ctx = ServiceContext {
            api: Box::new(mock_api),
            config,
        };
        let mut process_data = HashMap::from([(
            123,
            ProcessData {
                prev_working_set: 10_485_760, // 10 MB
                prev_time: Instant::now() - Duration::from_secs(1),
                prev_page_faults: 100,
                working_set_violations: 0,
                page_fault_violations: 0,
            },
        )]);
        let mut system_processes = HashMap::new();
        let mut first_run = false;

        let result = monitor_and_terminate(
            &ctx,
            &mut process_data,
            0,
            Instant::now(),
            &mut system_processes,
            &mut first_run,
        );
        assert!(result.is_ok());
    }
}
