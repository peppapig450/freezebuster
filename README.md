# FreezeBusterService

A Windows service to monitor and terminate processes based on memory usage.

## Features

- Monitors process working set growth and page faults.
- Terminates processes exceeding configured thresholds.
- Configurable via `config.json`.

## Installation

1. Build with `cargo build --release`.
2. Run `target/release/freeze-buster-service.exe`.

## Configuration

Create a `config.json` file:

```json
{
  "max_working_set_growth_mb_per_sec": 10.0,
  "min_available_memory_mb": 512,
  "max_page_faults_per_sec": 1000,
  "violations_before_termination": 3,
  "whitelist": ["notepad.exe"]
}
