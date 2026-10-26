# CyberShield Linux Agent

Functional prototype for Linux endpoint protection.

## Features
- File scanning with hash calculation
- Directory traversal and incremental scanning
- Integration hooks for ClamAV (via clamscan)
- Event logging
- HTTP API client for backend communication

## Build
```bash
cargo build --release
```

## Usage
```bash
./sentinelx-agent-linux scan /home/user/Downloads
./sentinelx-agent-linux monitor
```

## Limitations
- No kernel-level rootkit detection without root privileges
- eBPF monitoring requires additional capabilities
- Some features require root/sudo
