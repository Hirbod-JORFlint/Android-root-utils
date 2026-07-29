# netstats-fix

Magisk/KernelSU module that fixes broken traffic indicator on Android 14+ GSIs by:
1. Restoring BPF maps via kernel version override + bpfloader restart
2. Falling back to a native C binder proxy that reads `/proc/net/dev` directly
3. Applying comprehensive SELinux policies for all device variants

## How it works

**Layer 1 - BPF Repair (kernels >= 4.9):**
- Corrects `ro.bpf.kver_override` to match actual kernel
- Deletes stale `mainline_done` marker to force bpfloader to rerun
- Restarts bpfloader to recreate BPF maps with correct version

**Layer 2 - Native Proxy (kernels < 4.9 or BPF failure):**
- Native C binary (`netproxy`) communicates directly with Android's Binder driver
- Registers as `netstats` service to intercept `INetworkStatsService` calls
- Reads interface statistics from `/proc/net/dev`
- Provides interface-level traffic data when per-UID BPF stats are unavailable

**Layer 3 - SELinux Policy Fixes:**
- Handles `bpfloader_platform_exec` context (Axion OS)
- Allows `init` to execute bpfloader from any location
- Grants BPF filesystem access to netd and bpfloader
- Allows reading `/proc/net/dev` from all relevant domains

## Variants

| Module | BPF Repair | Proxy Fallback | Use Case |
|--------|-----------|----------------|----------|
| `netstats-fix-v10.zip` | Yes | Yes | General purpose (default) |
| `netstats-fix-v10-lite.zip` | No | Yes | Devices where BPF causes "no internet" |

## Installation

1. Flash the appropriate zip in Magisk/KernelSU/APatch
2. Reboot
3. Check logs: `cat /data/local/tmp/netproxy.log`

## Debugging

```bash
adb shell cat /data/local/tmp/netproxy.log
```

## Building

Requires Android NDK r27+:
```bash
chmod +x build.sh; ./build.sh   # Linux/macOS
.\build.ps1                     # Windows
```

## Project structure

```
netstats-fix/
├── build.ps1 / build.sh
├── src/
│   └── netproxy.c          # Native C binder proxy
└── module/
    ├── customize.sh         # Installation script
    ├── module.prop          # Module metadata (full)
    ├── module_lite.prop     # Module metadata (lite)
    ├── post-fs-data.sh      # Early boot BPF repair
    ├── post-fs-data_lite.sh # Early boot (lite)
    ├── sepolicy.rule        # SELinux policies
    ├── service.sh           # Main service (full)
    ├── service_lite.sh      # Main service (lite)
    └── system/bin/
        ├── netproxy         # ARM64 binary
        └── netproxy_arm     # ARM32 binary
```
