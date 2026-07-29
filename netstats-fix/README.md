# netstats-fix

A Magisk / KernelSU module that fixes broken traffic indicator and per-interface network
stats on **Android 16 (API 35) GSI** images by intercepting `INetworkStatsService` at the
Binder IPC layer.

## The Problem

`TrafficStats.getTxBytes()` / `getRxBytes()` returns zero on many GSI builds because
`NetworkStatsService` reads from **eBPF maps** that are:

- Unavailable on kernels < 5.0
- Blocked by SELinux on strict GSI builds
- Not populated when the BPF driver is missing or broken

SystemUI's traffic indicator calls `INetworkStatsService.getIfaceStats()` →
`NetworkStatsService.getIfaceStatsInternal()` → `nativeGetIfaceStat()` (BPF) → **0**.

## The Solution

A pure-Java **Binder proxy** that:

1. Registers itself as the `"netstats"` service in `ServiceManager`, replacing the original
   `NetworkStatsService`.
2. Intercepts transaction codes `0x0c` (`getIfaceStats`) and `0x0d` (`getTotalStats`) and
   reads `/proc/net/dev` directly.
3. Delegates all other methods (uid stats, sessions, etc.) transparently to the original
   service.
4. Starts the Binder thread pool (`BinderInternal.joinThreadPool()`) so it can actually
   receive incoming IPC.

## Requirements

- Android 16 (API 35)
- Magisk v24+ or KernelSU
- GSI images only (EvoX, Axion OS, Infinity X, crDroid, AOSP)

## Installation

1. Flash `netstats-fix-v7.zip` in Magisk Manager / KernelSU app
2. **Reboot**
3. After boot, check `/data/local/tmp/netproxy.log` for diagnostics

## Debugging

If it doesn't work, check the log:

```bash
adb shell cat /data/local/tmp/netproxy.log
```

Expected output:
```
=== netproxy service.sh start ===
boot completed
starting proxy daemon...
proxy.dex size: 5072
app_process: /system/bin/app_process
proc_net_dev readable: -r--r--r-- ...
magiskpolicy applied
proxy launched pid=12345
NetProxy: starting...
NetProxy: proxy registered. original=true
NetProxy: self-check: getService returned non-null
NetProxy: starting binder thread pool...
restarting SystemUI...
done
```

## Building from source

```bash
# Linux / macOS
chmod +x build.sh; ./build.sh

# Windows
.\build.ps1
```

Requires JDK 17+ and an internet connection (to download r8).

## Project structure

```
netstats-fix/
├── build.ps1 / build.sh       # Build scripts
├── LICENSE / README.md
├── src/
│   └── com/flint/netstats/
│       └── NetworkStatsProxy.java
├── stubs/android/os/          # Android framework stubs
│   ├── Binder.java
│   ├── BinderInternal.java
│   ├── IBinder.java
│   ├── IInterface.java
│   ├── Parcel.java
│   ├── Parcelable.java
│   ├── RemoteException.java
│   └── ServiceManager.java
└── module/                    # Magisk module skeleton
    ├── module.prop
    ├── customize.sh
    ├── post-fs-data.sh
    ├── service.sh
    └── sepolicy.rule
```
