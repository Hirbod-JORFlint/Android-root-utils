# netstats-fix

A Magisk / KernelSU module that fixes broken traffic indicators and per-interface network
stats on **Android 16 (API 35) GSI** images by intercepting the `INetworkStatsService`
Binder service at the framework level.

## The Problem

On Android 16 GSIs, `TrafficStats.getTxBytes()` / `getRxBytes()` often returns zero because
the underlying `NetworkStatsService` reads from **eBPF maps** that are either:

- Unavailable on kernels older than 5.0
- Blocked by SELinux policies on strict GSI builds
- Not populated on GSI kernels that lack proper eBPF driver support

The traffic indicator in SystemUI calls `INetworkStatsService.getIfaceStats()`, which hits
`NetworkStatsService.getIfaceStatsInternal()` → `nativeGetIfaceStat()` (BPF), and gets
nothing back.

## The Solution

A pure-Java **Binder proxy** (`NetworkStatsProxy`) that:

1. Registers itself as the `"netstats"` service in ServiceManager — replacing the original
   `NetworkStatsService` (which lives inside the `system_server` process).
2. Intercepts two key Binder transaction codes:
   - `0x0c` — `getIfaceStats(String iface)` → reads `/proc/net/dev`
   - `0x0d` — `getTotalStats()` → reads `/proc/net/dev`, skips `lo`
3. Transparently **delegates all other methods** (getUidStats, openSession, etc.) to the
   original `NetworkStatsService` so nothing else breaks.
4. Runs a background watchdog that re-registers itself every 10 seconds in case the
   `system_server` restarts and replaces the proxy.

Because the proxy intercepts at the **Binder IPC** layer, it works on **any ROM** — EvoX,
Axion OS, Infinity X, crDroid, or stock AOSP — without modifying SystemUI.

## Architecture

```
SystemUI / any app
       │
       │  ServiceManager.getService("netstats")
       ▼
┌─────────────────────────────────┐
│   NetworkStatsProxy (this mod)  │
│   - transact 0x0c → /proc/net   │
│   - transact 0x0d → /proc/net   │
│   - others → delegate to orig   │
└──────────┬──────────────────────┘
           │ delegate (code != 12/13)
           ▼
┌──────────────────────────────────┐
│  NetworkStatsService (system)    │
│  - getUidStats, openSession, etc │
└──────────────────────────────────┘
```

## Requirements

- **Android 16 (API 35)** — may also work on API 34+ but only API 35 is tested
- **Magisk** (v24+) or **KernelSU**
- **permissive or semi-permissive SELinux** (GSI default) — optional but strongly
  recommended; otherwise you must audit and extend `sepolicy.rule` for your domain
- A GSI image (tested on EvoX, Axion OS, Infinity X)

## Installation

1. Download `netstats-fix-v7.zip` from releases (or build it yourself)
2. Flash in Magisk Manager / KernelSU app
3. Reboot

After boot, the proxy automatically:
- Reads `/proc/net/dev` for iface stats
- Restarts SystemUI to force re-cache the service

## Building from source

### Requirements
- JDK 17+
- 7-Zip (Windows) or zip/unzip (Linux/macOS)

### Windows
```powershell
.\build.ps1
```

### Linux / macOS
```bash
chmod +x build.sh
./build.sh
```

The build script will:
1. Locate your JDK
2. Download r8 (DEX compiler) from Google's Maven repo
3. Compile `NetworkStatsProxy.java` against the Android framework stubs
4. Convert to DEX with d8
5. Package the Magisk module ZIP

Output: `netstats-fix-v7.zip`

## Project structure

```
netstats-fix/
├── build.ps1                     # Windows build script
├── build.sh                      # Unix build script
├── README.md
├── LICENSE
├── src/
│   └── com/opencode/netstats/
│       └── NetworkStatsProxy.java   # Binder proxy implementation
├── stubs/android/os/               # Framework stubs for compilation
│   ├── Binder.java
│   ├── IBinder.java
│   ├── IInterface.java
│   ├── Parcel.java
│   ├── Parcelable.java
│   ├── RemoteException.java
│   └── ServiceManager.java
└── module/                         # Magisk module skeleton
    ├── module.prop
    ├── customize.sh
    ├── post-fs-data.sh
    ├── service.sh
    └── sepolicy.rule
```

## How it works — technical deep-dive

### Binder transaction codes

From `INetworkStatsService` AIDL (package `android.net`, in the tethering APEX):

| Code | Method                           | Intercepted? |
|------|----------------------------------|-------------|
| 0x0b | `getUidStats(int uid, int type)` | ❌ delegated |
| 0x0c | `getIfaceStats(String iface)`    | ✅ /proc/net |
| 0x0d | `getTotalStats()`                | ✅ /proc/net |
| all  | others                           | ❌ delegated |

### StatsResult Parcel format

```
[int: total blob size] [long: rxBytes] [long: rxPackets] [long: txBytes] [long: txPackets]
```

The proxy constructs this from `/proc/net/dev`:

```
Inter-|   Receive                        |  Transmit
 face |bytes    packets ...              |bytes    packets ...
  wlan0: 1234567 1234  ...               7654321 5678 ...
```

### SELinux

The module ships `sepolicy.rule` with permissions for `system_app` to read `/proc/net/dev`.
On most GSI builds SELinux is permissive, but the rule is there for enforcing setups.

## License

Apache 2.0 — see [LICENSE](LICENSE)
