# netstats-fix

Magisk/KernelSU module that fixes broken traffic indicator on Android 16 GSIs by
intercepting `INetworkStatsService` at the Binder IPC layer.

## How it works

A pure-Java Binder proxy (`NetworkStatsProxy`) registers itself as `"netstats"`,
intercepts `getIfaceStats` / `getTotalStats` transactions, reads `/proc/net/dev`
instead of broken BPF maps, and delegates everything else to the original service.

## Installation

1. Flash `netstats-fix-v7.zip` in Magisk/KernelSU
2. Reboot
3. Check `/data/local/tmp/netproxy.log` for diagnostics

## Debugging

```bash
adb shell cat /data/local/tmp/netproxy.log
```

Expected output:
```
=== netproxy service.sh start ===
boot completed
starting proxy daemon...
proxy.dex size: 6480
app_process: /system/bin/app_process
proc_net_dev: -r--r--r-- ...
magiskpolicy applied
proxy launched pid=12345
NetProxy: starting...
NetProxy: found netstats service
NetProxy: pool thread starting...
NetProxy: pool thread started
NetProxy: registered. original=true
NetProxy: proxy active, entering keepalive
restarting SystemUI...
done
```

## Building

```bash
chmod +x build.sh; ./build.sh   # Linux/macOS
.\build.ps1                     # Windows
```

Requires JDK 17+.

## Project structure

```
netstats-fix/
├── build.ps1 / build.sh
├── LICENSE / README.md
├── src/com/flint/netstats/
│   └── NetworkStatsProxy.java
├── stubs/android/os/   (7 files)
└── module/             (6 files)
```
