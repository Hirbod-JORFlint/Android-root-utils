#!/system/bin/sh
LOG=/data/local/tmp/netproxy.log

_log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [post-fs-data-lite] $*" >> "$LOG"; }

chmod 0666 "$LOG" 2>/dev/null || true
echo "" >> "$LOG" 2>/dev/null || true
echo "=== BOOT $(date '+%Y-%m-%d %H:%M:%S') ===" >> "$LOG" 2>/dev/null

_log "=== post-fs-data-lite.sh started ==="
_log "MODDIR: ${0%/*}"
_log "Kernel: $(uname -r)"
_log "Android SDK: $(getprop ro.build.version.sdk 2>/dev/null)"
_log "Build: $(getprop ro.build.display.id 2>/dev/null || getprop ro.build.description 2>/dev/null)"
_log "SELinux: $(getenforce 2>/dev/null || echo unknown)"
_log "Arch: $(getprop ro.product.cpu.abi 2>/dev/null)"
_log "ROM: $(getprop ro.build.display.id 2>/dev/null)"

_log "Detecting system variant..."
if [ -d "/system_axion" ]; then
    _log "  Detected: Axion OS (/system_axion)"
elif [ -d "/system_infinity" ]; then
    _log "  Detected: Infinity X (/system_infinity)"
else
    _log "  Detected: Standard AOSP"
fi

_log "Checking bpffs..."
if mount | grep -q "bpf on /sys/fs/bpf"; then
    _log "  bpffs: mounted"
else
    _log "  bpffs: not mounted (OK for lite)"
fi

_log "Checking /proc/net/dev..."
if [ -f /proc/net/dev ]; then
    _log "  /proc/net/dev: readable"
    chmod 0644 /proc/net/dev 2>/dev/null && _log "  chmod /proc/net/dev: OK" || _log "  chmod /proc/net/dev: failed"
else
    _log "  /proc/net/dev: NOT FOUND"
fi

if [ -f /proc/self/net/dev ]; then
    chmod 0644 /proc/self/net/dev 2>/dev/null && _log "  chmod /proc/self/net/dev: OK" || true
fi

_log "Checking network stats service..."
NSE=$(settings get global network_stats_enabled 2>/dev/null)
_log "  network_stats_enabled: $NSE"
RNM=$(settings get global restricted_networking_mode 2>/dev/null)
_log "  restricted_networking_mode: $RNM"

_log "Checking netstats directory..."
if [ -d /data/misc/netstats ]; then
    _log "  /data/misc/netstats: exists"
    ls -la /data/misc/netstats/ 2>/dev/null | while IFS= read -r l; do _log "  $l"; done
else
    _log "  /data/misc/netstats: NOT FOUND (will be created)"
fi

_log "Binder devices:"
for dev in /dev/binder /dev/vndbinder /dev/hwbinder; do
    if [ -e "$dev" ]; then
        _log "  $dev: EXISTS ($(ls -la "$dev" 2>/dev/null))"
    else
        _log "  $dev: NOT FOUND"
    fi
done

_log "SELinux denials (binder/service_manager/netstats):"
dmesg 2>/dev/null | grep 'avc:.*denied' | grep -iE 'binder|service_manager|servicemanager|netstats|proc_net' | tail -15 | while IFS= read -r l; do _log "  DENIAL: $l"; done

_log "ServiceManager messages:"
dmesg 2>/dev/null | grep -iE 'service_manager|binder:' | tail -10 | while IFS= read -r l; do _log "  SM: $l"; done

_log "=== post-fs-data-lite.sh complete ==="
exit 0
