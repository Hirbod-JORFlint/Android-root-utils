#!/system/bin/sh
MODDIR=${0%/*}
LOG=/data/local/tmp/netproxy.log

log() { echo "$(date) [service-lite] $*" >> "$LOG"; }

log "=== service-lite.sh started ==="
WAIT=0
while [ "$(getprop sys.boot_completed)" != "1" ] && [ "$WAIT" -lt 180 ]; do
    sleep 1; WAIT=$((WAIT + 1))
done
log "Boot completed after ${WAIT}s"
sleep 15

chmod 0644 /proc/net/dev 2>/dev/null
chmod 0644 /proc/self/net/dev 2>/dev/null

magiskpolicy --live "allow * proc_net:file { read open getattr }" 2>/dev/null
magiskpolicy --live "allow * proc_net:dir { read search open }" 2>/dev/null
magiskpolicy --live "allow * binder_device:chr_file { read write open ioctl }" 2>/dev/null
magiskpolicy --live "allow * binder:service_manager { find add }" 2>/dev/null
magiskpolicy --live "allow * netd:fd use" 2>/dev/null
magiskpolicy --live "allow system_server proc_net:file { read open getattr }" 2>/dev/null
magiskpolicy --live "allow system_server proc_net:dir { read search open }" 2>/dev/null
log "SELinux policies applied"

# Multi-path binary resolution
find_netproxy() {
    local probe
    for probe in \
        "$MODDIR/system/bin/netproxy" \
        "${0%/*}/system/bin/netproxy" \
        "/data/adb/modules/netstats-fix/system/bin/netproxy" \
        "/data/adb/modules/netstats-fix-lite/system/bin/netproxy" \
        "/system/bin/netproxy" \
        "/apex/com.android.conscrypt/bin/netproxy" \
        "$(dirname "$0" 2>/dev/null)/system/bin/netproxy"; do
        [ -f "$probe" ] && { echo "$probe"; return 0; }
    done

    log "Searching for netproxy in module directory..."
    local found
    found=$(find "$MODDIR" -name "netproxy" -type f 2>/dev/null | head -1)
    [ -n "$found" ] && { echo "$found"; return 0; }

    found=$(find /data/adb/modules -name "netproxy" -type f 2>/dev/null | head -1)
    [ -n "$found" ] && { echo "$found"; return 0; }

    return 1
}

# Architecture-aware binary selection
select_arch_binary() {
    local base_bin="$1"
    local dir; dir=$(dirname "$base_bin")
    local arch; arch=$(getprop ro.product.cpu.abi 2>/dev/null)
    log "Detected arch: ${arch:-unknown}"
    case "$arch" in
        arm64-v8a|arm64)
            [ -f "$base_bin" ] && { echo "$base_bin"; return 0; }
            [ -f "$dir/netproxy_arm" ] && { echo "$dir/netproxy_arm"; return 0; }
            [ -f "$dir/../netproxy" ] && { echo "$dir/../netproxy"; return 0; }
            [ -f "$dir/../netproxy_arm" ] && { echo "$dir/../netproxy_arm"; return 0; }
            ;;
        armeabi-v7a|armeabi)
            [ -f "$dir/netproxy_arm" ] && { echo "$dir/netproxy_arm"; return 0; }
            [ -f "$base_bin" ] && { echo "$base_bin"; return 0; }
            ;;
        *)
            [ -f "$base_bin" ] && { echo "$base_bin"; return 0; }
            [ -f "$dir/netproxy_arm" ] && { echo "$dir/netproxy_arm"; return 0; }
            ;;
    esac
    return 1
}

PROXY_BIN=$(find_netproxy)
if [ -z "$PROXY_BIN" ]; then
    log "FATAL: netproxy not found after exhaustive search"
    log "MODDIR=$MODDIR"
    log "Contents of $MODDIR:"
    ls -la "$MODDIR" 2>/dev/null >> "$LOG" || log "  (cannot list)"
    log "Contents of ${MODDIR}/system:"
    ls -la "$MODDIR/system" 2>/dev/null >> "$LOG" || log "  (cannot list)"
    log "Contents of ${MODDIR}/system/bin:"
    ls -la "$MODDIR/system/bin" 2>/dev/null >> "$LOG" || log "  (cannot list)"
    log "Searching /data/adb/modules:"
    ls -la /data/adb/modules/ 2>/dev/null >> "$LOG" || log "  (no modules dir)"
    exit 1
fi

TARGET_BIN=$(select_arch_binary "$PROXY_BIN")
if [ -z "$TARGET_BIN" ]; then
    TARGET_BIN="$PROXY_BIN"
fi

log "Found binary: $TARGET_BIN"
chmod 755 "$TARGET_BIN"

# Verify binary is executable ELF
if ! head -c 4 "$TARGET_BIN" 2>/dev/null | grep -q $'\x7fELF'; then
    log "WARNING: $TARGET_BIN is not an ELF binary!"
fi

log "Starting netproxy..."
nohup "$TARGET_BIN" >> "$LOG" 2>&1 &
PROXY_PID=$!
log "Proxy launched (pid=$PROXY_PID)"
sleep 3
if kill -0 "$PROXY_PID" 2>/dev/null; then
    log "Proxy is running (PID $PROXY_PID)"
else
    log "Proxy exited prematurely (exit code: $?)"
    # Retry once
    log "Retrying netproxy..."
    nohup "$TARGET_BIN" >> "$LOG" 2>&1 &
    PROXY_PID=$!
    log "Proxy retry launched (pid=$PROXY_PID)"
    sleep 3
    if kill -0 "$PROXY_PID" 2>/dev/null; then
        log "Proxy running after retry"
    else
        log "Proxy failed again"
    fi
fi

settings put global network_stats_enabled 1 2>/dev/null
settings put global restricted_networking_mode 0 2>/dev/null
cmd netstats force-refresh 2>/dev/null || true

sleep 5
killall -9 com.android.systemui 2>/dev/null || \
    pkill -9 -f "com.android.systemui" 2>/dev/null || \
    am force-stop com.android.systemui 2>/dev/null
log "SystemUI killed"
sleep 8
SYSUI_PID=$(pidof com.android.systemui 2>/dev/null)
log "SystemUI running as pid=$SYSUI_PID"

log "=== service-lite.sh complete ==="
exit 0
