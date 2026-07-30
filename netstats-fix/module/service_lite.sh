#!/system/bin/sh
MODDIR=${0%/*}
LOG=/data/local/tmp/netproxy.log

log() { echo "$(date) [service-lite] $*" >> "$LOG"; }

find_netproxy() {
    local probe
    for probe in \
        "$MODDIR/system/bin/netproxy" \
        "${0%/*}/system/bin/netproxy" \
        "/data/adb/modules/netstats-fix/system/bin/netproxy" \
        "/data/adb/modules/netstats-fix-lite/system/bin/netproxy" \
        "/system/bin/netproxy"; do
        [ -f "$probe" ] && { echo "$probe"; return 0; }
    done
    local found
    found=$(find /data/adb/modules -name "netproxy" -type f 2>/dev/null | head -1)
    [ -n "$found" ] && { echo "$found"; return 0; }
    return 1
}

select_arch_binary() {
    local base_bin="$1"
    local dir; dir=$(dirname "$base_bin")
    local arch; arch=$(getprop ro.product.cpu.abi 2>/dev/null)
    case "$arch" in
        arm64-v8a|arm64)
            [ -f "$base_bin" ] && { echo "$base_bin"; return 0; }
            [ -f "$dir/netproxy_arm" ] && { echo "$dir/netproxy_arm"; return 0; }
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

start_nproxy() {
    local bin="$1"
    chmod 755 "$bin"
    log "Starting netproxy: $bin"
    nohup "$bin" >> "$LOG" 2>&1 &
    local pid=$!
    log "Proxy launched (pid=$pid)"
    sleep 2
    if kill -0 "$pid" 2>/dev/null; then
        log "Proxy running (PID $pid)"
        echo "$pid"
        return 0
    fi
    log "Proxy exited, retrying..."
    sleep 2
    nohup "$bin" >> "$LOG" 2>&1 &
    pid=$!
    sleep 3
    if kill -0 "$pid" 2>/dev/null; then
        log "Proxy running after retry (PID $pid)"
        echo "$pid"
        return 0
    fi
    log "Proxy failed both attempts"
    return 1
}

log "=== service-lite.sh started ==="
WAIT=0
while [ "$(getprop sys.boot_completed)" != "1" ] && [ "$WAIT" -lt 180 ]; do
    sleep 1; WAIT=$((WAIT + 1))
done
log "Boot completed after ${WAIT}s"
sleep 8

# SELinux: allow reading /proc/net/dev and binder access
MAGISKPOLICY=$(command -v magiskpolicy 2>/dev/null)
if [ -n "$MAGISKPOLICY" ]; then
    "$MAGISKPOLICY" --live "allow domain proc_net:file { read open getattr }" 2>/dev/null
    "$MAGISKPOLICY" --live "allow domain proc_net:dir { read search open }" 2>/dev/null
    "$MAGISKPOLICY" --live "allow domain binder_device:chr_file { read write open ioctl }" 2>/dev/null
    "$MAGISKPOLICY" --live "allow domain binder:service_manager { find add }" 2>/dev/null
    "$MAGISKPOLICY" --live "allow domain netd:fd use" 2>/dev/null
    "$MAGISKPOLICY" --live "allow system_server proc_net:file { read open getattr }" 2>/dev/null
    "$MAGISKPOLICY" --live "allow system_server proc_net:dir { read search open }" 2>/dev/null
    log "SELinux policies applied"
fi

chmod 0644 /proc/net/dev 2>/dev/null
chmod 0644 /proc/self/net/dev 2>/dev/null

PROXY_BIN=$(find_netproxy)
if [ -z "$PROXY_BIN" ]; then
    log "FATAL: netproxy not found"
    log "MODDIR=$MODDIR"
    exit 1
fi

TARGET_BIN=$(select_arch_binary "$PROXY_BIN")
[ -z "$TARGET_BIN" ] && TARGET_BIN="$PROXY_BIN"
log "Found binary: $TARGET_BIN (arch: $(getprop ro.product.cpu.abi 2>/dev/null))"

PROXY_PID=$(start_nproxy "$TARGET_BIN")
if [ -z "$PROXY_PID" ]; then
    log "Proxy failed to start"
fi

# Wait for netproxy to register with ServiceManager
REG_OK=0
for RTRY in 1 2 3; do
    sleep 3
    if grep -q "registered '" "$LOG" 2>/dev/null; then
        REG_OK=1
        log "Netproxy registered with ServiceManager (attempt $RTRY)"
        break
    fi
    if grep -q "WARNING:" "$LOG" 2>/dev/null; then
        log "Netproxy registration failed, retrying..."
        kill -9 "$PROXY_PID" 2>/dev/null
        PROXY_PID=$(start_nproxy "$TARGET_BIN")
    fi
done

if [ "$REG_OK" -eq 0 ]; then
    log "WARNING: Netproxy NOT registered after $RTRY attempts"
    log "  Traffic indicator may still show 0"
    log "  Last log lines:"
    tail -5 "$LOG" 2>/dev/null | while IFS= read -r l; do log "  $l"; done
    echo "REG_FAILED" > /data/local/tmp/netproxy_reg_status 2>/dev/null
else
    echo "REG_OK" > /data/local/tmp/netproxy_reg_status 2>/dev/null
fi

# Settings
settings put global restricted_networking_mode 0 2>/dev/null

ATTEMPT=0
while [ "$ATTEMPT" -lt 12 ]; do
    ATTEMPT=$((ATTEMPT+1))
    settings put global network_stats_enabled 1 2>/dev/null
    sleep 2
    NSE=$(settings get global network_stats_enabled 2>/dev/null)
    [ "$NSE" = "1" ] && log "network_stats_enabled=1 (attempt $ATTEMPT)" && break
done

settings put global netstats_enabled 1 2>/dev/null
cmd netstats force-refresh 2>/dev/null || true

# Restart SystemUI to pick up our service
sleep 3
killall -9 com.android.systemui 2>/dev/null || \
    pkill -9 -f "com.android.systemui" 2>/dev/null || \
    am force-stop com.android.systemui 2>/dev/null
log "SystemUI killed"
sleep 8
SYSUI_PID=$(pidof com.android.systemui 2>/dev/null)
log "SystemUI running as pid=$SYSUI_PID"

if [ "$REG_OK" -eq 0 ]; then
    log "WARNING: netproxy NOT registered. Consider trying the full module with BPF restoration."
fi

log "=== service-lite.sh complete ==="

# Watchdog
WD=0
while true; do
    sleep 300
    WD=$((WD+1))
    NSE=$(settings get global network_stats_enabled 2>/dev/null)
    [ "$NSE" != "1" ] && settings put global network_stats_enabled 1 2>/dev/null && log "[WD] restored network_stats_enabled"
    if ! pidof netproxy > /dev/null 2>&1; then
        log "[WD] Proxy died restarting..."
        PROXY_PID=$(start_nproxy "$TARGET_BIN")
        REG_OK=0
        for RTRY in 1 2 3; do
            sleep 3
            if grep -q "registered '" "$LOG" 2>/dev/null; then
                REG_OK=1
                log "[WD] Netproxy registered (attempt $RTRY)"
                # Restart SystemUI to pick up new registration
                killall -9 com.android.systemui 2>/dev/null || true
                break
            fi
        done
        if [ "$REG_OK" -eq 0 ]; then
            log "[WD] Netproxy still NOT registered after restart"
        fi
    fi
done
