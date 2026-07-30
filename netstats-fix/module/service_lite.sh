#!/system/bin/sh
MODDIR=${0%/*}
LOG=/data/local/tmp/netproxy.log

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [service-lite] $*" >> "$LOG"; }

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

check_registered() {
    grep -q "registered '" "$LOG" 2>/dev/null && return 0
    [ -f /data/local/tmp/netproxy_registered ] && return 0
    return 1
}

apply_sepolicy() {
    local MP; MP=$(command -v magiskpolicy 2>/dev/null || echo "")
    [ -z "$MP" ] && { log "magiskpolicy not found; relying on sepolicy.rule"; return 0; }
    log "Applying live SELinux rules..."
    "$MP" --live "allow domain proc_net:file { read open getattr }" 2>/dev/null
    "$MP" --live "allow domain proc_net:dir { read search open }" 2>/dev/null
    "$MP" --live "allow domain binder_device:chr_file { read write open ioctl }" 2>/dev/null
    "$MP" --live "allow domain servicemanager:binder { call transfer }" 2>/dev/null
    "$MP" --live "allow domain servicemanager:service_manager { find add }" 2>/dev/null
    "$MP" --live "allow domain netstats_service:service_manager { add }" 2>/dev/null
    "$MP" --live "allow domain default_android_service:service_manager { add find }" 2>/dev/null
    "$MP" --live "allow domain netd:fd use" 2>/dev/null
    "$MP" --live "allow system_server proc_net:file { read open getattr }" 2>/dev/null
    "$MP" --live "allow system_server proc_net:dir { read search open }" 2>/dev/null
    "$MP" --live "allow system_app proc_net:file { read open getattr }" 2>/dev/null
    "$MP" --live "allow platform_app proc_net:file { read open getattr }" 2>/dev/null
    "$MP" --live "allow * * service_manager { add find }" 2>/dev/null
    log "SELinux policies applied"
}

log "=== service-lite.sh started ==="
WAIT=0
while [ "$(getprop sys.boot_completed)" != "1" ] && [ "$WAIT" -lt 180 ]; do
    sleep 1; WAIT=$((WAIT + 1))
done
log "Boot completed after ${WAIT}s"
sleep 8

apply_sepolicy

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

REG_OK=0
for RTRY in 1 2 3 4 5; do
    sleep 3
    if check_registered; then
        REG_OK=1
        log "Netproxy registered with ServiceManager (attempt $RTRY)"
        break
    fi
    if [ -n "$PROXY_PID" ] && ! kill -0 "$PROXY_PID" 2>/dev/null; then
        log "Proxy died, restarting..."
        PROXY_PID=$(start_nproxy "$TARGET_BIN")
        continue
    fi
    apply_sepolicy
done

if [ "$REG_OK" -eq 0 ]; then
    log "WARNING: Netproxy NOT registered after $RTRY attempts"
    log "  Traffic indicator may still show 0"
    log "  Last log lines:"
    tail -10 "$LOG" 2>/dev/null | while IFS= read -r l; do log "  $l"; done
    echo "REG_FAILED" > /data/local/tmp/netproxy_reg_status 2>/dev/null
else
    echo "REG_OK" > /data/local/tmp/netproxy_reg_status 2>/dev/null
fi

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

# Only restart SystemUI if proxy registered (avoids boot loops)
if [ "$REG_OK" -eq 1 ]; then
    sleep 3
    am force-stop com.android.systemui 2>/dev/null
    log "SystemUI killed"
    sleep 8
    SYSUI_PID=$(pidof com.android.systemui 2>/dev/null)
    log "SystemUI running as pid=$SYSUI_PID"
else
    log "Skipping SystemUI restart (proxy not registered)"
fi

if [ "$REG_OK" -eq 0 ]; then
    log "WARNING: netproxy NOT registered."
fi

log "=== service-lite.sh complete ==="

WD=0
while true; do
    sleep 300
    WD=$((WD+1))
    NSE=$(settings get global network_stats_enabled 2>/dev/null)
    [ "$NSE" != "1" ] && settings put global network_stats_enabled 1 2>/dev/null && log "[WD] restored network_stats_enabled"

    if pidof netproxy > /dev/null 2>&1; then
        if ! check_registered; then
            log "[WD] Proxy running but not registered, waiting..."
            sleep 10
            if ! check_registered; then
                log "[WD] Still not registered, restarting proxy"
                killall -9 netproxy 2>/dev/null || true
                sleep 1
                PROXY_PID=$(start_nproxy "$TARGET_BIN")
                REG_OK=0
                for RTRY in 1 2 3; do
                    sleep 3
                    if check_registered; then
                        REG_OK=1
                        log "[WD] Netproxy registered (attempt $RTRY)"
                        am force-stop com.android.systemui 2>/dev/null || true
                        break
                    fi
                done
                if [ "$REG_OK" -eq 0 ]; then
                    log "[WD] Netproxy NOT registered after restart"
                fi
            fi
        fi
    else
        log "[WD] Proxy died, restarting..."
        PROXY_PID=$(start_nproxy "$TARGET_BIN")
    fi
done
