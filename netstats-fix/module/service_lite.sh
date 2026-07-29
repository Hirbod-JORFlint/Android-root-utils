#!/system/bin/sh
MODDIR=${0%/*}
LOG=/data/local/tmp/netproxy.log
PROXY_BIN="$MODDIR/system/bin/netproxy"

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

# Apply comprehensive SELinux policies via magiskpolicy
magiskpolicy --live "allow * proc_net:file { read open getattr }" 2>/dev/null
magiskpolicy --live "allow * proc_net:dir { read search open }" 2>/dev/null
magiskpolicy --live "allow * binder_device:chr_file { read write open ioctl }" 2>/dev/null
magiskpolicy --live "allow * binder:service_manager { find add }" 2>/dev/null
magiskpolicy --live "allow * netd:fd use" 2>/dev/null
magiskpolicy --live "allow system_server proc_net:file { read open getattr }" 2>/dev/null
magiskpolicy --live "allow system_server proc_net:dir { read search open }" 2>/dev/null
log "SELinux policies applied"

# Try to find the right arch binary
if [ -f "$PROXY_BIN" ]; then
    TARGET_BIN="$PROXY_BIN"
else
    ARCH=$(getprop ro.product.cpu.abi 2>/dev/null)
    case "$ARCH" in
        arm64-v8a|arm64)
            TARGET_BIN="$PROXY_BIN"
            [ ! -f "$TARGET_BIN" ] && TARGET_BIN="$MODDIR/system/bin/netproxy"
            ;;
        armeabi-v7a|armeabi)
            TARGET_BIN="$MODDIR/system/bin/netproxy_arm"
            [ ! -f "$TARGET_BIN" ] && TARGET_BIN="$PROXY_BIN"
            ;;
        *)
            TARGET_BIN="$PROXY_BIN"
            ;;
    esac
fi

if [ -f "$TARGET_BIN" ]; then
    chmod 755 "$TARGET_BIN"
    log "Starting netproxy: $TARGET_BIN"
    nohup "$TARGET_BIN" >> "$LOG" 2>&1 &
    PROXY_PID=$!
    log "Proxy launched (pid=$PROXY_PID)"
    sleep 2
    if kill -0 "$PROXY_PID" 2>/dev/null; then
        log "Proxy is running"
    else
        log "Proxy exited prematurely"
    fi
else
    log "FATAL: netproxy not found"
    exit 1
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
