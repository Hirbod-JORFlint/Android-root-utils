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
sleep 10

chmod 0644 /proc/net/dev 2>/dev/null

magiskpolicy --live "allow * proc_net:file { read open getattr }" 2>/dev/null
magiskpolicy --live "allow * binder_device:chr_file { read write open ioctl }" 2>/dev/null
magiskpolicy --live "allow * binder:service_manager { find add }" 2>/dev/null
log "SELinux policies applied"

if [ -f "$PROXY_BIN" ]; then
    nohup "$PROXY_BIN" >> "$LOG" 2>&1 &
    log "proxy launched pid=$!"
else
    log "FATAL: netproxy not found"
    exit 1
fi

settings put global network_stats_enabled 1 2>/dev/null
settings put global restricted_networking_mode 0 2>/dev/null

sleep 5
killall -9 com.android.systemui 2>/dev/null || pkill -9 -f "com.android.systemui" 2>/dev/null || am force-stop com.android.systemui 2>/dev/null
log "SystemUI killed"
sleep 8
log "SystemUI running as pid=$(pidof com.android.systemui 2>/dev/null)"

log "=== service-lite.sh complete ==="
exit 0
