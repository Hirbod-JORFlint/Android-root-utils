#!/system/bin/sh
MODDIR=${0%/*}
LOG=/data/local/tmp/netproxy.log
PROXY_BIN="$MODDIR/system/bin/netproxy"

echo "=== netproxy service.sh start ===" > "$LOG"

while [ "$(getprop sys.boot_completed)" != "1" ]; do sleep 2; done
echo "boot completed" >> "$LOG"
sleep 5
echo "starting native netproxy..." >> "$LOG"

if [ ! -f "$PROXY_BIN" ]; then
    echo "FATAL: netproxy binary not found at $PROXY_BIN" >> "$LOG"; exit 1
fi
echo "netproxy size: $(stat -c%s "$PROXY_BIN" 2>/dev/null || wc -c < "$PROXY_BIN")" >> "$LOG"

chmod 0644 /proc/net/dev 2>/dev/null
echo "proc_net_dev: $(ls -la /proc/net/dev 2>/dev/null)" >> "$LOG"

# SELinux rules
magiskpolicy --live "allow * proc_net:file { read open getattr }" 2>/dev/null
magiskpolicy --live "allow * binder_device:chr_file { read write open ioctl }" 2>/dev/null
magiskpolicy --live "allow * binder:service_manager { find add }" 2>/dev/null
echo "magiskpolicy applied" >> "$LOG"

nohup "$PROXY_BIN" >> "$LOG" 2>&1 &
PROXY_PID=$!
echo "proxy launched pid=$PROXY_PID" >> "$LOG"

sleep 15
echo "restarting SystemUI..." >> "$LOG"
killall -9 com.android.systemui 2>/dev/null || \
  pkill -9 -f "com.android.systemui" 2>/dev/null || \
  am force-stop com.android.systemui 2>/dev/null
echo "SystemUI killed, waiting for restart..." >> "$LOG"
sleep 5
SYSUI_PID=$(pidof com.android.systemui 2>/dev/null)
echo "SystemUI running as pid=$SYSUI_PID" >> "$LOG"
echo "done" >> "$LOG"
exit 0
