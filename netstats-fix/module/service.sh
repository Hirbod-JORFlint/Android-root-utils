#!/system/bin/sh
# service.sh - Late boot initialization for netstats-fix v7 (Binder proxy)
# Log: /data/local/tmp/netproxy.log

MODDIR=${0%/*}
LOG=/data/local/tmp/netproxy.log
PROXY_DEX="$MODDIR/proxy.dex"

echo "=== netproxy service.sh start ===" > "$LOG"

# Wait for boot completion
while [ "$(getprop sys.boot_completed)" != "1" ]; do
    sleep 2
done
echo "boot completed" >> "$LOG"

sleep 5
echo "starting proxy daemon..." >> "$LOG"

# Verify DEX exists
if [ ! -f "$PROXY_DEX" ]; then
    echo "FATAL: proxy.dex not found at $PROXY_DEX" >> "$LOG"
    exit 1
fi
echo "proxy.dex size: $(stat -c%s "$PROXY_DEX" 2>/dev/null || wc -c < "$PROXY_DEX")" >> "$LOG"

# Verify app_process exists
APP_PROC=$(command -v app_process 2>/dev/null || echo "/system/bin/app_process")
if [ ! -f "$APP_PROC" ]; then
    echo "FATAL: app_process not found" >> "$LOG"
    exit 1
fi
echo "app_process: $APP_PROC" >> "$LOG"

# Ensure /proc/net/dev is readable
chmod 0644 /proc/net/dev 2>/dev/null
echo "proc_net_dev readable: $(ls -la /proc/net/dev 2>/dev/null)" >> "$LOG"

# Add SELinux policy for the proxy domain
magiskpolicy --live "allow magisk proc_net:file { read open getattr }" 2>/dev/null
magiskpolicy --live "allow su proc_net:file { read open getattr }" 2>/dev/null
magiskpolicy --live "allow init proc_net:file { read open getattr }" 2>/dev/null
magiskpolicy --live "allow shell proc_net:file { read open getattr }" 2>/dev/null
echo "magiskpolicy applied" >> "$LOG"

# Launch the Binder proxy daemon
export CLASSPATH="$PROXY_DEX"
nohup "$APP_PROC" /system/bin com.flint.netstats.NetworkStatsProxy >> "$LOG" 2>&1 &
PROXY_PID=$!
echo "proxy launched pid=$PROXY_PID" >> "$LOG"

# Wait for proxy to register, then restart SystemUI to force re-cache
sleep 15
echo "restarting SystemUI..." >> "$LOG"
am force-stop com.android.systemui 2>/dev/null
echo "done" >> "$LOG"

exit 0
