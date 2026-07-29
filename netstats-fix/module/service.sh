#!/system/bin/sh
MODDIR=${0%/*}
LOG=/data/local/tmp/netproxy.log
PROXY_DEX="$MODDIR/proxy.dex"

echo "=== netproxy service.sh start ===" > "$LOG"

while [ "$(getprop sys.boot_completed)" != "1" ]; do sleep 2; done
echo "boot completed" >> "$LOG"
sleep 5
echo "starting proxy daemon..." >> "$LOG"

if [ ! -f "$PROXY_DEX" ]; then
    echo "FATAL: proxy.dex not found at $PROXY_DEX" >> "$LOG"; exit 1
fi
echo "proxy.dex size: $(stat -c%s "$PROXY_DEX" 2>/dev/null || wc -c < "$PROXY_DEX")" >> "$LOG"

APP_PROC=$(command -v app_process 2>/dev/null || echo "/system/bin/app_process")
if [ ! -f "$APP_PROC" ]; then
    echo "FATAL: app_process not found at $APP_PROC" >> "$LOG"; exit 1
fi
echo "app_process: $APP_PROC" >> "$LOG"

chmod 0644 /proc/net/dev 2>/dev/null
echo "proc_net_dev: $(ls -la /proc/net/dev 2>/dev/null)" >> "$LOG"

magiskpolicy --live "allow * proc_net:file { read open getattr }" 2>/dev/null
echo "magiskpolicy applied" >> "$LOG"

CLASSPATH="$PROXY_DEX" nohup "$APP_PROC" /system/bin com.flint.netstats.NetworkStatsProxy >> "$LOG" 2>&1 &
PROXY_PID=$!
echo "proxy launched pid=$PROXY_PID" >> "$LOG"

sleep 15
echo "restarting SystemUI..." >> "$LOG"
am force-stop com.android.systemui 2>/dev/null
echo "done" >> "$LOG"
exit 0
