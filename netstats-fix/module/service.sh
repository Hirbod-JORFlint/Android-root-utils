#!/system/bin/sh
# service.sh - Late boot initialization for netstats-fix v7 (Binder proxy)
# Runs after system is fully booted

MODDIR=${0%/*}

# Wait for boot completion
while [ "$(getprop sys.boot_completed)" != "1" ]; do
    sleep 5
done

sleep 10

# Ensure /proc/net/dev is readable
chmod 0644 /proc/net/dev 2>/dev/null

# Add SELinux policy for the proxy domain
magiskpolicy --live "allow magisk proc_net:file { read open getattr }" 2>/dev/null
magiskpolicy --live "allow su proc_net:file { read open getattr }" 2>/dev/null
magiskpolicy --live "allow shell proc_net:file { read open getattr }" 2>/dev/null
magiskpolicy --live "allow init proc_net:file { read open getattr }" 2>/dev/null

# Launch the Binder proxy daemon
export CLASSPATH="$MODDIR/proxy.dex"
nohup app_process /system/bin com.opencode.netstats.NetworkStatsProxy </dev/null >/dev/null 2>&1 &
PROXY_PID=$!

# Wait for proxy to register, then restart SystemUI to force re-cache
sleep 15
am force-stop com.android.systemui 2>/dev/null

exit 0
