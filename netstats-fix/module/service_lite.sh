#!/system/bin/sh
MODDIR=${0%/*}
LOG=/data/local/tmp/netproxy.log
REGFILE=/data/local/tmp/netproxy_registered
STATSFILE=/data/local/tmp/netproxy_stats
NETSTATS_DIR=/data/misc/netstats

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [LITE] $*" >> "$LOG"; }
warn() { echo "$(date '+%Y-%m-%d %H:%M:%S') [LITE-WARN] $*" >> "$LOG"; }

log_sep() { echo "--- $* ---" >> "$LOG"; }

find_netproxy() {
    for probe in "$MODDIR/system/bin/netproxy" "${0%/*}/system/bin/netproxy" \
        "/data/adb/modules/netstats-fix/system/bin/netproxy" \
        "/data/adb/modules/netstats-fix-lite/system/bin/netproxy" "/system/bin/netproxy"; do
        [ -f "$probe" ] && { echo "$probe"; return 0; }
    done
    local f=$(find /data/adb/modules -name "netproxy" -type f 2>/dev/null | head -1)
    [ -n "$f" ] && { echo "$f"; return 0; }
    return 1
}

start_nproxy() {
    local bin="$1"; local ctx="$2"
    chmod 755 "$bin"
    local sz=$(wc -c < "$bin" 2>/dev/null || echo "?")
    log "Binary: $bin ($sz bytes)"
    log "Context: ${ctx:-default}"
    log "SELinux: $(getenforce 2>/dev/null)"
    log "Starting..."
    if [ -n "$ctx" ] && command -v runcon >/dev/null 2>&1; then
        nohup runcon "$ctx" "$bin" >> "$LOG" 2>&1 &
    else
        nohup "$bin" >> "$LOG" 2>&1 &
    fi
    local pid=$!
    log "Launched pid=$pid"
    sleep 4
    if kill -0 "$pid" 2>/dev/null; then
        log "Running (PID $pid)"
        echo "$pid"; return 0
    fi
    log "Retrying..."
    sleep 3
    if [ -n "$ctx" ] && command -v runcon >/dev/null 2>&1; then
        nohup runcon "$ctx" "$bin" >> "$LOG" 2>&1 &
    else
        nohup "$bin" >> "$LOG" 2>&1 &
    fi
    pid=$!; sleep 5
    if kill -0 "$pid" 2>/dev/null; then
        log "Running after retry (PID $pid)"
        echo "$pid"; return 0
    fi
    warn "Failed to start after retry"
    return 1
}

check_registered() { grep -q "REGISTERED" "$LOG" 2>/dev/null || [ -f "$REGFILE" ]; }

apply_sepolicy() {
    local MP=$(command -v magiskpolicy 2>/dev/null || echo "")
    [ -z "$MP" ] && { log "magiskpolicy not found"; return 0; }
    log "Applying live SELinux rules..."
    "$MP" --live "allow domain servicemanager:service_manager { find add }" 2>/dev/null
    "$MP" --live "allow domain default_android_service:service_manager { add find }" 2>/dev/null
    "$MP" --live "allow domain netstats_service:service_manager { add }" 2>/dev/null
    "$MP" --live "allow domain * service_manager { add find }" 2>/dev/null
    "$MP" --live "allow * * service_manager { find add }" 2>/dev/null
    "$MP" --live "allow domain proc_net:file { read open getattr }" 2>/dev/null
    "$MP" --live "allow domain proc_net:dir { read search open }" 2>/dev/null
    "$MP" --live "allow domain binder_device:chr_file { read write open ioctl }" 2>/dev/null
    "$MP" --live "allow domain servicemanager:binder { call transfer }" 2>/dev/null
    "$MP" --live "allow system_server proc_net:file { read open getattr }" 2>/dev/null
    "$MP" --live "allow system_app proc_net:file { read open getattr }" 2>/dev/null
    "$MP" --live "allow platform_app proc_net:file { read open getattr }" 2>/dev/null
    "$MP" --live "allow untrusted_app proc_net:file { read open getattr }" 2>/dev/null
    log "SELinux rules applied"
}

write_netstats_xml() {
    mkdir -p "$NETSTATS_DIR" 2>/dev/null

    local total_rx=0 total_tx=0 iface_count=0
    local dev_entries=""

    if [ -f /proc/net/dev ]; then
        while IFS= read -r line; do
            local iface=$(echo "$line" | cut -d: -f1 | tr -d ' ')
            [ -z "$iface" ] && continue; [ "$iface" = "lo" ] && continue
            [ "$iface" = "Inter-|" ] && continue; [ "$iface" = "face" ] && continue
            local vals=$(echo "$line" | cut -d: -f2)
            local rb=$(echo "$vals" | awk '{print $1}'); local rp=$(echo "$vals" | awk '{print $2}')
            local tb=$(echo "$vals" | awk '{print $9}'); local tp=$(echo "$vals" | awk '{print $10}')
            rb=${rb:-0}; rp=${rp:-0}; tb=${tb:-0}; tp=${tp:-0}
            total_rx=$((total_rx + rb)); total_tx=$((total_tx + tb))
            dev_entries="${dev_entries}<st if=\"$iface\" dev=\"$iface\" uid=\"-1\" tag=\"0x0\" set=\"default\" rb=\"$rb\" rp=\"$rp\" tb=\"$tb\" tp=\"$tp\" />"$'\n'
            iface_count=$((iface_count + 1))
        done < /proc/net/dev 2>/dev/null
    fi

    if [ "$iface_count" -eq 0 ]; then
        dev_entries="<st if=\"wlan0\" dev=\"wlan0\" uid=\"-1\" tag=\"0x0\" set=\"default\" rb=\"0\" rp=\"0\" tb=\"0\" tp=\"0\" />"$'\n'
    fi

    cat > "$NETSTATS_DIR/netstats_dev.xml" <<EOF
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<stats devDetail="true">
${dev_entries}</stats>
EOF

    cat > "$NETSTATS_DIR/netstats_uid.xml" <<EOF
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<stats uidStats="true">
</stats>
EOF

    chmod 0644 "$NETSTATS_DIR/netstats_dev.xml" 2>/dev/null
    chmod 0644 "$NETSTATS_DIR/netstats_uid.xml" 2>/dev/null
    chown 1000:1000 "$NETSTATS_DIR" 2>/dev/null || true
    log "Wrote XML: ifaces=$iface_count rx=$total_rx tx=$total_tx"
}

update_proxy_stats() {
    local trx=0 ttx=0 trxp=0 ttxp=0 ic=0
    > "$STATSFILE" 2>/dev/null
    if [ ! -f /proc/net/dev ]; then return; fi
    while IFS= read -r line; do
        local iface=$(echo "$line" | cut -d: -f1 | tr -d ' ')
        [ -z "$iface" ] && continue; [ "$iface" = "lo" ] && continue
        [ "$iface" = "Inter-|" ] && continue; [ "$iface" = "face" ] && continue
        local vals=$(echo "$line" | cut -d: -f2)
        local rb=$(echo "$vals" | awk '{print $1}'); local rp=$(echo "$vals" | awk '{print $2}')
        local tb=$(echo "$vals" | awk '{print $9}'); local tp=$(echo "$vals" | awk '{print $10}')
        rb=${rb:-0}; rp=${rp:-0}; tb=${tb:-0}; tp=${tp:-0}
        trx=$((trx+rb)); ttx=$((ttx+tb)); trxp=$((trxp+rp)); ttxp=$((ttxp+tp))
        ic=$((ic+1))
        echo "iface_${iface}_rx=$rb" >> "$STATSFILE"
        echo "iface_${iface}_tx=$tb" >> "$STATSFILE"
        echo "iface_${iface}_rxp=$rp" >> "$STATSFILE"
        echo "iface_${iface}_txp=$tp" >> "$STATSFILE"
    done < /proc/net/dev 2>/dev/null
    echo "rx_bytes=$trx" >> "$STATSFILE"
    echo "tx_bytes=$ttx" >> "$STATSFILE"
    echo "rx_packets=$trxp" >> "$STATSFILE"
    echo "tx_packets=$ttxp" >> "$STATSFILE"
    echo "iface_count=$ic" >> "$STATSFILE"
    echo "timestamp=$(date +%s 2>/dev/null || echo 0)" >> "$STATSFILE"
}

background_updater() {
    local C=0
    while true; do
        sleep 30; C=$((C+1))
        write_netstats_xml
        update_proxy_stats
        log "[BG-$C] stats updated: rx=$(grep '^rx_bytes=' "$STATSFILE" 2>/dev/null | cut -d= -f2) tx=$(grep '^tx_bytes=' "$STATSFILE" 2>/dev/null | cut -d= -f2)"
    done
}

#========================================================================
log_sep "=============================================="
log_sep "  service-lite.sh v8.0 - STARTED"
log_sep "=============================================="
log "MODDIR: $MODDIR"
log "Kernel: $(uname -r) ($(uname -r | cut -d. -f1).$(uname -r | cut -d. -f2))"
log "SDK: $(getprop ro.build.version.sdk 2>/dev/null)"
log "Android: $(getprop ro.build.version.release 2>/dev/null)"
log "Arch: $(getprop ro.product.cpu.abi 2>/dev/null)"
log "SELinux: $(getenforce 2>/dev/null)"
log "Build: $(getprop ro.build.display.id 2>/dev/null)"

log "Waiting for boot completion..."
local W=0
while [ "$(getprop sys.boot_completed)" != "1" ] && [ "$W" -lt 300 ]; do
    sleep 1; W=$((W+1))
done
log "Boot completed after ${W}s"
if [ "$W" -ge 300 ]; then warn "Boot timeout!"; fi

sleep 15
log_sep "ENVIRONMENT"

log "SELinux: $(getenforce 2>/dev/null)"
log "/proc/net/dev readable: $([ -r /proc/net/dev ] && echo yes || echo no)"
local raw=$(head -20 /proc/net/dev 2>/dev/null | grep -v "Inter-\|face" | grep -v "lo:" | grep -v "^$" | head -5)
log "Interfaces with data:"
echo "$raw" | while IFS= read -r l; do
    local iface=$(echo "$l" | cut -d: -f1 | tr -d ' ')
    local vals=$(echo "$l" | cut -d: -f2)
    local rb=$(echo "$vals" | awk '{print $1}'); local tb=$(echo "$vals" | awk '{print $9}')
    log "  $iface: rx=$rb tx=$tb"
done
log "BPF maps: $(ls /sys/fs/bpf/netd_shared/map_netd_* 2>/dev/null | wc -l)"
log "Tethering APEX: $([ -d /apex/com.android.tethering ] && echo mounted || echo absent)"
log "System variant: $([ -d /system_axion ] && echo Axion || ([ -d /system_infinity ] && echo Infinity || echo Standard))"

log "Checking /proc/net/dev permissions..."
ls -la /proc/net/dev 2>/dev/null | while IFS= read -r l; do log "  $l"; done
chmod 0644 /proc/net/dev 2>/dev/null
chmod 0644 /proc/self/net/dev 2>/dev/null
log "Permissions updated"

log "dmesg SELinux denials (bpf/netd related):"
dmesg 2>/dev/null | grep 'avc:.*denied' | grep -iE 'bpf|netd|bpfloader|proc_net|service_manager|netstats|servicemanager' | tail -20 | while IFS= read -r l; do warn "  DENIAL: $l"; done

apply_sepolicy

log_sep "PHASE 1: Kill existing netproxy"
local old_pid=$(pidof netproxy 2>/dev/null)
if [ -n "$old_pid" ]; then
    log "Killing existing netproxy (PID $old_pid)"
    kill -9 "$old_pid" 2>/dev/null
    sleep 2
fi
rm -f "$REGFILE" 2>/dev/null

log_sep "PHASE 2: Find and start netproxy"
local PROXY_BIN=$(find_netproxy)
if [ -z "$PROXY_BIN" ]; then
    warn "FATAL: netproxy binary not found!"
    ls -la "$MODDIR/system/bin/" 2>/dev/null | while IFS= read -r l; do log "  $l"; done
else
    log "Found: $PROXY_BIN"
    log "Trying with default context..."
    PROXY_PID=$(start_nproxy "$PROXY_BIN")
    if [ -z "$PROXY_PID" ]; then
        log "Trying with system_app context..."
        PROXY_PID=$(start_nproxy "$PROXY_BIN" "u:r:system_app:s0")
    fi
    if [ -z "$PROXY_PID" ]; then
        warn "netproxy failed to start in all contexts"
        log "Will rely on file-based stats only"
    fi
fi

log_sep "PHASE 3: Wait for registration"
local REG_OK=0
local START_TS=$(date +%s)
for RTRY in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    local waited=$(($(date +%s) - START_TS))
    if [ -n "$PROXY_PID" ] && ! kill -0 "$PROXY_PID" 2>/dev/null; then
        warn "Proxy died at ${waited}s, restarting..."
        PROXY_PID=$(start_nproxy "$PROXY_BIN")
        [ -z "$PROXY_PID" ] && PROXY_PID=$(start_nproxy "$PROXY_BIN" "u:r:system_app:s0")
    fi

    if check_registered; then
        REG_OK=1
        log "*** REGISTERED (attempt $RTRY, ${waited}s) ***"
        log "Registration log context:"
        grep -i "registered\|REGISTERED" "$LOG" 2>/dev/null | tail -5 | while IFS= read -r l; do log "  $l"; done
        break
    fi
    sleep 3

    if [ "$((RTRY % 4))" -eq 0 ]; then
        apply_sepolicy
        local denials=$(dmesg 2>/dev/null | grep 'avc:.*denied' | grep -iE 'service_manager|servicemanager|proc_net' | tail -5)
        [ -n "$denials" ] && echo "$denials" | while IFS= read -r l; do warn "  DENIAL: $l"; done
    fi
    log "Registration: attempt $RTRY/20 (${waited}s), proxy=$(pidof netproxy 2>/dev/null || echo dead)"
done

if [ "$REG_OK" -eq 0 ]; then
    warn "REGISTRATION FAILED after 20 attempts ($(($(date +%s) - START_TS))s)"
    warn "Netproxy is running but cannot register with ServiceManager."
    warn "Check SELinux denials above."
    grep -i "WARNING\|ERROR\|FAILED\|denied\|BR_" "$LOG" 2>/dev/null | tail -20 | while IFS= read -r l; do warn "  $l"; done
fi

log_sep "PHASE 4: Settings"
settings put global restricted_networking_mode 0 2>/dev/null
log "restricted_networking_mode: $(settings get global restricted_networking_mode 2>/dev/null)"

for A in 1 2 3 4 5 6 7 8; do
    settings put global network_stats_enabled 1 2>/dev/null
    sleep 1
    local V=$(settings get global network_stats_enabled 2>/dev/null)
    [ "$V" = "1" ] && { log "network_stats_enabled=1 (attempt $A)"; break; }
    content insert --uri content://settings/global --bind name:s:network_stats_enabled --bind value:s:1 2>/dev/null || true
    log "  attempt $A: got '$V'"
done

settings put global netstats_enabled 1 2>/dev/null
cmd netstats force-refresh 2>/dev/null && log "netstats force-refresh OK" || log "netstats force-refresh N/A"
cmd netstatscore force-refresh 2>/dev/null || true

log_sep "PHASE 5: Write netstats files to /data/misc/netstats"
write_netstats_xml
update_proxy_stats

log "Contents of $NETSTATS_DIR:"
ls -la "$NETSTATS_DIR/" 2>/dev/null | while IFS= read -r l; do log "  $l"; done

log "Stats file contents:"
head -10 "$STATSFILE" 2>/dev/null | while IFS= read -r l; do log "  $l"; done

log_sep "PHASE 6: Verify stats availability"
local srx=$(grep '^rx_bytes=' "$STATSFILE" 2>/dev/null | cut -d= -f2)
local stx=$(grep '^tx_bytes=' "$STATSFILE" 2>/dev/null | cut -d= -f2)
log "Stats from file: rx=$srx tx=$stx"

log "Stats from /proc/net/dev:"
grep -v "lo:" /proc/net/dev 2>/dev/null | grep -v "Inter-\|face" | grep -v "^$" | awk '{print $1, $2, $10}' | while IFS= read -r l; do log "  $l"; done

log_sep "PHASE 7: SystemUI restart"
if [ "$REG_OK" -eq 1 ]; then
    log "Proxy registered, restarting SystemUI..."
    am force-stop com.android.systemui 2>/dev/null
    sleep 12
    log "SystemUI PID: $(pidof com.android.systemui 2>/dev/null)"
else
    log "Proxy not registered, gentle refresh..."
    cmd netstats force-refresh 2>/dev/null || true
fi

log_sep "SUMMARY"
log "  netproxy PID: $(pidof netproxy 2>/dev/null || echo dead)"
log "  Registered: $([ "$REG_OK" -eq 1 ] && echo YES || echo NO)"
log "  network_stats_enabled: $(settings get global network_stats_enabled 2>/dev/null)"
log "  netstats_dev.xml: $(ls -la $NETSTATS_DIR/netstats_dev.xml 2>/dev/null | awk '{print $5 " bytes"}')"
log "  stats file rx: $srx"
log "  stats file tx: $stx"
log_sep "Main execution complete - entering watchdog"

background_updater &
local WD=0
while true; do
    sleep 300; WD=$((WD+1))
    log_sep "WATCHDOG $WD"
    local V=$(settings get global network_stats_enabled 2>/dev/null)
    [ "$V" != "1" ] && settings put global network_stats_enabled 1 2>/dev/null && log "[WD] Restored network_stats_enabled"
    local R=$(settings get global restricted_networking_mode 2>/dev/null)
    [ "$R" = "1" ] && settings put global restricted_networking_mode 0 2>/dev/null && log "[WD] Cleared restricted_networking_mode"

    chmod 0644 /proc/net/dev 2>/dev/null
    chmod 0644 /proc/self/net/dev 2>/dev/null

    if [ -n "$PROXY_BIN" ]; then
        local np=$(pidof netproxy 2>/dev/null)
        if [ -z "$np" ]; then
            warn "[WD] netproxy died, restarting..."
            PROXY_PID=$(start_nproxy "$PROXY_BIN")
            [ -z "$PROXY_PID" ] && PROXY_PID=$(start_nproxy "$PROXY_BIN" "u:r:system_app:s0")
            for R in 1 2 3; do
                sleep 5
                if check_registered; then
                    log "[WD] Re-registered"
                    am force-stop com.android.systemui 2>/dev/null || true
                    break
                fi
            done
        elif ! check_registered; then
            warn "[WD] Running but NOT registered, killing & restarting..."
            kill -9 "$np" 2>/dev/null; sleep 2; rm -f "$REGFILE"
            PROXY_PID=$(start_nproxy "$PROXY_BIN")
            [ -z "$PROXY_PID" ] && PROXY_PID=$(start_nproxy "$PROXY_BIN" "u:r:system_app:s0")
        fi
    fi

    write_netstats_xml
    update_proxy_stats
    local sr=$(grep '^rx_bytes=' "$STATSFILE" 2>/dev/null | cut -d= -f2)
    local st=$(grep '^tx_bytes=' "$STATSFILE" 2>/dev/null | cut -d= -f2)
    log "[WD] stats: rx=$sr tx=$st proxy=$(pidof netproxy 2>/dev/null || echo dead) reg=$(check_registered && echo yes || echo no)"
done
