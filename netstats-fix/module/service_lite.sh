#!/system/bin/sh
MODDIR=${0%/*}
LOG=/data/local/tmp/netproxy.log
REGFILE=/data/local/tmp/netproxy_registered
STATSFILE=/data/local/tmp/netproxy_stats
NETSTATS_DIR=/data/misc/netstats

log()   { echo "$(date '+%Y-%m-%d %H:%M:%S') [LITE] $*" >> "$LOG"; }
warn()  { echo "$(date '+%Y-%m-%d %H:%M:%S') [LITE-WARN] $*" >> "$LOG"; }
die()   { echo "$(date '+%Y-%m-%d %H:%M:%S') [LITE-DIE] $*" >> "$LOG"; exit 1; }
log_sep() { echo "--- $* ---" >> "$LOG"; }

dump_env() {
    log "--- ENV DUMP ---"
    log "MODDIR=$MODDIR"
    log "PWD=$(pwd 2>/dev/null)"
    log "PATH=$PATH"
    log "SHELL=$SHELL"
    log "USER=$(id -un 2>/dev/null || echo unknown)"
    log "UID=$(id -u 2>/dev/null || echo ?)"
    log "PID=$$"
    log "PPID=$PPID"
    log "Kernel: $(uname -r 2>/dev/null || echo ?)"
    log "uname -a: $(uname -a 2>/dev/null || echo ?)"
    log "getprop sys.boot_completed: $(getprop sys.boot_completed 2>/dev/null || echo FAIL)"
    log "getprop init.svc.netd: $(getprop init.svc.netd 2>/dev/null || echo FAIL)"
    log "getprop init.svc.servicemanager: $(getprop init.svc.servicemanager 2>/dev/null || echo ?)"
    log "which getprop: $(command -v getprop 2>/dev/null || echo NOT FOUND)"
    log "which magiskpolicy: $(command -v magiskpolicy 2>/dev/null || echo NOT FOUND)"
    log "which runcon: $(command -v runcon 2>/dev/null || echo NOT FOUND)"
    log "which pidof: $(command -v pidof 2>/dev/null || echo NOT FOUND)"
    log "ls -la /dev/binder*: $(ls -la /dev/binder* 2>/dev/null || echo FAIL)"
    log "cat /proc/net/dev head: $(head -5 /proc/net/dev 2>/dev/null || echo FAIL)"
    log "--- END ENV DUMP ---"
}

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
    [ -n "$ctx" ] && log "runcon available: $(command -v runcon >/dev/null 2>&1 && echo yes || echo no)"
    log "Starting..."
    if [ -n "$ctx" ] && command -v runcon >/dev/null 2>&1; then
        nohup runcon "$ctx" "$bin" >> "$LOG" 2>&1 &
    else
        nohup "$bin" >> "$LOG" 2>&1 &
    fi
    local pid=$!
    log "Launched pid=$pid"
    for WAIT in 1 2 3 4; do
        sleep 1
        if kill -0 "$pid" 2>/dev/null; then
            log "PID $pid still alive after ${WAIT}s"
        else
            warn "PID $pid DIED after ${WAIT}s!"
            wait "$pid" 2>/dev/null
            log "Exit code: $?"
            break
        fi
    done
    if kill -0 "$pid" 2>/dev/null; then
        log "Running (PID $pid)"
        echo "$pid"; return 0
    fi
    log "First attempt failed, checking log for clues..."
    grep -E "ERROR|FATAL|FAILED|denied|Cannot open|No such|binder" "$LOG" 2>/dev/null | tail -10 | while IFS= read -r l; do warn "  $l"; done
    log "Retrying..."
    sleep 3
    if [ -n "$ctx" ] && command -v runcon >/dev/null 2>&1; then
        nohup runcon "$ctx" "$bin" >> "$LOG" 2>&1 &
    else
        nohup "$bin" >> "$LOG" 2>&1 &
    fi
    pid=$!
    log "Retry launched pid=$pid"
    for WAIT in 1 2 3 4 5; do
        sleep 1
        if kill -0 "$pid" 2>/dev/null; then
            log "  Retry PID $pid alive after ${WAIT}s"
        else
            warn "  Retry PID $pid DIED after ${WAIT}s!"
            break
        fi
    done
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
    [ -z "$MP" ] && { log "magiskpolicy not found - rules may not apply"; return 0; }
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
    log_sep "WRITING NETSTATS XML"
    mkdir -p "$NETSTATS_DIR" 2>/dev/null
    log "NETSTATS_DIR=$NETSTATS_DIR"
    log "Current owner: $(ls -ld "$NETSTATS_DIR" 2>/dev/null)"

    local total_rx=0 total_tx=0 iface_count=0
    local dev_entries=""

    if [ -f /proc/net/dev ]; then
        log "/proc/net/dev exists, reading..."
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
            log "  iface=$iface rx=$rb tx=$tb"
        done < /proc/net/dev 2>/dev/null
    else
        log "/proc/net/dev NOT FOUND!"
    fi

    if [ "$iface_count" -eq 0 ]; then
        log "No interfaces found, using wlan0 placeholder"
        dev_entries="<st if=\"wlan0\" dev=\"wlan0\" uid=\"-1\" tag=\"0x0\" set=\"default\" rb=\"0\" rp=\"0\" tb=\"0\" tp=\"0\" />"$'\n'
    fi

    log "Writing netstats_dev.xml ($iface_count interfaces, rx=$total_rx tx=$total_tx)"
    cat > "$NETSTATS_DIR/netstats_dev.xml" <<EOF
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<stats devDetail="true">
${dev_entries}</stats>
EOF
    local RES_DEV=$?
    log "  netstats_dev.xml write exit=$RES_DEV"

    cat > "$NETSTATS_DIR/netstats_uid.xml" <<EOF
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<stats uidStats="true">
</stats>
EOF
    local RES_UID=$?
    log "  netstats_uid.xml write exit=$RES_UID"

    chmod 0644 "$NETSTATS_DIR/netstats_dev.xml" 2>/dev/null
    chmod 0644 "$NETSTATS_DIR/netstats_uid.xml" 2>/dev/null
    chown 1000:1000 "$NETSTATS_DIR/netstats_dev.xml" 2>/dev/null || log "  chown dev.xml: FAILED ($?)"
    chown 1000:1000 "$NETSTATS_DIR/netstats_uid.xml" 2>/dev/null || log "  chown uid.xml: FAILED ($?)"
    chown 1000:1000 "$NETSTATS_DIR" 2>/dev/null || log "  chown dir: FAILED ($?)"
    log "  Final dir: $(ls -la "$NETSTATS_DIR/" 2>/dev/null)"
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
        local sr=$(grep '^rx_bytes=' "$STATSFILE" 2>/dev/null | cut -d= -f2)
        local st=$(grep '^tx_bytes=' "$STATSFILE" 2>/dev/null | cut -d= -f2)
        log "[BG-$C] stats updated: rx=$sr tx=$st"
    done
}

#========================================================================
log_sep "=============================================="
log_sep "  service-lite.sh v8.1 - STARTED"
log_sep "=============================================="
log "MODDIR: $MODDIR"
log "Kernel: $(uname -r) ($(uname -r | cut -d. -f1).$(uname -r | cut -d. -f2))"
log "SDK: $(getprop ro.build.version.sdk 2>/dev/null)"
log "Android: $(getprop ro.build.version.release 2>/dev/null)"
log "Arch: $(getprop ro.product.cpu.abi 2>/dev/null)"
log "SELinux: $(getenforce 2>/dev/null)"
log "Build: $(getprop ro.build.display.id 2>/dev/null)"

dump_env

log "Waiting for boot completion..."
W=0
while [ "$(getprop sys.boot_completed)" != "1" ] && [ "$W" -lt 300 ]; do
    sleep 1; W=$((W+1))
    if [ "$((W % 10))" -eq 0 ]; then
        log "  Still waiting for boot... (${W}s)"
        log "  sys.boot_completed=$(getprop sys.boot_completed 2>/dev/null || echo FAIL)"
        log "  init.svc.bootanim=$(getprop init.svc.bootanim 2>/dev/null || echo ?)"
    fi
done
log "Boot completed after ${W}s"
if [ "$W" -ge 300 ]; then warn "BOOT TIMEOUT after 300s!"; fi

log "Sleeping 15s for system stabilization..."
sleep 15
log "Post-boot sleep done"

log_sep "ENVIRONMENT"
log "SELinux: $(getenforce 2>/dev/null)"
log "/proc/net/dev readable: $([ -r /proc/net/dev ] && echo yes || echo no)"

RAW_DEV=$(head -20 /proc/net/dev 2>/dev/null)
log "Raw /proc/net/dev first 20 lines:"
echo "$RAW_DEV" | while IFS= read -r l; do log "  $l"; done

log "Interfaces with data:"
echo "$RAW_DEV" | grep -v "Inter-\|face" | grep -v "lo:" | grep -v "^$" | head -10 | while IFS= read -r l; do
    iface=$(echo "$l" | cut -d: -f1 | tr -d ' ')
    vals=$(echo "$l" | cut -d: -f2)
    rb=$(echo "$vals" | awk '{print $1}'); tb=$(echo "$vals" | awk '{print $9}')
    log "  $iface: rx=$rb tx=$tb"
done

log "BPF maps: $(ls /sys/fs/bpf/netd_shared/map_netd_* 2>/dev/null | wc -l)"
BPF_MAP_LIST=$(ls /sys/fs/bpf/netd_shared/map_netd_* 2>/dev/null)
if [ -n "$BPF_MAP_LIST" ]; then
    echo "$BPF_MAP_LIST" | while IFS= read -r m; do log "  BPF map: $m"; done
else
    log "  No BPF maps found"
fi
log "Tethering APEX: $([ -d /apex/com.android.tethering ] && echo mounted || echo absent)"
log "System variant: $([ -d /system_axion ] && echo Axion || ([ -d /system_infinity ] && echo Infinity || echo Standard))"

log "Checking /proc/net/dev permissions..."
ls -la /proc/net/dev 2>/dev/null | while IFS= read -r l; do log "  $l"; done
chmod 0644 /proc/net/dev 2>/dev/null; log "chmod /proc/net/dev: $?"
chmod 0644 /proc/self/net/dev 2>/dev/null; log "chmod /proc/self/net/dev: $?"

log "Binder devices:"
for dev in /dev/binder /dev/vndbinder /dev/hwbinder; do
    if [ -e "$dev" ]; then
        info=$(ls -la "$dev" 2>/dev/null)
        log "  $dev: EXISTS ($info)"
    else
        log "  $dev: NOT FOUND"
    fi
done

log "dmesg SELinux denials (binder/service_manager/netstats):"
dmesg 2>/dev/null | grep 'avc:.*denied' | grep -iE 'binder|service_manager|servicemanager|netstats|proc_net' | tail -25 | while IFS= read -r l; do warn "  DENIAL: $l"; done

log "dmesg ServiceManager messages:"
dmesg 2>/dev/null | grep -iE 'service_manager|binder:' | tail -10 | while IFS= read -r l; do log "  SM: $l"; done

apply_sepolicy

log_sep "PHASE 1: Kill existing netproxy"
OLD_PID=$(pidof netproxy 2>/dev/null)
if [ -n "$OLD_PID" ]; then
    log "Killing existing netproxy (PID $OLD_PID)"
    kill -9 "$OLD_PID" 2>/dev/null; log "kill -9 old proxy: $?"
    sleep 2
    if pidof netproxy >/dev/null 2>&1; then
        warn "Old proxy STILL ALIVE after kill -9!"
        kill -9 $(pidof netproxy) 2>/dev/null
        sleep 2
    fi
fi
rm -f "$REGFILE" 2>/dev/null; log "Removed REGFILE: $?"

log_sep "PHASE 2: Find and start netproxy"
PROXY_BIN=$(find_netproxy)
log "find_netproxy result: '${PROXY_BIN:-EMPTY}'"
if [ -z "$PROXY_BIN" ]; then
    warn "FATAL: netproxy binary not found!"
    log "Contents of $MODDIR/system/bin/:"
    ls -la "$MODDIR/system/bin/" 2>/dev/null | while IFS= read -r l; do log "  $l"; done
    log "Contents of /data/adb/modules/:"
    ls -la /data/adb/modules/ 2>/dev/null | while IFS= read -r l; do log "  $l"; done
    log "Will rely on file-based stats only"
else
    log "Found netproxy at: $PROXY_BIN"
    log "File size: $(wc -c < "$PROXY_BIN" 2>/dev/null || echo ?) bytes"
    log "File type: $(file "$PROXY_BIN" 2>/dev/null || echo unknown)"
    log "Trying with default context..."
    PROXY_PID=$(start_nproxy "$PROXY_BIN")
    log "start_nproxy (default) returned: '${PROXY_PID:-EMPTY}'"
    if [ -z "$PROXY_PID" ]; then
        log "Trying with system_app context..."
        PROXY_PID=$(start_nproxy "$PROXY_BIN" "u:r:system_app:s0")
        log "start_nproxy (system_app) returned: '${PROXY_PID:-EMPTY}'"
    fi
    if [ -z "$PROXY_PID" ]; then
        warn "netproxy failed to start in all contexts"
        log "Last 30 lines of log for diagnosis:"
        tail -30 "$LOG" 2>/dev/null | while IFS= read -r l; do warn "  $l"; done
        log "Will rely on file-based stats only"
    fi
fi

log_sep "PHASE 3: Wait for registration"
REG_OK=0
START_TS=$(date +%s)
LAST_LOG_LINE_COUNT=$(wc -l < "$LOG" 2>/dev/null || echo 0)
LAST_TX_COUNT=0
for RTRY in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
    waited=$(($(date +%s) - START_TS))
    log "=== Registration attempt $RTRY/30 (${waited}s) ==="

    # Check if proxy process is alive
    PROXY_ALIVE=$(pidof netproxy 2>/dev/null || echo "")
    if [ -n "$PROXY_PID" ] && [ -z "$PROXY_ALIVE" ]; then
        warn "Proxy process GONE at ${waited}s (was PID $PROXY_PID)!"
        log "  Last 30 log lines before death:"
        tail -30 "$LOG" 2>/dev/null | while IFS= read -r l; do log "  | $l"; done
        log "  Full dmesg for OOM/signal info:"
        dmesg 2>/dev/null | grep -iE "oom|kill|netproxy|out of memory" | tail -10 | while IFS= read -r l; do warn "  KERN: $l"; done
        log "  Attempting restart..."
        PROXY_PID=$(start_nproxy "$PROXY_BIN")
        [ -z "$PROXY_PID" ] && PROXY_PID=$(start_nproxy "$PROXY_BIN" "u:r:system_app:s0")
        if [ -n "$PROXY_PID" ]; then
            log "  Restarted as PID $PROXY_PID"
        else
            warn "  COULD NOT RESTART proxy!"
        fi
    fi

    # Check registration
    if check_registered; then
        REG_OK=1
        log "*** REGISTERED (attempt $RTRY, ${waited}s) ***"
        log "Registration log context:"
        grep -i "registered\|REGISTERED\|SELINUX\|addService\|add_service\|binder opened" "$LOG" 2>/dev/null | tail -20 | while IFS= read -r l; do log "  $l"; done
        break
    fi

    # Show latest netproxy log lines every attempt
    NEW_LINES=$(($(wc -l < "$LOG" 2>/dev/null || echo 0) - LAST_LOG_LINE_COUNT))
    if [ "$NEW_LINES" -gt 0 ]; then
        log "  netproxy log since last check ($NEW_LINES new lines, total=$(wc -l < "$LOG")):"
        tail -$((NEW_LINES > 30 ? 30 : NEW_LINES)) "$LOG" 2>/dev/null | grep -E "ERROR|WARNING|REGISTER|FAIL|opened|ioctl|addService|BR_|TX#|REPLY|passive|hexdump|hex" | while IFS= read -r l; do log "  NP: $l"; done
    fi
    LAST_LOG_LINE_COUNT=$(wc -l < "$LOG" 2>/dev/null || echo 0)

    # Transaction counter
    TX_COUNT=$(grep -c "TX#" "$LOG" 2>/dev/null || echo 0)
    if [ "$TX_COUNT" -ne "$LAST_TX_COUNT" ]; then
        log "  TRANSACTIONS increased: $LAST_TX_COUNT -> $TX_COUNT"
        LAST_TX_COUNT=$TX_COUNT
    fi

    # Check proxy status
    PROXY_PID_CURRENT=$(pidof netproxy 2>/dev/null || echo "")
    log "  Proxy PID: ${PROXY_PID_CURRENT:-dead}"

    sleep 3

    # Periodic SELinux and dmesg checks
    if [ "$((RTRY % 4))" -eq 0 ]; then
        apply_sepolicy
        log "  dmesg SELinux denials check:"
        dmesg 2>/dev/null | grep 'avc:.*denied' | grep -iE 'service_manager|servicemanager|binder|proc_net' | tail -5 | while IFS= read -r l; do warn "  DENIAL: $l"; done
        log "  dmesg ServiceManager check:"
        dmesg 2>/dev/null | grep -iE 'service_manager.*netstats|netstats.*service' | tail -5 | while IFS= read -r l; do log "  SM: $l"; done
        log "  /proc/net/dev check: $(head -3 /proc/net/dev 2>/dev/null | tail -1 || echo unreadable)"
    fi
done

if [ "$REG_OK" -eq 0 ]; then
    warn "REGISTRATION FAILED after 30 attempts ($(($(date +%s) - START_TS))s)"
    warn "Netproxy is running but cannot register with ServiceManager."
    warn "Checking last 50 log entries for clues:"
    grep -i "WARNING\|ERROR\|FAILED\|denied\|BR_\|ioctl.*failed\|Cannot open" "$LOG" 2>/dev/null | tail -30 | while IFS= read -r l; do warn "  $l"; done
    warn "Full dmesg for service_manager denials:"
    dmesg 2>/dev/null | grep -iE 'service_manager|servicemanager' | grep -i 'denied' | tail -20 | while IFS= read -r l; do warn "  $l"; done
fi

log_sep "PHASE 4: Settings"
RNM_BEFORE=$(settings get global restricted_networking_mode 2>/dev/null)
log "restricted_networking_mode before: '$RNM_BEFORE'"
settings put global restricted_networking_mode 0 2>/dev/null
RNM_AFTER=$(settings get global restricted_networking_mode 2>/dev/null)
log "restricted_networking_mode after: '$RNM_AFTER'"

for A in 1 2 3 4 5 6 7 8 9 10; do
    settings put global network_stats_enabled 1 2>/dev/null
    sleep 1
    V=$(settings get global network_stats_enabled 2>/dev/null)
    [ "$V" = "1" ] && { log "network_stats_enabled=1 (attempt $A)"; break; }
    content insert --uri content://settings/global --bind name:s:network_stats_enabled --bind value:s:1 2>/dev/null || true
    log "  attempt $A: got '$V'"
done

settings put global netstats_enabled 1 2>/dev/null; log "netstats_enabled set to 1: $?"
cmd netstats force-refresh 2>/dev/null && log "netstats force-refresh OK" || log "netstats force-refresh N/A"
cmd netstatscore force-refresh 2>/dev/null || true

log_sep "PHASE 5: Write netstats files to /data/misc/netstats"
log "Before write - contents of $NETSTATS_DIR:"
ls -la "$NETSTATS_DIR/" 2>/dev/null | while IFS= read -r l; do log "  $l"; done
write_netstats_xml
update_proxy_stats
log "After write - contents of $NETSTATS_DIR:"
ls -la "$NETSTATS_DIR/" 2>/dev/null | while IFS= read -r l; do log "  $l"; done

log "Stats file contents:"
cat "$STATSFILE" 2>/dev/null | while IFS= read -r l; do log "  $l"; done

log_sep "PHASE 6: Verify stats availability"
SRX=$(grep '^rx_bytes=' "$STATSFILE" 2>/dev/null | cut -d= -f2)
STX=$(grep '^tx_bytes=' "$STATSFILE" 2>/dev/null | cut -d= -f2)
log "Stats from file: rx=$SRX tx=$STX"

log "Stats from /proc/net/dev (non-lo):"
grep -v "lo:" /proc/net/dev 2>/dev/null | grep -v "Inter-\|face" | grep -v "^$" | awk '{print $1, $2, $10}' | while IFS= read -r l; do log "  $l"; done

log_sep "PHASE 7: SystemUI restart"
if [ "$REG_OK" -eq 1 ]; then
    log "Proxy registered, restarting SystemUI..."
    SYSUI_PID_BEFORE=$(pidof com.android.systemui 2>/dev/null || echo "?")
    log "SystemUI PID before: $SYSUI_PID_BEFORE"
    am force-stop com.android.systemui 2>/dev/null; log "am force-stop: $?"
    for SLEEP in 1 2 3 4 5 6 7 8 9 10 11 12; do
        sleep 1
        SYSUI_PID_NOW=$(pidof com.android.systemui 2>/dev/null || echo "")
        [ -n "$SYSUI_PID_NOW" ] && break
    done
    SYSUI_PID_AFTER=$(pidof com.android.systemui 2>/dev/null || echo "NOT_RUNNING")
    log "SystemUI PID after restart: $SYSUI_PID_AFTER"
    log "SystemUI restart wait: ${SLEEP}s"
else
    log "Proxy not registered, gentle refresh..."
    cmd netstats force-refresh 2>/dev/null || true
    log "force-refresh done"
fi

log_sep "SUMMARY"
log "  netproxy PID: $(pidof netproxy 2>/dev/null || echo dead)"
log "  Registered: $([ "$REG_OK" -eq 1 ] && echo YES || echo NO)"
log "  network_stats_enabled: $(settings get global network_stats_enabled 2>/dev/null)"
log "  netstats_dev.xml: $(ls -la $NETSTATS_DIR/netstats_dev.xml 2>/dev/null | awk '{print $5 " bytes"}')"
log "  netstats_uid.xml: $(ls -la $NETSTATS_DIR/netstats_uid.xml 2>/dev/null | awk '{print $5 " bytes"}')"
log "  stats file rx: $SRX"
log "  stats file tx: $STX"
log "  Total log lines: $(wc -l < "$LOG" 2>/dev/null || echo ?)"
log "  Log file size: $(ls -la "$LOG" 2>/dev/null | awk '{print $5}') bytes"

# Netproxy log analysis
log "Netproxy log analysis:"
NP_LOG="$LOG"
grep_errors=$(grep -ciE "ERROR|FATAL|FAILED|denied|WARNING" "$NP_LOG" 2>/dev/null || echo 0)
grep_reg=$(grep -c "REGISTERED\|registered '" "$NP_LOG" 2>/dev/null || echo 0)
grep_binder=$(grep -c "binder opened" "$NP_LOG" 2>/dev/null || echo 0)
grep_txns=$(grep -c ">>> TX" "$NP_LOG" 2>/dev/null || echo 0)
grep_replies=$(grep -c "<<< REPLY\|REPLY SENT" "$NP_LOG" 2>/dev/null || echo 0)
grep_sysui_txns=$(grep -c "sender_euid=10027\|uid=10027\|com.android.systemui" "$NP_LOG" 2>/dev/null || echo 0)
log "  Errors/warnings: $grep_errors"
log "  Registrations: $grep_reg"
log "  Binder opened: $grep_binder"
log "  Transactions received: $grep_txns"
log "  Replies sent: $grep_replies"
log "  SystemUI transactions: $grep_sysui_txns"
if [ "$grep_binder" -eq 0 ]; then
    warn "  BINDER NOT OPENED - netproxy cannot intercept stats calls!"
    warn "  Check 'Cannot open binder' or 'ioctl.*failed' in log"
fi
if [ "$grep_txns" -eq 0 ] && [ "$REG_OK" -eq 1 ]; then
    warn "  REGISTERED but NO TRANSACTIONS - SystemUI may not be querying stats"
    warn "  Check if SystemUI uses cached reference to real service"
    warn "  Last 30 log lines for any transaction signs:"
    grep -i "REPLY\|TX#\|BC_\|BR_\|transaction\|cookie\|uid_map\|stats_map\|query" "$LOG" 2>/dev/null | tail -30 | while IFS= read -r l; do warn "  $l"; done
fi
if [ "$grep_txns" -eq 0 ] && [ "$REG_OK" -eq 0 ]; then
    warn "  NOT REGISTERED - SystemUI is talking directly to real netstats service"
    warn "  Traffic indicator will show 0 without BPF maps or netproxy"
fi

log_sep "Main execution complete - entering watchdog"

background_updater &
WD=0
while true; do
    sleep 300; WD=$((WD+1))
    log_sep "WATCHDOG $WD"

    V=$(settings get global network_stats_enabled 2>/dev/null)
    [ "$V" != "1" ] && settings put global network_stats_enabled 1 2>/dev/null && log "[WD] Restored network_stats_enabled"
    R=$(settings get global restricted_networking_mode 2>/dev/null)
    [ "$R" = "1" ] && settings put global restricted_networking_mode 0 2>/dev/null && log "[WD] Cleared restricted_networking_mode"

    chmod 0644 /proc/net/dev 2>/dev/null
    chmod 0644 /proc/self/net/dev 2>/dev/null

    NP_PID=$(pidof netproxy 2>/dev/null || echo "")
    NP_REG_CHECK="?"
    NP_TXNS=$(grep -c "TX#" "$LOG" 2>/dev/null || echo 0)
    NP_TOTAL_LINES=$(wc -l < "$LOG" 2>/dev/null || echo 0)
    NP_LOG_SIZE=$(ls -la "$LOG" 2>/dev/null | awk '{print $5}')
    NP_SYSUI_TXNS=$(grep -c "sender_euid=10027\|uid=10027\|com.android.systemui" "$LOG" 2>/dev/null || echo 0)

    if [ -n "$PROXY_BIN" ]; then
        if [ -z "$NP_PID" ]; then
            warn "[WD-$WD] netproxy DIED (was PID $PROXY_PID), restarting..."
            warn "[WD-$WD]  Last netproxy log lines before death:"
            grep -E "ERROR|FATAL|FAILED|ioctl|binder|REGISTERED|TX#|SUMMARY|SENT" "$LOG" 2>/dev/null | tail -20 | while IFS= read -r l; do warn "  $l"; done
            warn "[WD-$WD]  dmesg OOM/signal check:"
            dmesg 2>/dev/null | grep -iE "oom|kill|netproxy" | tail -5 | while IFS= read -r l; do warn "  KERN: $l"; done
            PROXY_PID=$(start_nproxy "$PROXY_BIN")
            [ -z "$PROXY_PID" ] && PROXY_PID=$(start_nproxy "$PROXY_BIN" "u:r:system_app:s0")
            if [ -n "$PROXY_PID" ]; then
                log "[WD-$WD]  Restarted as PID $PROXY_PID"
                for R in 1 2 3 4 5; do
                    sleep 5
                    if check_registered; then
                        log "[WD-$WD]  Re-registered"
                        am force-stop com.android.systemui 2>/dev/null || true
                        break
                    fi
                    log "[WD-$WD]  Re-registration attempt $R/5..."
                done
            fi
        else
            if check_registered; then
                NP_REG_CHECK="yes"
            else
                NP_REG_CHECK="no"
                warn "[WD-$WD] Running PID $NP_PID but NOT registered, killing & restarting..."
                kill -9 "$NP_PID" 2>/dev/null; sleep 2; rm -f "$REGFILE"
                PROXY_PID=$(start_nproxy "$PROXY_BIN")
                [ -z "$PROXY_PID" ] && PROXY_PID=$(start_nproxy "$PROXY_BIN" "u:r:system_app:s0")
                if [ -n "$PROXY_PID" ]; then
                    log "[WD-$WD]  Restarted as PID $PROXY_PID"
                    for R in 1 2 3 4 5; do
                        sleep 5
                        if check_registered; then
                            log "[WD-$WD]  Re-registered"
                            am force-stop com.android.systemui 2>/dev/null || true
                            break
                        fi
                    done
                fi
            fi
        fi
    fi

    write_netstats_xml
    update_proxy_stats
    local sr=$(grep '^rx_bytes=' "$STATSFILE" 2>/dev/null | cut -d= -f2)
    local st=$(grep '^tx_bytes=' "$STATSFILE" 2>/dev/null | cut -d= -f2)
    log "[WD-$WD] stats: rx=$sr tx=$st proxy=$NP_PID reg=$NP_REG_CHECK sysui_txns=$NP_SYSUI_TXNS txns=$NP_TXNS log_lines=$NP_TOTAL_LINES log_size=$NP_LOG_SIZE"

    # On first WD, dump full context
    if [ "$WD" -eq 1 ]; then
        log "[WD-$WD] Full netproxy registration context:"
        grep -E "REGISTERED|addService|binder opened|opened /dev|Cannot open|passive mode|FATAL|ERROR.*binder" "$LOG" 2>/dev/null | tail -30 | while IFS= read -r l; do log "  $l"; done
        log "[WD-$WD] SELinux denials since boot:"
        dmesg 2>/dev/null | grep 'avc:.*denied' | grep -iE 'service_manager|servicemanager|binder|proc_net|netstats' | tail -20 | while IFS= read -r l; do warn "  $l"; done
    fi

    # Check if SystemUI is querying netproxy - if not after 2 WDs, do something
    if [ "$WD" -le 3 ] && [ "$NP_TXNS" -eq 0 ] && [ "$REG_OK" -eq 1 ]; then
        warn "[WD-$WD] No transactions seen yet - force-restarting SystemUI"
        am force-stop com.android.systemui 2>/dev/null || true
        log "[WD-$WD] SystemUI force-stop sent"
    fi
done
