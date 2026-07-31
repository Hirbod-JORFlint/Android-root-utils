#!/system/bin/sh
# ============================================================
#  Netstats Fix Lite v9.0 - Service Script
#  Universal traffic indicator fix without BPF restoration
# ============================================================
MODDIR=${0%/*}
LOG=/data/local/tmp/netproxy.log
REGFILE=/data/local/tmp/netproxy_registered
STATSFILE=/data/local/tmp/netproxy_stats
STATSFILE_DEV=/data/local/tmp/netproxy_dev
STATSFILE_UID=/data/local/tmp/netproxy_uid
NETSTATS_DIR=/data/misc/netstats
NO_TXN_FILE=/data/local/tmp/netproxy_no_txns
BOOTLOG=/data/local/tmp/netproxy_boot.log
BPF_NETD="/sys/fs/bpf/netd_shared"

# ============================================================
# Logging helpers
# ============================================================
log()   { echo "$(date '+%Y-%m-%d %H:%M:%S') [LITE] $*" >> "$LOG"; }
warn()  { echo "$(date '+%Y-%m-%d %H:%M:%S') [LITE-WARN] $*" >> "$LOG"; }
die()   { echo "$(date '+%Y-%m-%d %H:%M:%S') [LITE-DIE] $*" >> "$LOG"; exit 1; }
log_sep() { echo "--- $* ---" >> "$LOG"; }

chmod 0666 "$LOG" 2>/dev/null || true
echo "" >> "$LOG" 2>/dev/null || true

# ============================================================
# Environment dump
# ============================================================
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
    log "getprop init.svc.netstats: $(getprop init.svc.netstats 2>/dev/null || echo ?)"
    log "getprop ro.bpf.kver_override: $(getprop ro.bpf.kver_override 2>/dev/null || echo not_set)"
    log "which getprop: $(command -v getprop 2>/dev/null || echo NOT FOUND)"
    log "which magiskpolicy: $(command -v magiskpolicy 2>/dev/null || echo NOT FOUND)"
    log "which runcon: $(command -v runcon 2>/dev/null || echo NOT FOUND)"
    log "which pidof: $(command -v pidof 2>/dev/null || echo NOT FOUND)"
    log "which nsenter: $(command -v nsenter 2>/dev/null || echo NOT FOUND)"
    log "ls -la /dev/binder*: $(ls -la /dev/binder* 2>/dev/null || echo FAIL)"
    log "cat /proc/net/dev head:"
    head -5 /proc/net/dev 2>/dev/null | while IFS= read -r l; do log "  $l"; done
    log "--- END ENV DUMP ---"
}

# ============================================================
# Service call to check/add
# ============================================================
service_check() {
    local name="$1"
    service call servicemanager 2 s16 "$name" 2>/dev/null
    return $?
}

service_add() {
    local name="$1"
    local binder="$2"
    service call servicemanager 3 s16 "$name" "$binder" 2>/dev/null
    return $?
}

# ============================================================
# Find netproxy binary
# ============================================================
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

# ============================================================
# Start netproxy with specific SELinux context
# ============================================================
start_nproxy() {
    local bin="$1"
    local ctx="$2"
    local attempt_label="$3"

    chmod 755 "$bin"
    local sz=$(wc -c < "$bin" 2>/dev/null || echo "?")
    local ft=$(file "$bin" 2>/dev/null || echo unknown)
    log "Binary: $bin ($sz bytes, $ft)"
    log "Context: ${ctx:-default} (label=$attempt_label)"
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

    # Monitor for 5 seconds
    for WAIT in 1 2 3 4 5; do
        sleep 1
        if kill -0 "$pid" 2>/dev/null; then
            log "PID $pid still alive after ${WAIT}s"
        else
            wait "$pid" 2>/dev/null
            local ec=$?
            log "PID $pid DIED after ${WAIT}s (exit=$ec)"
            log "Last 20 netproxy log lines:"
            grep -E "ERROR|FATAL|FAILED|denied|Cannot open|ioctl|binder|FATAL" "$LOG" 2>/dev/null | tail -20 | while IFS= read -r l; do warn "  $l"; done
            break
        fi
    done

    if kill -0 "$pid" 2>/dev/null; then
        log "Running (PID $pid)"
        echo "$pid"
        return 0
    fi

    # Retry once without context
    log "First attempt failed (ctx=$ctx), retrying without context..."
    sleep 3
    nohup "$bin" >> "$LOG" 2>&1 &
    pid=$!
    log "Retry launched pid=$pid"
    for WAIT in 1 2 3 4 5; do
        sleep 1
        if kill -0 "$pid" 2>/dev/null; then
            log "  Retry PID $pid alive after ${WAIT}s"
        else
            log "  Retry PID $pid DIED after ${WAIT}s!"
            break
        fi
    done
    if kill -0 "$pid" 2>/dev/null; then
        log "Running after retry (PID $pid)"
        echo "$pid"
        return 0
    fi
    warn "Failed to start netproxy after all attempts"
    return 1
}

# ============================================================
# Check if netproxy registered
# ============================================================
check_registered() {
    grep -q "REGISTERED" "$LOG" 2>/dev/null && return 0
    [ -f "$REGFILE" ] && return 0
    return 1
}

# ============================================================
# Apply SELinux rules live
# ============================================================
apply_sepolicy() {
    local MP=$(command -v magiskpolicy 2>/dev/null || echo "")
    [ -z "$MP" ] && { log "magiskpolicy not found - rules may not apply - relying on sepolicy.rule"; return 0; }
    log "Applying live SELinux rules..."

    # Universal wide-open rules for service_manager
    "$MP" --live "allow * * service_manager { add find }" 2>/dev/null
    "$MP" --live "allow domain * service_manager { add find }" 2>/dev/null
    "$MP" --live "allow domain servicemanager:service_manager { find add }" 2>/dev/null
    "$MP" --live "allow domain default_android_service:service_manager { add find }" 2>/dev/null
    "$MP" --live "allow domain netstats_service:service_manager { add }" 2>/dev/null

    # proc_net access for all
    "$MP" --live "allow domain proc_net:file { read open getattr }" 2>/dev/null
    "$MP" --live "allow domain proc_net:dir { read search open }" 2>/dev/null
    "$MP" --live "allow domain proc_net_dev:file { read open getattr }" 2>/dev/null

    # Binder access
    "$MP" --live "allow domain binder_device:chr_file { read write open ioctl }" 2>/dev/null
    "$MP" --live "allow domain servicemanager:binder { call transfer }" 2>/dev/null

    # System specific
    "$MP" --live "allow system_server proc_net:file { read open getattr }" 2>/dev/null
    "$MP" --live "allow system_server proc_net:dir { read search open }" 2>/dev/null
    "$MP" --live "allow system_app proc_net:file { read open getattr }" 2>/dev/null
    "$MP" --live "allow platform_app proc_net:file { read open getattr }" 2>/dev/null
    "$MP" --live "allow untrusted_app proc_net:file { read open getattr }" 2>/dev/null
    "$MP" --live "allow shell proc_net:file { read open getattr }" 2>/dev/null

    # Magisk domain
    "$MP" --live "allow magisk proc_net:file { read open getattr }" 2>/dev/null
    "$MP" --live "allow magisk proc_net:dir { read search open }" 2>/dev/null
    "$MP" --live "allow magisk binder_device:chr_file { read write open ioctl }" 2>/dev/null
    "$MP" --live "allow magisk servicemanager:binder { call transfer }" 2>/dev/null
    "$MP" --live "allow magisk servicemanager:service_manager { find add }" 2>/dev/null
    "$MP" --live "allow magisk netstats_service:service_manager { add find }" 2>/dev/null

    # bpfloader permissions (in case bpfloader runs)
    "$MP" --live "allow bpfloader proc_net:file { read open getattr }" 2>/dev/null
    "$MP" --live "allow bpfloader proc_net:dir { search read }" 2>/dev/null
    "$MP" --live "allow bpfloader bpffs:dir { search read write add_name remove_name create rmdir setattr }" 2>/dev/null
    "$MP" --live "allow bpfloader bpffs:file { create read write open map getattr setattr unlink }" 2>/dev/null

    log "SELinux rules applied"
}

# ============================================================
# Read /proc/net/dev robustly (skip headers correctly)
# ============================================================
parse_proc_net_dev() {
    local file="${1:-/proc/net/dev}"
    local line=""
    local iface=""
    local vals=""
    local rb=0 rp=0 tb=0 tp=0
    local total_rx=0 total_tx=0 total_rxp=0 total_txp=0
    local iface_count=0
    local dev_entries=""
    local first_iface=""

    if [ ! -r "$file" ]; then
        log "/proc/net/dev: NOT READABLE"
        echo "iface_count=0"
        return 1
    fi

    # Read file line by line, skip first 2 header lines
    local line_num=0
    while IFS= read -r line; do
        line_num=$((line_num + 1))
        [ "$line_num" -le 2 ] && continue  # skip headers

        # Extract interface name (before colon)
        local colon_pos
        colon_pos=$(echo "$line" | tr -d '\n' | awk -F: '{print $1}')
        iface=$(echo "$colon_pos" | xargs)
        [ -z "$iface" ] && continue
        [ "$iface" = "lo" ] && continue
        [ "$iface" = "Inter-|" ] && continue

        # Extract values after colon
        vals=$(echo "$line" | cut -d: -f2-)
        rb=$(echo "$vals" | awk '{print $1}'); rp=$(echo "$vals" | awk '{print $2}')
        tb=$(echo "$vals" | awk '{print $9}'); tp=$(echo "$vals" | awk '{print $10}')
        rb=${rb:-0}; rp=${rp:-0}; tb=${tb:-0}; tp=${tp:-0}

        # Filter only valid network interfaces
        case "$iface" in
            eth*|wlan*|rmnet*|p2p*|tun*|veth*|bond*|bat*|gre*|gretap*|erspan*)
                ;;
            *)
                [ "$rb" -gt 0 ] || [ "$tb" -gt 0 ] || continue
                ;;
        esac

        total_rx=$((total_rx + rb))
        total_tx=$((total_tx + tb))
        total_rxp=$((total_rxp + rp))
        total_txp=$((total_txp + tp))
        iface_count=$((iface_count + 1))
        [ -z "$first_iface" ] && first_iface="$iface"

        # Produce output format: iface:rx:tx:rp:tp
        echo "IFACE:$iface:$rb:$rp:$tb:$tp"
    done < "$file" 2>/dev/null

    echo "TOTAL:$total_rx:$total_rxp:$total_tx:$total_txp"
    echo "IFCOUNT:$iface_count"
    echo "FIRST:$first_iface"
    return 0
}

# ============================================================
# Write netstats XML files to /data/misc/netstats/
# ============================================================
write_netstats_xml() {
    log_sep "WRITE NETSTATS XML"
    mkdir -p "$NETSTATS_DIR" 2>/dev/null
    log "NETSTATS_DIR=$NETSTATS_DIR"
    log "Current owner: $(ls -ld "$NETSTATS_DIR" 2>/dev/null)"

    # Parse /proc/net/dev
    local total_rx=0 total_tx=0 total_rxp=0 total_txp=0
    local iface_count=0
    local dev_entries=""
    local uid_entries=""
    local first_iface="wlan0"

    if [ -r /proc/net/dev ]; then
        log "/proc/net/dev exists and readable"
        while IFS= read -r p_line; do
            case "$p_line" in
                IFACE:*)
                    local iface=$(echo "$p_line" | cut -d: -f2)
                    local irb=$(echo "$p_line" | cut -d: -f3)
                    local irp=$(echo "$p_line" | cut -d: -f4)
                    local itb=$(echo "$p_line" | cut -d: -f5)
                    local itp=$(echo "$p_line" | cut -d: -f6)
                    irb=${irb:-0}; irp=${irp:-0}; itb=${itb:-0}; itp=${itp:-0}
                    total_rx=$((total_rx + irb))
                    total_tx=$((total_tx + itb))
                    total_rxp=$((total_rxp + irp))
                    total_txp=$((total_txp + itp))
                    iface_count=$((iface_count + 1))
                    [ -z "$first_iface" ] && first_iface="$iface"
                    dev_entries="${dev_entries}<st if=\"$iface\" dev=\"$iface\" uid=\"-1\" tag=\"0x0\" set=\"default\" rb=\"$irb\" rp=\"$irp\" tb=\"$itb\" tp=\"$itp\" />"$'\n'
                    log "  iface=$iface rx=$irb tx=$itb"
                    ;;
            esac
        done <<EOF
$(parse_proc_net_dev)
EOF
    else
        log "/proc/net/dev NOT READABLE!"
    fi

    log "Parsed $iface_count interfaces, rx=$total_rx tx=$total_tx"

    # Build dev XML
    if [ -z "$dev_entries" ]; then
        log "No interface data - using placeholder"
        dev_entries="<st if=\"$first_iface\" dev=\"$first_iface\" uid=\"-1\" tag=\"0x0\" set=\"default\" rb=\"0\" rp=\"0\" tb=\"0\" tp=\"0\" />"$'\n'
    fi

    cat > "$NETSTATS_DIR/netstats_dev.xml" <<EOF
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<stats devDetail="true">
${dev_entries}</stats>
EOF
    local RES_DEV=$?
    log "netstats_dev.xml write exit=$RES_DEV ($(wc -c < "$NETSTATS_DIR/netstats_dev.xml" 2>/dev/null) bytes)"

    # Build UID XML from netproxy_uid if available
    if [ -f "$STATSFILE_UID" ]; then
        log "Building UID XML from $STATSFILE_UID"
        while IFS= read -r uline; do
            case "$uline" in
                uid_*_rx=*)
                    local uid=$(echo "$uline" | sed 's/uid_\(.*\)_rx=.*/\1/')
                    local rx=$(echo "$uline" | cut -d= -f2)
                    local tx="0"
                    local tx_line=$(grep "^uid_${uid}_tx=" "$STATSFILE_UID" 2>/dev/null)
                    [ -n "$tx_line" ] && tx=$(echo "$tx_line" | cut -d= -f2)
                    uid_entries="${uid_entries}<st uid=\"$uid\" tag=\"0x0\" set=\"0\" rxBytes=\"$rx\" txBytes=\"$tx\" rxPackets=\"$((rx > 0 ? rx / 1500 : 0))\" txPackets=\"$((tx > 0 ? tx / 1500 : 0))\" />"$'\n'
                    ;;
            esac
        done < "$STATSFILE_UID"
    fi

    if [ -z "$uid_entries" ]; then
        log "No UID data - writing empty UID XML"
        uid_entries=""
    fi

    cat > "$NETSTATS_DIR/netstats_uid.xml" <<EOF
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<stats uidStats="true">
${uid_entries}</stats>
EOF
    local RES_UID=$?
    log "netstats_uid.xml write exit=$RES_UID ($(wc -c < "$NETSTATS_DIR/netstats_uid.xml" 2>/dev/null) bytes)"

    # Set correct permissions and ownership
    chmod 0644 "$NETSTATS_DIR/netstats_dev.xml" 2>/dev/null; log "  chmod dev: $?"
    chmod 0644 "$NETSTATS_DIR/netstats_uid.xml" 2>/dev/null; log "  chmod uid: $?"
    chown 1000:1000 "$NETSTATS_DIR/netstats_dev.xml" 2>/dev/null; log "  chown dev: $?"
    chown 1000:1000 "$NETSTATS_DIR/netstats_uid.xml" 2>/dev/null; log "  chown uid: $?"
    chown 1000:1000 "$NETSTATS_DIR" 2>/dev/null; log "  chown dir: $?"
    chmod 0770 "$NETSTATS_DIR" 2>/dev/null; log "  chmod dir: $?"

    log "Final dir listing:"
    ls -la "$NETSTATS_DIR/" 2>/dev/null | while IFS= read -r l; do log "  $l"; done
    log "Wrote XML: ifaces=$iface_count rx=$total_rx tx=$total_tx"
}

# ============================================================
# Update netproxy proxy stats files
# ============================================================
update_proxy_stats() {
    local trx=0 ttx=0 trxp=0 ttxp=0 ic=0
    > "$STATSFILE" 2>/dev/null

    while IFS= read -r p_line; do
        case "$p_line" in
            IFACE:*)
                local iface=$(echo "$p_line" | cut -d: -f2)
                local irb=$(echo "$p_line" | cut -d: -f3)
                local irp=$(echo "$p_line" | cut -d: -f4)
                local itb=$(echo "$p_line" | cut -d: -f5)
                local itp=$(echo "$p_line" | cut -d: -f6)
                irb=${irb:-0}; irp=${irp:-0}; itb=${itb:-0}; itp=${itp:-0}
                trx=$((trx + irb)); ttx=$((ttx + itb))
                trxp=$((trxp + irp)); ttxp=$((ttxp + itp))
                ic=$((ic + 1))
                echo "iface_${iface}_rx=$irb" >> "$STATSFILE"
                echo "iface_${iface}_tx=$itb" >> "$STATSFILE"
                echo "iface_${iface}_rxp=$irp" >> "$STATSFILE"
                echo "iface_${iface}_txp=$itp" >> "$STATSFILE"
                ;;
            TOTAL:*)
                local tr=$(echo "$p_line" | cut -d: -f2)
                local trp=$(echo "$p_line" | cut -d: -f3)
                local tt=$(echo "$p_line" | cut -d: -f4)
                local ttp=$(echo "$p_line" | cut -d: -f5)
                [ "$tr" -gt 0 ] && trx=$tr
                [ "$tt" -gt 0 ] && ttx=$tt
                [ "$trp" -gt 0 ] && trxp=$trp
                [ "$ttp" -gt 0 ] && ttxp=$ttp
                ;;
            IFCOUNT:*) ic=$(echo "$p_line" | cut -d: -f2) ;;
        esac
    done <<EOF
$(parse_proc_net_dev)
EOF

    echo "rx_bytes=$trx" >> "$STATSFILE"
    echo "tx_bytes=$ttx" >> "$STATSFILE"
    echo "rx_packets=$trxp" >> "$STATSFILE"
    echo "tx_packets=$ttxp" >> "$STATSFILE"
    echo "iface_count=$ic" >> "$STATSFILE"
    echo "timestamp=$(date +%s 2>/dev/null || echo 0)" >> "$STATSFILE"

    # Also write dev file
    > "$STATSFILE_DEV" 2>/dev/null
    while IFS= read -r p_line; do
        case "$p_line" in
            IFACE:*)
                local iface=$(echo "$p_line" | cut -d: -f2)
                local irb=$(echo "$p_line" | cut -d: -f3)
                local irp=$(echo "$p_line" | cut -d: -f4)
                local itb=$(echo "$p_line" | cut -d: -f5)
                local itp=$(echo "$p_line" | cut -d: -f6)
                echo "$iface $irb $irp $itb $itp" >> "$STATSFILE_DEV"
                ;;
        esac
    done <<EOF
$(parse_proc_net_dev)
EOF
    chmod 0644 "$STATSFILE" 2>/dev/null
    chmod 0644 "$STATSFILE_DEV" 2>/dev/null
}

# ============================================================
# Background interval updater
# ============================================================
background_updater() {
    local C=0
    while true; do
        sleep 60; C=$((C+1))
        write_netstats_xml
        update_proxy_stats
        local sr=$(grep '^rx_bytes=' "$STATSFILE" 2>/dev/null | cut -d= -f2)
        local st=$(grep '^tx_bytes=' "$STATSFILE" 2>/dev/null | cut -d= -f2)
        log "[BG-$C] stats updated: rx=$sr tx=$st"

        # Check if netproxy is alive
        local np_pid=$(pidof netproxy 2>/dev/null || echo "")
        if [ -z "$np_pid" ]; then
            warn "[BG-$C] netproxy NOT RUNNING!"
        fi
    done
}

# ============================================================
# Try to kill existing netstats service if running
# ============================================================
kill_real_netstats() {
    log "Attempting to find and stop real netstats service..."
    # Kill system_server's netstats thread by restarting netd
    # This is a last resort - may cause connectivity interruption
    local netd=$(getprop init.svc.netd 2>/dev/null)
    log "  netd status: $netd"

    # Try to use svc or setprop to kill netstats-related processes
    for svc in netstats netstats_service; do
        local s=$(getprop "init.svc.$svc" 2>/dev/null)
        if [ -n "$s" ]; then
            log "  Found service: $svc=$s"
            stop "$svc" 2>/dev/null
            log "  stop $svc: $?"
        fi
    done
}

# ============================================================
# Main execution
# ============================================================
log_sep "=============================================="
log_sep "  service-lite.sh v9.0 - STARTED"
log_sep "=============================================="
log "MODDIR: $MODDIR"
log "Kernel: $(uname -r) ($(uname -r | cut -d. -f1).$(uname -r | cut -d. -f2))"
log "SDK: $(getprop ro.build.version.sdk 2>/dev/null)"
log "Android: $(getprop ro.build.version.release 2>/dev/null)"
log "Arch: $(getprop ro.product.cpu.abi 2>/dev/null)"
log "SELinux: $(getenforce 2>/dev/null)"
log "Build: $(getprop ro.build.display.id 2>/dev/null)"
log "ROM: $(getprop ro.build.description 2>/dev/null)"

dump_env

# ============================================================
# Wait for boot
# ============================================================
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

# ============================================================
# Initial diagnostics
# ============================================================
log_sep "DIAGNOSTICS"
log "SELinux: $(getenforce 2>/dev/null)"
log "/proc/net/dev readable: $([ -r /proc/net/dev ] && echo yes || echo no)"

log "Raw /proc/net/dev (full):"
cat /proc/net/dev 2>/dev/null | while IFS= read -r l; do log "  $l"; done

log "Parsed interfaces:"
while IFS= read -r p_line; do
    case "$p_line" in
        IFACE:*) log "  $p_line" ;;
        TOTAL:*) log "  $p_line" ;;
        IFCOUNT:*) log "  $p_line" ;;
    esac
done <<EOF
$(parse_proc_net_dev)
EOF

log "BPF maps: $(ls /sys/fs/bpf/netd_shared/map_netd_* 2>/dev/null | wc -l)"
BPF_MAP_LIST=$(ls /sys/fs/bpf/netd_shared/map_netd_* 2>/dev/null)
if [ -n "$BPF_MAP_LIST" ]; then
    echo "$BPF_MAP_LIST" | while IFS= read -r m; do log "  BPF map: $m"; done
else
    log "  No BPF maps found (expected for lite module)"
fi
log "Tethering APEX: $([ -d /apex/com.android.tethering ] && echo mounted || echo absent)"

log "Checking /proc/net/dev permissions:"
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

log "SELinux denials (binder/service_manager/netstats):"
dmesg 2>/dev/null | grep 'avc:.*denied' | grep -iE 'binder|service_manager|servicemanager|netstats|proc_net' | tail -30 | while IFS= read -r l; do warn "  DENIAL: $l"; done

log "ServiceManager messages:"
dmesg 2>/dev/null | grep -iE 'service_manager|binder:' | tail -15 | while IFS= read -r l; do log "  SM: $l"; done

log "Settings:"
log "  network_stats_enabled=$(settings get global network_stats_enabled 2>/dev/null || echo ?)"
log "  restricted_networking_mode=$(settings get global restricted_networking_mode 2>/dev/null || echo ?)"
log "  netstats_enabled=$(settings get global netstats_enabled 2>/dev/null || echo ?)"
log "  bt_hfp=$(settings get global bluetooth_hfp 2>/dev/null || echo ?)"

# ============================================================
# Apply sepolicy early
# ============================================================
apply_sepolicy

# ============================================================
# Phase 1: Kill existing netproxy instances
# ============================================================
log_sep "PHASE 1: Cleanup"
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
rm -f "$NO_TXN_FILE" 2>/dev/null; log "Removed NO_TXN_FILE: $?"

# ============================================================
# Phase 2: Find and start netproxy
# ============================================================
log_sep "PHASE 2: Start netproxy"
PROXY_BIN=$(find_netproxy)
log "find_netproxy result: '${PROXY_BIN:-EMPTY}'"

PROXY_PID=""
if [ -z "$PROXY_BIN" ]; then
    warn "FATAL: netproxy binary not found!"
    log "Contents of $MODDIR/system/bin/:"
    ls -la "$MODDIR/system/bin/" 2>/dev/null | while IFS= read -r l; do log "  $l"; done
else
    log "Found netproxy at: $PROXY_BIN"
    log "File size: $(wc -c < "$PROXY_BIN" 2>/dev/null || echo ?) bytes"
    log "File type: $(file "$PROXY_BIN" 2>/dev/null || echo unknown)"

    # Try multiple SELinux contexts
    CONTEXTS=""
    CONTEXTS="$CONTEXTS default"    # no context
    CONTEXTS="$CONTEXTS u:r:system_app:s0"
    CONTEXTS="$CONTEXTS u:r:untrusted_app:s0"
    CONTEXTS="$CONTEXTS u:r:magisk:s0"
    CONTEXTS="$CONTEXTS u:r:su:s0"
    CONTEXTS="$CONTEXTS u:r:netd:s0"

    for ctx_entry in $CONTEXTS; do
        [ -n "$PROXY_PID" ] && break

        if [ "$ctx_entry" = "default" ]; then
            log "Trying with default context..."
            PROXY_PID=$(start_nproxy "$PROXY_BIN" "" "default")
        else
            log "Trying with context: $ctx_entry..."
            PROXY_PID=$(start_nproxy "$PROXY_BIN" "$ctx_entry" "$ctx_entry")
        fi

        if [ -n "$PROXY_PID" ]; then
            log "Started with context $ctx_entry, PID=$PROXY_PID"
            break
        fi
    done

    if [ -z "$PROXY_PID" ]; then
        warn "netproxy failed to start in ALL contexts"
        log "Last 50 log lines for diagnosis:"
        tail -50 "$LOG" 2>/dev/null | while IFS= read -r l; do warn "  $l"; done
    fi
fi

# ============================================================
# Phase 3: Wait for registration
# ============================================================
log_sep "PHASE 3: Registration wait"
REG_OK=0
START_TS=$(date +%s)
LAST_LOG_LINE_COUNT=$(wc -l < "$LOG" 2>/dev/null || echo 0)
LAST_TX_COUNT=0
LAST_STATS_FILE_LINES=0

for RTRY in $(seq 1 60); do
    waited=$(($(date +%s) - START_TS))
    log "=== Registration attempt $RTRY/60 (${waited}s) ==="

    # Check if proxy process is alive
    PROXY_ALIVE=$(pidof netproxy 2>/dev/null || echo "")
    if [ -n "$PROXY_PID" ] && [ -z "$PROXY_ALIVE" ]; then
        warn "Proxy process GONE at ${waited}s (was PID $PROXY_PID)!"
        log "  Last log lines before death:"
        tail -30 "$LOG" 2>/dev/null | grep -E "ERROR|FATAL|FAILED|denied|ioctl|binder|Cannot|WARNING" | while IFS= read -r l; do warn "  $l"; done
        log "  dmesg for OOM/signal:"
        dmesg 2>/dev/null | grep -iE "oom|kill|netproxy|out of memory" | tail -10 | while IFS= read -r l; do warn "  KERN: $l"; done

        # Restart
        log "  Attempting restart..."
        for ctx_entry in default "u:r:system_app:s0" "u:r:magisk:s0"; do
            if [ "$ctx_entry" = "default" ]; then
                PROXY_PID=$(start_nproxy "$PROXY_BIN" "" "default")
            else
                PROXY_PID=$(start_nproxy "$PROXY_BIN" "$ctx_entry" "$ctx_entry")
            fi
            [ -n "$PROXY_PID" ] && break
        done
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

    # Show latest netproxy log lines
    NEW_LINES=$(($(wc -l < "$LOG" 2>/dev/null || echo 0) - LAST_LOG_LINE_COUNT))
    if [ "$NEW_LINES" -gt 0 ]; then
        log "  netproxy log since last check ($NEW_LINES new lines, total=$(wc -l < "$LOG")):"
        tail -$((NEW_LINES > 30 ? 30 : NEW_LINES)) "$LOG" 2>/dev/null | grep -E "ERROR|WARNING|REGISTER|FAIL|opened|ioctl|addService|BR_|TX#|REPLY|passive|SELINUX|REG" | while IFS= read -r l; do log "  NP: $l"; done
    fi
    LAST_LOG_LINE_COUNT=$(wc -l < "$LOG" 2>/dev/null || echo 0)

    # Transaction counter
    TX_COUNT=$(grep -c "TX#" "$LOG" 2>/dev/null || echo 0)
    if [ "$TX_COUNT" -ne "$LAST_TX_COUNT" ]; then
        log "  TRANSACTIONS increased: $LAST_TX_COUNT -> $TX_COUNT"
        LAST_TX_COUNT=$TX_COUNT
    fi

    # Stats file check
    if [ -f "$STATSFILE" ]; then
        CURR_STATS=$(wc -c < "$STATSFILE" 2>/dev/null || echo 0)
        if [ "$CURR_STATS" -ne "$LAST_STATS_FILE_LINES" ]; then
            log "  Stats file updated: $CURR_STATS bytes"
            head -5 "$STATSFILE" 2>/dev/null | while IFS= read -r l; do log "  STAT: $l"; done
            LAST_STATS_FILE_LINES=$CURR_STATS
        fi
    fi

    # Alive check
    PROXY_CURRENT=$(pidof netproxy 2>/dev/null || echo "")
    log "  Proxy PID: ${PROXY_CURRENT:-dead}, TX: $TX_COUNT"

    sleep 3

    # Periodic SELinux checks
    if [ "$((RTRY % 5))" -eq 0 ]; then
        apply_sepolicy
        log "  SELinux denials check:"
        dmesg 2>/dev/null | grep 'avc:.*denied' | grep -iE 'service_manager|servicemanager|binder|proc_net' | tail -10 | while IFS= read -r l; do warn "  DENIAL: $l"; done
        log "  ServiceManager check:"
        dmesg 2>/dev/null | grep -iE 'service_manager.*netstats|netstats.*service' | tail -5 | while IFS= read -r l; do log "  SM: $l"; done
    fi

    # Periodic environment checks
    if [ "$((RTRY % 10))" -eq 0 ]; then
        log "  /proc/net/dev check:"
        head -5 /proc/net/dev 2>/dev/null | while IFS= read -r l; do log "    $l"; done
    fi
done

if [ "$REG_OK" -eq 0 ]; then
    warn "REGISTRATION FAILED after 60 attempts ($(($(date +%s) - START_TS))s)"
    warn "Checking last 50 log entries for clues:"
    grep -i "WARNING\|ERROR\|FAILED\|denied\|BR_\|ioctl.*failed\|Cannot open\|mmap" "$LOG" 2>/dev/null | tail -30 | while IFS= read -r l; do warn "  $l"; done
    warn "Full dmesg for service_manager denials:"
    dmesg 2>/dev/null | grep -iE 'service_manager|servicemanager' | grep -i 'denied' | tail -20 | while IFS= read -r l; do warn "  $l"; done
fi

# ============================================================
# Phase 4: Settings
# ============================================================
log_sep "PHASE 4: Settings"
RNM_BEFORE=$(settings get global restricted_networking_mode 2>/dev/null)
log "restricted_networking_mode before: '$RNM_BEFORE'"
settings put global restricted_networking_mode 0 2>/dev/null
settings put global netstats_enabled 1 2>/dev/null
log "Cleared restricted_networking_mode and set netstats_enabled"

for A in $(seq 1 15); do
    settings put global network_stats_enabled 1 2>/dev/null
    sleep 1
    V=$(settings get global network_stats_enabled 2>/dev/null)
    if [ "$V" = "1" ]; then
        log "network_stats_enabled=1 (attempt $A)"
        break
    fi
    # Direct content provider insert as fallback
    content insert --uri content://settings/global --bind name:s:network_stats_enabled --bind value:s:1 2>/dev/null || true
    log "  attempt $A: got '$V'"
done

cmd netstats force-refresh 2>/dev/null && log "netstats force-refresh OK" || log "netstats force-refresh N/A"
cmd netstatscore force-refresh 2>/dev/null || true

settings put global netstats_enabled 1 2>/dev/null; log "netstats_enabled set: $?"

# ============================================================
# Phase 5: Write netstats XML files
# ============================================================
log_sep "PHASE 5: Write netstats files"
log "Before write - contents of $NETSTATS_DIR:"
ls -la "$NETSTATS_DIR/" 2>/dev/null | while IFS= read -r l; do log "  $l"; done

write_netstats_xml
update_proxy_stats

log "After write - contents of $NETSTATS_DIR:"
ls -la "$NETSTATS_DIR/" 2>/dev/null | while IFS= read -r l; do log "  $l"; done

log "Stats file contents:"
if [ -f "$STATSFILE" ]; then
    cat "$STATSFILE" 2>/dev/null | while IFS= read -r l; do log "  $l"; done
fi

# ============================================================
# Phase 6: Verify stats
# ============================================================
log_sep "PHASE 6: Verify"
SRX=$(grep '^rx_bytes=' "$STATSFILE" 2>/dev/null | cut -d= -f2)
STX=$(grep '^tx_bytes=' "$STATSFILE" 2>/dev/null | cut -d= -f2)
log "Stats from file: rx=$SRX tx=$STX"
log "Stats from /proc/net/dev (non-lo):"
grep -v "lo:" /proc/net/dev 2>/dev/null | tail -n +3 | while IFS= read -r l; do
    iface=$(echo "$l" | awk -F: '{print $1}' | xargs)
    rx=$(echo "$l" | awk '{print $2}')
    tx=$(echo "$l" | awk '{print $10}')
    [ -n "$iface" ] && [ "$iface" != "Inter-|" ] && [ "$iface" != "face" ] && log "  $iface: rx=$rx tx=$tx"
done

log "/proc/uid_stat/ verification:"
if [ -d /proc/uid_stat ]; then
    log "  Directory exists: $(ls -la /proc/uid_stat/ 2>/dev/null | wc -l) entries"
    for uid in 1000 1001 10027; do
        local rcv=$(cat /proc/uid_stat/$uid/tcp_rcv 2>/dev/null || echo "N/A")
        local snd=$(cat /proc/uid_stat/$uid/tcp_snd 2>/dev/null || echo "N/A")
        log "  UID $uid: tcp_rcv=$rcv tcp_snd=$snd"
    done
else
    warn "  /proc/uid_stat/ DOES NOT EXIST!"
fi

log "BPF map permissions:"
if [ -d "$BPF_NETD" ]; then
    ls -la "$BPF_NETD/" 2>/dev/null | head -8 | while IFS= read -r l; do log "  $l"; done
fi

# ============================================================
# Phase 7: Kill and restart SystemUI to pick up netproxy
# ============================================================
log_sep "PHASE 7: SystemUI refresh"
if [ "$REG_OK" -eq 1 ]; then
    log "Proxy registered, performing aggressive SystemUI restart..."

    # Method 1: am force-stop
    SYSUI_BEFORE=$(pidof com.android.systemui 2>/dev/null || echo "?")
    log "SystemUI PID before: $SYSUI_BEFORE"
    am force-stop com.android.systemui 2>/dev/null; log "am force-stop: $?"

    sleep 5

    # Method 2: kill directly if still running
    SYSUI_AFTER=$(pidof com.android.systemui 2>/dev/null || echo "")
    if [ -n "$SYSUI_AFTER" ]; then
        log "SystemUI still running ($SYSUI_AFTER) after force-stop, using kill"
        kill -9 "$SYSUI_AFTER" 2>/dev/null; log "kill -9 SystemUI: $?"
        sleep 3
    fi

    # Wait for SystemUI to restart
    for SLEEP_W in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
        sleep 1
        SYSUI_NOW=$(pidof com.android.systemui 2>/dev/null || echo "")
        [ -n "$SYSUI_NOW" ] && { log "SystemUI restarted as PID $SYSUI_NOW after ${SLEEP_W}s"; break; }
    done

    SYSUI_FINAL=$(pidof com.android.systemui 2>/dev/null || echo "NOT_RUNNING")
    log "SystemUI PID after restart: $SYSUI_FINAL"
    sleep 5

    # After SystemUI restart, check if transactions start flowing
    log "Waiting for SystemUI to connect to netproxy..."
    sleep 10
    TX_AFTER=$(grep -c "TX#" "$LOG" 2>/dev/null || echo 0)
    TX_BEFORE=$LAST_TX_COUNT
    log "Transactions before: $TX_BEFORE, after SystemUI restart: $TX_AFTER"
    if [ "$TX_AFTER" -le "$TX_BEFORE" ]; then
        warn "No new transactions detected after SystemUI restart!"
        warn "SystemUI may be using a different API path (TrafficStats, not NetworkStatsManager)"
        log "Forcing another SystemUI restart..."
        am force-stop com.android.systemui 2>/dev/null || true
        sleep 10
        TX_NOW=$(grep -c "TX#" "$LOG" 2>/dev/null || echo 0)
        log "Transactions after 2nd restart: $TX_NOW"
    fi
else
    log "Proxy not registered - gentle refresh instead"
    cmd netstats force-refresh 2>/dev/null || true
    am force-stop com.android.systemui 2>/dev/null || true
    log "Gentle refresh done"
fi

# ============================================================
# Phase 8: Final summary
# ============================================================
log_sep "SUMMARY"
log "  netproxy PID: $(pidof netproxy 2>/dev/null || echo dead)"
log "  Registered: $([ "$REG_OK" -eq 1 ] && echo YES || echo NO)"
log "  network_stats_enabled: $(settings get global network_stats_enabled 2>/dev/null)"
log "  restricted_networking_mode: $(settings get global restricted_networking_mode 2>/dev/null)"
log "  netstats_enabled: $(settings get global netstats_enabled 2>/dev/null)"
log "  netstats_dev.xml: $(ls -la $NETSTATS_DIR/netstats_dev.xml 2>/dev/null | awk '{print $5 " bytes"}')"
log "  netstats_uid.xml: $(ls -la $NETSTATS_DIR/netstats_uid.xml 2>/dev/null | awk '{print $5 " bytes"}')"
log "  stats file rx: $SRX"
log "  stats file tx: $STX"
log "  Total log lines: $(wc -l < "$LOG" 2>/dev/null || echo ?)"
log "  Log file size: $(ls -la "$LOG" 2>/dev/null | awk '{print $5}') bytes"

# Netproxy log analysis
log "--- NETPROXY LOG ANALYSIS ---"
NP_LOG="$LOG"
grep_errors=$(grep -ciE "ERROR|FATAL|FAILED|denied|WARNING" "$NP_LOG" 2>/dev/null || echo 0)
grep_reg=$(grep -c "REGISTERED\|registered '" "$NP_LOG" 2>/dev/null || echo 0)
grep_binder=$(grep -c "binder opened" "$NP_LOG" 2>/dev/null || echo 0)
grep_txns=$(grep -c ">>> TX" "$NP_LOG" 2>/dev/null || echo 0)
grep_replies=$(grep -c "<<< REPLY" "$NP_LOG" 2>/dev/null || echo 0)
grep_sysui_txns=$(grep -c "sender_euid=10027\|uid=10027\|com.android.systemui" "$NP_LOG" 2>/dev/null || echo 0)
grep_total_txns=$(grep -c "TX#" "$NP_LOG" 2>/dev/null || echo 0)
grep_sessions=$(grep -c "openSession" "$NP_LOG" 2>/dev/null || echo 0)
grep_get_iface=$(grep -c "getIfaceStats\|getTotalStats\|getUidStats" "$NP_LOG" 2>/dev/null || echo 0)
log "  Errors/warnings: $grep_errors"
log "  Registrations: $grep_reg"
log "  Binder opened: $grep_binder"
log "  Transactions received: $grep_txns"
log "  Total TX# markers: $grep_total_txns"
log "  Replies sent: $grep_replies"
log "  SystemUI transactions: $grep_sysui_txns"
log "  Session opens: $grep_sessions"
log "  Stats queries: $grep_get_iface"

if [ "$grep_binder" -eq 0 ] && [ "$REG_OK" -eq 1 ]; then
    log "  WARNING: registered but binder opened count is 0 (may use cached fd)"
fi
if [ "$grep_txns" -eq 0 ] && [ "$REG_OK" -eq 1 ]; then
    warn "  REGISTERED but NO TRANSACTIONS - SystemUI may use TrafficStats directly!"
    warn "  Traffic indicator likely reads from BPF maps or xt_qtaguid, not binder."
    warn "  Suggest: enable full module with BPF restoration, or patch framework."
fi
if [ "$grep_get_iface" -eq 0 ] && [ "$REG_OK" -eq 1 ]; then
    warn "  REGISTERED but no iface/total/uid stats queries - wrong API being called"
fi

log_sep "Main execution complete - entering watchdog"

# ============================================================
# Start background updater
# ============================================================
background_updater &

# ============================================================
# Watchdog
# ============================================================
WD=0
while true; do
    sleep 300; WD=$((WD+1))
    log_sep "WATCHDOG $WD"

    # Restore settings if changed
    V=$(settings get global network_stats_enabled 2>/dev/null)
    [ "$V" != "1" ] && settings put global network_stats_enabled 1 2>/dev/null && log "[WD] Restored network_stats_enabled"
    R=$(settings get global restricted_networking_mode 2>/dev/null)
    [ "$R" = "1" ] && settings put global restricted_networking_mode 0 2>/dev/null && log "[WD] Cleared restricted_networking_mode"

    chmod 0644 /proc/net/dev 2>/dev/null
    chmod 0644 /proc/self/net/dev 2>/dev/null

    # Netproxy management
    NP_PID=$(pidof netproxy 2>/dev/null || echo "")
    NP_TXNS=$(grep -c "TX#" "$LOG" 2>/dev/null || echo 0)
    NP_TOTAL_LINES=$(wc -l < "$LOG" 2>/dev/null || echo 0)
    NP_LOG_SIZE=$(ls -la "$LOG" 2>/dev/null | awk '{print $5}')
    NP_REG_CHECK="?"
    if check_registered; then NP_REG_CHECK="yes"; else NP_REG_CHECK="no"; fi

    if [ -n "$PROXY_BIN" ]; then
        if [ -z "$NP_PID" ]; then
            warn "[WD-$WD] netproxy DIED, restarting..."
            warn "[WD-$WD]  Last netproxy log:"
            grep -E "ERROR|FATAL|FAILED|ioctl|binder|REGISTERED|TX#|SUMMARY|SENT" "$LOG" 2>/dev/null | tail -20 | while IFS= read -r l; do warn "  $l"; done
            warn "[WD-$WD]  dmesg OOM check:"
            dmesg 2>/dev/null | grep -iE "oom|kill|netproxy" | tail -5 | while IFS= read -r l; do warn "  KERN: $l"; done

            for ctx_entry in default "u:r:system_app:s0" "u:r:magisk:s0"; do
                if [ "$ctx_entry" = "default" ]; then
                    PROXY_PID=$(start_nproxy "$PROXY_BIN" "" "default")
                else
                    PROXY_PID=$(start_nproxy "$PROXY_BIN" "$ctx_entry" "$ctx_entry")
                fi
                [ -n "$PROXY_PID" ] && break
            done

            if [ -n "$PROXY_PID" ]; then
                log "[WD-$WD] Restarted as PID $PROXY_PID"
                for R in 1 2 3 4 5; do
                    sleep 5
                    if check_registered; then
                        log "[WD-$WD] Re-registered"
                        am force-stop com.android.systemui 2>/dev/null || true
                        break
                    fi
                    log "[WD-$WD] Re-registration attempt $R/5"
                done
            fi
        else
            if [ "$NP_REG_CHECK" = "no" ]; then
                warn "[WD-$WD] Running PID $NP_PID but NOT registered, restarting..."
                kill -9 "$NP_PID" 2>/dev/null; sleep 2; rm -f "$REGFILE"
                for ctx_entry in default "u:r:system_app:s0" "u:r:magisk:s0"; do
                    if [ "$ctx_entry" = "default" ]; then
                        PROXY_PID=$(start_nproxy "$PROXY_BIN" "" "default")
                    else
                        PROXY_PID=$(start_nproxy "$PROXY_BIN" "$ctx_entry" "$ctx_entry")
                    fi
                    [ -n "$PROXY_PID" ] && break
                done
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

    # Write stats periodically
    write_netstats_xml
    update_proxy_stats

    local sr=$(grep '^rx_bytes=' "$STATSFILE" 2>/dev/null | cut -d= -f2)
    local st=$(grep '^tx_bytes=' "$STATSFILE" 2>/dev/null | cut -d= -f2)
    log "[WD-$WD] stats: rx=$sr tx=$st proxy=$NP_PID reg=$NP_REG_CHECK txns=$NP_TXNS log_lines=$NP_TOTAL_LINES log_size=$NP_LOG_SIZE"

    # Check for stale no-transaction state
    if [ -f "$NO_TXN_FILE" ] && [ "$NP_TXNS" -gt 0 ]; then
        log "[WD-$WD] Transactions started flowing, removing no_txn flag"
        rm -f "$NO_TXN_FILE" 2>/dev/null
    fi

    # Check /proc/uid_stat/ and repopulate if needed
    if [ -d /proc/uid_stat ] 2>/dev/null; then
        local uid_count=$(ls /proc/uid_stat/ 2>/dev/null | wc -l)
        log "[WD-$WD] /proc/uid_stat active: $uid_count entries"
        # Verify it has content - if empty, repopulate
        if [ "$uid_count" -lt 5 ]; then
            warn "[WD-$WD] /proc/uid_stat has only $uid_count entries, repopulating..."
            # Force netproxy to repopulate
            settings put global network_stats_enabled 1 2>/dev/null
        fi
        # Sample a value to verify it's readable
        local sample=$(cat /proc/uid_stat/1000/tcp_rcv 2>/dev/null || echo "?")
        log "[WD-$WD] /proc/uid_stat/1000/tcp_rcv = $sample"
    else
        warn "[WD-$WD] /proc/uid_stat: not available - recreating..."
        mkdir -p /proc/uid_stat 2>/dev/null
        mount -t tmpfs tmpfs /proc/uid_stat 2>/dev/null || \
        mount --bind /data/local/tmp/uid_stat /proc/uid_stat 2>/dev/null || true
        chmod 0755 /proc/uid_stat 2>/dev/null
    fi

    # Check xt_qtaguid
    if [ -f /proc/net/xt_qtaguid/stats ]; then
        log "[WD-$WD] xt_qtaguid stats: available"
        chmod 0644 /proc/net/xt_qtaguid/stats 2>/dev/null
    fi

    # Ensure BPF maps stay hidden (for lite module)
    if [ -d "$BPF_NETD" ] 2>/dev/null; then
        for m in "$BPF_NETD"/*; do
            if [ -f "$m" ] && [ "$(stat -c %a "$m" 2>/dev/null)" != "0" ]; then
                chmod 0000 "$m" 2>/dev/null
                log "[WD-$WD] Re-hid BPF map: $m"
            fi
        done
    fi

    # On first few WDs, dump full registration context
    if [ "$WD" -le 3 ]; then
        log "[WD-$WD] Full netproxy context:"
        grep -E "REGISTERED|addService|binder opened|opened /dev|Cannot open|FATAL|ERROR.*binder|getInterface|getUidStats|getTotalStats|getIfaceStats|openSession" "$LOG" 2>/dev/null | tail -30 | while IFS= read -r l; do log "  $l"; done
    fi

    # If no transactions ever and registered, force SystemUI restart every 2 WDs
    if [ "$NP_TXNS" -eq 0 ] && [ "$REG_OK" -eq 1 ] && [ "$((WD % 2))" -eq 0 ]; then
        warn "[WD-$WD] Zero transactions despite registration - force-restarting SystemUI"
        am force-stop com.android.systemui 2>/dev/null || true
        sleep 15
        TX_NOW=$(grep -c "TX#" "$LOG" 2>/dev/null || echo 0)
        log "[WD-$WD] After restart: TX count = $TX_NOW"
        if [ "$TX_NOW" -gt 0 ]; then
            log "[WD-$WD] Transactions started after forced SystemUI restart!"
        fi
    fi

    # Check if the netstats XML needs updating (every 30 min)
    if [ "$((WD % 6))" -eq 0 ]; then
        log "[WD-$WD] Periodic deep refresh..."
        cmd netstats force-refresh 2>/dev/null || true
        settings put global network_stats_enabled 1 2>/dev/null
    fi
done
