#!/system/bin/sh
MODDIR=${0%/*}
LOG=/data/local/tmp/netproxy.log

_log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [service] $*" >> "$LOG"; }

BPF_NETD="/sys/fs/bpf/netd_shared"
BPF_MAP_OWNER="$BPF_NETD/map_netd_uid_owner_map"
BPF_MAP_STATS="$BPF_NETD/map_netd_app_uid_stats_map"
BPF_MAP_COOKIE="$BPF_NETD/map_netd_cookie_tag_map"
BPF_MAP_CONFIG="$BPF_NETD/map_netd_configuration_map"
BPF_MAP_STATS_A="$BPF_NETD/map_netd_stats_map_A"
BPF_MAP_STATS_B="$BPF_NETD/map_netd_stats_map_B"
STATSFILE_DIR="/data/local/tmp/netstats"
REGFILE="/data/local/tmp/netproxy_registered"

count_bpf_maps() {
    local c=0
    for m in "$BPF_MAP_OWNER" "$BPF_MAP_STATS" "$BPF_MAP_COOKIE" \
             "$BPF_MAP_CONFIG" "$BPF_MAP_STATS_A" "$BPF_MAP_STATS_B"; do
        [ -e "$m" ] && c=$((c+1))
    done
    echo "$c"
}

bpf_stats_ready() {
    [ -e "$BPF_MAP_STATS" ] && [ -e "$BPF_MAP_CONFIG" ]
}

stub_bpfloader_detected() {
    [ -d "$BPF_NETD/mainline_done" ] && [ "$(count_bpf_maps)" -eq 0 ]
}

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
    local base="$1"
    local dir; dir=$(dirname "$base")
    local arch; arch=$(getprop ro.product.cpu.abi 2>/dev/null)
    case "$arch" in
        arm64-v8a|arm64)
            [ -f "$base" ]              && { echo "$base";              return 0; }
            [ -f "$dir/netproxy_arm" ]  && { echo "$dir/netproxy_arm"; return 0; }
            ;;
        armeabi-v7a|armeabi)
            [ -f "$dir/netproxy_arm" ]  && { echo "$dir/netproxy_arm"; return 0; }
            [ -f "$base" ]              && { echo "$base";              return 0; }
            ;;
        *)
            [ -f "$base" ]              && { echo "$base";              return 0; }
            [ -f "$dir/netproxy_arm" ]  && { echo "$dir/netproxy_arm"; return 0; }
            ;;
    esac
    return 1
}

NPROXY_PID=""
NPROXY_BIN=""

apply_sepolicy() {
    local MP; MP=$(command -v magiskpolicy 2>/dev/null || echo "")
    [ -z "$MP" ] && { _log "magiskpolicy not found; relying on sepolicy.rule"; return 0; }

    _log "Applying live SELinux rules..."

    # proc_net access
    "$MP" --live "allow domain proc_net:file { read open getattr }"               2>/dev/null
    "$MP" --live "allow domain proc_net:dir { read search open }"                 2>/dev/null

    # Binder access
    "$MP" --live "allow domain binder_device:chr_file { read write open ioctl }"  2>/dev/null
    "$MP" --live "allow domain servicemanager:binder { call transfer }"            2>/dev/null
    "$MP" --live "allow domain servicemanager:service_manager { find add }"       2>/dev/null
    "$MP" --live "allow domain netstats_service:service_manager { add }"          2>/dev/null
    "$MP" --live "allow domain default_android_service:service_manager { add find }" 2>/dev/null
    "$MP" --live "allow * * service_manager { add find }"                         2>/dev/null

    # System server / apps
    "$MP" --live "allow system_server proc_net:file { read open getattr }"        2>/dev/null
    "$MP" --live "allow system_server proc_net:dir { read search open }"          2>/dev/null
    "$MP" --live "allow system_app proc_net:file { read open getattr }"           2>/dev/null
    "$MP" --live "allow platform_app proc_net:file { read open getattr }"         2>/dev/null
    "$MP" --live "allow system_background proc_net:file { read open getattr }"    2>/dev/null

    # bpfloader execution
    "$MP" --live "allow init bpfloader_exec:file { getattr open read execute execute_no_trans }"  2>/dev/null
    "$MP" --live "allow init bpfloader_platform_exec:file { getattr open read execute execute_no_trans }" 2>/dev/null
    "$MP" --live "allow init apex_file:file { getattr open read execute execute_no_trans }" 2>/dev/null
    "$MP" --live "allow init apex_exec:file { getattr open read execute execute_no_trans }" 2>/dev/null
    "$MP" --live "allow init system_file:file { getattr open read execute execute_no_trans }" 2>/dev/null
    "$MP" --live "allow init debug_ramdisk_file:file { getattr open read execute execute_no_trans }" 2>/dev/null

    # bpfloader domain permissions
    "$MP" --live "allow bpfloader self:capability { sys_ptrace sys_admin net_admin }" 2>/dev/null
    "$MP" --live "allow bpfloader self:capability2 { sys_ptrace sys_admin }" 2>/dev/null
    "$MP" --live "allow bpfloader kernel:system module_request" 2>/dev/null
    "$MP" --live "allow bpfloader bpffs:dir { search read write add_name remove_name create rmdir setattr }" 2>/dev/null
    "$MP" --live "allow bpfloader bpffs:file { create read write open map getattr setattr unlink }" 2>/dev/null
    "$MP" --live "allow bpfloader bpffs:lnk_file { read open getattr }" 2>/dev/null
    "$MP" --live "allow bpfloader proc_net:file { read open getattr }" 2>/dev/null
    "$MP" --live "allow bpfloader proc_net:dir { search read }" 2>/dev/null
    "$MP" --live "allow bpfloader proc_kallsyms:file { read open getattr }" 2>/dev/null
    "$MP" --live "allow bpfloader kmsg_device:chr_file { write }" 2>/dev/null
    "$MP" --live "allow bpfloader sysfs_btf:file { read open getattr }" 2>/dev/null
    "$MP" --live "allow bpfloader sysfs_btf:dir { search read }" 2>/dev/null
    "$MP" --live "allow bpfloader sysfs:file { read open getattr }" 2>/dev/null
    "$MP" --live "allow bpfloader sysfs:dir { search read }" 2>/dev/null
    "$MP" --live "allow bpfloader tmpfs:file { read write open }" 2>/dev/null
    "$MP" --live "allow bpfloader tmpfs:dir { search read write add_name create }" 2>/dev/null
    "$MP" --live "allow bpfloader unlabeled:dir { search read }" 2>/dev/null
    "$MP" --live "allow bpfloader unlabeled:file { read open getattr }" 2>/dev/null
    "$MP" --live "allow bpfloader selinuxfs:file { read open getattr }" 2>/dev/null

    # netd BPF access
    "$MP" --live "allow netd self:capability { sys_admin net_admin }" 2>/dev/null
    "$MP" --live "allow netd kernel:system module_request" 2>/dev/null
    "$MP" --live "allow netd bpffs:dir { search read write add_name remove_name create rmdir }" 2>/dev/null
    "$MP" --live "allow netd bpffs:file { read write open map getattr setattr }" 2>/dev/null
    "$MP" --live "allow netd bpffs:lnk_file { read open getattr }" 2>/dev/null
    "$MP" --live "allow netd proc_net:file { read open getattr }" 2>/dev/null
    "$MP" --live "allow netd proc_net:dir { search read }" 2>/dev/null

    # system_server BPF
    "$MP" --live "allow system_server self:capability { sys_admin }" 2>/dev/null
    "$MP" --live "allow system_server bpffs:dir { read search open }" 2>/dev/null
    "$MP" --live "allow system_server bpffs:file { read open getattr map }" 2>/dev/null
    "$MP" --live "allow system_server bpffs:lnk_file { read open getattr }" 2>/dev/null
    "$MP" --live "allow system_server sysfs_bpf:file { read open getattr }" 2>/dev/null
    "$MP" --live "allow system_server sysfs_bpf:dir { search read open }" 2>/dev/null

    # crash_dump (diagnostics)
    "$MP" --live "allow crash_dump bpfloader:process { ptrace }" 2>/dev/null
    "$MP" --live "allow dumpstate bpfloader:process { ptrace }" 2>/dev/null

    # shell/adb
    "$MP" --live "allow shell proc_net:file { read open getattr }" 2>/dev/null
    "$MP" --live "allow shell proc_net:dir { read search open }" 2>/dev/null

    # Magisk module context
    "$MP" --live "allow magisk proc_net:file { read open getattr }" 2>/dev/null
    "$MP" --live "allow magisk proc_net:dir { read search open }" 2>/dev/null
    "$MP" --live "allow magisk binder_device:chr_file { read write open ioctl }" 2>/dev/null
    "$MP" --live "allow magisk servicemanager:binder { call transfer }" 2>/dev/null
    "$MP" --live "allow magisk servicemanager:service_manager { find add }" 2>/dev/null
    "$MP" --live "allow magisk netstats_service:service_manager { add find }" 2>/dev/null
    "$MP" --live "allow magisk sysfs_bpf:file { read open getattr }" 2>/dev/null
    "$MP" --live "allow magisk sysfs_bpf:dir { search read open }" 2>/dev/null

    # Allow all domains to read /proc/net/dev
    "$MP" --live "allow domain proc_net:file { read open getattr }" 2>/dev/null
    "$MP" --live "allow domain proc_net:dir { read search open }" 2>/dev/null

    _log "Live SELinux rules applied"
}

start_nproxy() {
    local bin="$1"
    [ -f "$bin" ] || { _log "start_nproxy: $bin not found"; return 1; }
    chmod 755 "$bin"

    local BAKLOG="$LOG.bak"
    [ -f "$LOG" ] && cp "$LOG" "$BAKLOG" 2>/dev/null

    _log "Starting netproxy: $bin"
    nohup "$bin" >> "$LOG" 2>&1 &
    local pid=$!
    _log "Proxy launched (pid=$pid)"
    sleep 2

    if kill -0 "$pid" 2>/dev/null; then
        _log "Proxy running (PID $pid)"
        echo "$pid"
        return 0
    fi

    if grep -q "FATAL: failed to open binder" "$LOG" 2>/dev/null; then
        _log "Binder not available yet, will retry"
        return 2
    fi

    _log "Proxy exited immediately, retrying..."
    sleep 2
    nohup "$bin" >> "$LOG" 2>&1 &
    pid=$!
    sleep 3
    if kill -0 "$pid" 2>/dev/null; then
        _log "Proxy running after retry (PID $pid)"
        echo "$pid"
        return 0
    fi
    _log "Proxy failed both attempts"
    return 1
}

check_nproxy_registered() {
    grep -q "registered '" "$LOG" 2>/dev/null && return 0
    [ -f "$REGFILE" ] && return 0
    return 1
}

# ============================================================
# Write netstats files fallback
# This creates minimal netstats XML that NetworkStatsService
# can read for interface-level stats when BPF/netproxy fail
# ============================================================
write_netstats_fallback() {
    _log "--- Writing netstats fallback files ---"
    mkdir -p "$STATSFILE_DIR" 2>/dev/null

    NOW=$(date +%s 2>/dev/null || echo 1700000000)
    START=$((NOW - 86400))

    # Read current interface stats from /proc/net/dev
    local total_rx=0 total_tx=0 total_rxp=0 total_txp=0
    local first_iface=""
    local entry_lines=""

    if [ -f /proc/net/dev ]; then
        while IFS= read -r line; do
            iface=$(echo "$line" | cut -d: -f1 | tr -d ' ')
            [ -z "$iface" ] && continue
            [ "$iface" = "lo" ] && continue
            case "$iface" in
                eth*|wlan*|rmnet*|p2p*|tun*|veth*)
                    ;;
                *)
                    continue
                    ;;
            esac

            vals=$(echo "$line" | cut -d: -f2)
            rxbytes=$(echo "$vals" | awk '{print $1}')
            rxpackets=$(echo "$vals" | awk '{print $2}')
            txbytes=$(echo "$vals" | awk '{print $9}')
            txpackets=$(echo "$vals" | awk '{print $10}')

            total_rx=$((total_rx + ${rxbytes:-0}))
            total_tx=$((total_tx + ${txbytes:-0}))
            total_rxp=$((total_rxp + ${rxpackets:-0}))
            total_txp=$((total_txp + ${txpackets:-0}))

            [ -z "$first_iface" ] && first_iface="$iface"
            entry_lines="${entry_lines}<st if=\"$iface\" dev=\"$iface\" uid=\"-1\" tag=\"0x0\" set=\"default\" rb=\"${rxbytes:-0}\" rp=\"${rxpackets:-0}\" tb=\"${txbytes:-0}\" tp=\"${txpackets:-0}\" />"$'\n'
        done < /proc/net/dev
    fi

    [ -z "$first_iface" ] && first_iface="wlan0"

    # Write dev stats XML
    cat > "$STATSFILE_DIR/netstats_dev.xml" <<DEVXML
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<stats devDetail="true">
${entry_lines}</stats>
DEVXML

    # Write UID stats XML (empty - no per-UID data available)
    cat > "$STATSFILE_DIR/netstats_uid.xml" <<UIDXML
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<stats uidStats="true">
</stats>
UIDXML

    chmod 0644 "$STATSFILE_DIR/netstats_dev.xml" 2>/dev/null
    chmod 0644 "$STATSFILE_DIR/netstats_uid.xml" 2>/dev/null
    _log "Wrote netstats fallback (rx=$total_rx tx=$total_tx)"
}

_log "============================================"
_log "  service.sh v14 - started"
_log "============================================"

WAIT=0
while [ "$(getprop sys.boot_completed 2>/dev/null)" != "1" ] && [ "$WAIT" -lt 180 ]; do
    sleep 1; WAIT=$((WAIT+1))
done
_log "Boot completed after ${WAIT}s"
sleep 8

KVER=$(uname -r 2>/dev/null)
KMAJOR=$(echo "$KVER" | cut -d. -f1)
KMINOR=$(echo "$KVER" | cut -d. -f2)
KPATCH=$(echo "$KVER" | cut -d. -f3 | grep -oE '^[0-9]+')
KMAJOR=${KMAJOR:-0}; KMINOR=${KMINOR:-0}; KPATCH=${KPATCH:-0}
CORRECT_KVER="${KMAJOR}.${KMINOR}.${KPATCH}"

_log "--- Diagnostics ---"
_log "Kernel: $KVER"
_log "Android SDK: $(getprop ro.build.version.sdk 2>/dev/null)"
_log "SELinux: $(getenforce 2>/dev/null)"
_log "ro.bpf.kver_override: $(getprop ro.bpf.kver_override 2>/dev/null)"
_log "network_stats_enabled: $(settings get global network_stats_enabled 2>/dev/null)"
_log "restricted_networking_mode: $(settings get global restricted_networking_mode 2>/dev/null)"
_log "bpfloader: $(getprop init.svc.bpfloader 2>/dev/null)"
_log "netd: $(getprop init.svc.netd 2>/dev/null)"

_log "Binder devices:"
for dev in /dev/binder /dev/vndbinder /dev/hwbinder; do
    if [ -e "$dev" ]; then
        _log "  $dev: EXISTS ($(ls -la "$dev" 2>/dev/null))"
    else
        _log "  $dev: NOT FOUND"
    fi
done

MAP_COUNT=$(count_bpf_maps)
_log "BPF maps present: $MAP_COUNT"
for m in uid_owner_map app_uid_stats_map cookie_tag_map configuration_map stats_map_A stats_map_B; do
    p="$BPF_NETD/map_netd_$m"
    [ -e "$p" ] && _log "  $m: present" || _log "  $m: absent"
done

STUB_BPF=0
if stub_bpfloader_detected; then
    _log "*** bpfloader STUB detected (mainline_done present, 0 maps) ***"
    STUB_BPF=1
fi

_log "--- SELinux denials (relevant) ---"
dmesg 2>/dev/null | grep 'avc:.*denied' | grep -iE 'bpf|netd|bpfloader|proc_net|service_manager|netstats' | tail -15 | \
    while IFS= read -r line; do _log "  DENIED: $line"; done

_log "ServiceManager messages:"
dmesg 2>/dev/null | grep -iE 'service_manager|binder:' | tail -10 | while IFS= read -r l; do _log "  SM: $l"; done

BPF_RESTORE=0
if   [ "$KMAJOR" -gt 4 ]; then BPF_RESTORE=1
elif [ "$KMAJOR" -eq 4 ] && [ "$KMINOR" -ge 9 ]; then BPF_RESTORE=1
fi
_log "BPF restore eligible: $BPF_RESTORE (kernel $KMAJOR.$KMINOR)"

# Phase 1: Start netproxy early
_log "--- Phase 1: Early Netproxy ---"
RAW_BIN=$(find_netproxy)
if [ -n "$RAW_BIN" ]; then
    NPROXY_BIN=$(select_arch_binary "$RAW_BIN")
    [ -z "$NPROXY_BIN" ] && NPROXY_BIN="$RAW_BIN"
    _log "Binary: $NPROXY_BIN"
    NPROXY_PID=$(start_nproxy "$NPROXY_BIN")
else
    _log "netproxy binary not found!"
fi

# Phase 2: BPF Repair (skip if stub bpfloader known or kernel too old)
BPF_STATS_OK=0
if bpf_stats_ready; then
    BPF_STATS_OK=1
    _log "--- Phase 2: BPF maps already present ---"
elif [ "$BPF_RESTORE" -eq 0 ] || [ "$STUB_BPF" -eq 1 ]; then
    _log "--- Phase 2: BPF not capable or stub bpfloader, skipping restoration ---"
    _log "  Relying on netproxy fallback"
else
    _log "--- Phase 2: BPF Repair ---"

    # Ensure correct kver_override
    CURRENT_OVERRIDE=$(getprop ro.bpf.kver_override 2>/dev/null)
    if [ "$CURRENT_OVERRIDE" != "$CORRECT_KVER" ]; then
        _log "Fixing kver_override: $CURRENT_OVERRIDE -> $CORRECT_KVER"
        resetprop ro.bpf.kver_override "$CORRECT_KVER" 2>/dev/null \
        || resetprop_phh ro.bpf.kver_override "$CORRECT_KVER" 2>/dev/null \
        || setprop ro.bpf.kver_override "$CORRECT_KVER" 2>/dev/null
    fi

    apply_sepolicy

    # Remove all mainline_done markers
    for MARKER in "$BPF_NETD/mainline_done" /dev/pmt/atomic/tebpf_mainline_done; do
        [ -d "$MARKER" ] && rm -rf "$MARKER" 2>/dev/null \
            && _log "Deleted marker: $MARKER"
    done

    echo 1 > /proc/sys/net/core/bpf_jit_enable 2>/dev/null

    # Try up to 3 repair attempts
    ATTEMPT=0
    while [ "$ATTEMPT" -lt 3 ] && ! bpf_stats_ready; do
        ATTEMPT=$((ATTEMPT+1))
        _log "Restarting bpfloader (attempt $ATTEMPT)..."
        stop bpfloader 2>/dev/null
        sleep 1
        start bpfloader 2>/dev/null

        BW=0
        while [ "$(getprop init.svc.bpfloader 2>/dev/null)" = "running" ] && [ "$BW" -lt 60 ]; do
            sleep 1; BW=$((BW+1))
        done
        _log "  bpfloader done after ${BW}s"
        sleep 3

        NEW=$(count_bpf_maps)
        _log "  BPF maps after attempt $ATTEMPT: $NEW"

        # Check if stub bpfloader regenerated mainline_done
        if stub_bpfloader_detected; then
            _log "  *** Stub bpfloader detected! mainline_done reappeared with 0 maps."
            _log "  *** Stopping BPF restoration attempts."
            STUB_BPF=1
            break
        fi
    done

    if bpf_stats_ready; then
        BPF_STATS_OK=1
        _log "BPF Repair SUCCESS!"
    else
        _log "BPF Repair FAILED after $ATTEMPT attempts"
        if stub_bpfloader_detected; then
            _log "  Cause: bpfloader is a STUB (creates only mainline_done)"
            _log "  Will rely on netproxy fallback"
        fi
        ls -la "$BPF_NETD/" 2>/dev/null | while IFS= read -r l; do _log "  $l"; done
    fi
fi

# Phase 3: xt_qtaguid fallback
QTAGUID_OK=0
if [ "$BPF_STATS_OK" -eq 0 ] && [ "$KMAJOR" -lt 5 ]; then
    _log "--- Phase 3: xt_qtaguid fallback ---"
    for MP in \
        /vendor/lib/modules/xt_qtaguid.ko \
        /system/lib/modules/xt_qtaguid.ko \
        /vendor_dlkm/lib/modules/xt_qtaguid.ko \
        /system_dlkm/lib/modules/xt_qtaguid.ko; do
        [ -f "$MP" ] && insmod "$MP" 2>/dev/null \
            && _log "Loaded xt_qtaguid from $MP" && QTAGUID_OK=1 && break
    done
    [ -f /proc/net/xt_qtaguid/stats ] && QTAGUID_OK=1 && _log "xt_qtaguid: available"
    [ "$QTAGUID_OK" -eq 0 ] && _log "xt_qtaguid: not available"
fi

# Phase 4: Netd Restart (if BPF maps just created)
if [ "$BPF_STATS_OK" -eq 1 ]; then
    _log "--- Phase 4: Restart netd ---"
    setprop ctl.restart netd 2>/dev/null
    NW=0
    while [ "$(getprop init.svc.netd 2>/dev/null)" != "running" ] && [ "$NW" -lt 30 ]; do
        sleep 1; NW=$((NW+1))
    done
    sleep 5
    _log "netd restarted (waited ${NW}s)"
fi

# Phase 5: Settings
_log "--- Phase 5: Settings ---"
settings put global restricted_networking_mode 0 2>/dev/null

ATTEMPT=0
while [ "$ATTEMPT" -lt 12 ]; do
    ATTEMPT=$((ATTEMPT+1))
    settings put global network_stats_enabled 1 2>/dev/null
    sleep 2
    NSE=$(settings get global network_stats_enabled 2>/dev/null)
    if [ "$NSE" = "1" ]; then
        _log "network_stats_enabled=1 (attempt $ATTEMPT)"
        break
    fi
    _log "  attempt $ATTEMPT: got '$NSE'"
    content insert --uri content://settings/global \
        --bind name:s:network_stats_enabled --bind value:s:1 2>/dev/null || true
done

settings put global netstats_enabled 1 2>/dev/null
cmd netstats force-refresh 2>/dev/null && _log "netstats force-refresh: OK" \
    || _log "netstats force-refresh: not available"
cmd netstatscore force-refresh 2>/dev/null || true

# Phase 6: Ensure netproxy is running and registered
_log "--- Phase 6: Netproxy Verification ---"

apply_sepolicy

chmod 0644 /proc/net/dev 2>/dev/null
chmod 0644 /proc/self/net/dev 2>/dev/null

if [ -z "$NPROXY_BIN" ]; then
    RAW_BIN=$(find_netproxy)
    if [ -n "$RAW_BIN" ]; then
        NPROXY_BIN=$(select_arch_binary "$RAW_BIN")
        [ -z "$NPROXY_BIN" ] && NPROXY_BIN="$RAW_BIN"
    fi
fi

NPROXY_REGISTERED=0
if [ -n "$NPROXY_BIN" ]; then
    if [ -n "$NPROXY_PID" ] && ! kill -0 "$NPROXY_PID" 2>/dev/null; then
        NPROXY_PID=""
    fi

    if [ -z "$NPROXY_PID" ]; then
        _log "Starting netproxy..."
        NPROXY_PID=$(start_nproxy "$NPROXY_BIN")
    fi

    if [ -n "$NPROXY_PID" ]; then
        # Exponential backoff wait for registration with log monitoring
        WAIT_REG=0
        BACKOFF=2
        LAST_LOG_LINES=$(wc -l < "$LOG" 2>/dev/null || echo 0)
        while [ "$WAIT_REG" -lt 30 ]; do
            sleep $BACKOFF; WAIT_REG=$((WAIT_REG + BACKOFF))

            # Check if proxy died
            if ! kill -0 "$NPROXY_PID" 2>/dev/null; then
                _log "Proxy died at ${WAIT_REG}s, restarting..."
                tail -20 "$LOG" 2>/dev/null | while IFS= read -r l; do _log "  LAST: $l"; done
                NPROXY_PID=$(start_nproxy "$NPROXY_BIN")
                if [ -z "$NPROXY_PID" ]; then
                    _log "  Could not restart proxy"
                    break
                fi
            fi

            if check_nproxy_registered; then
                NPROXY_REGISTERED=1
                _log "*** REGISTERED (after ${WAIT_REG}s) ***"
                _log "Registration context:"
                grep -i "registered\|REGISTERED\|addService\|binder opened" "$LOG" 2>/dev/null | tail -10 | while IFS= read -r l; do _log "  $l"; done
                break
            fi

            # Show netproxy log snippets periodically
            NEW_LINES=$(($(wc -l < "$LOG" 2>/dev/null || echo 0) - LAST_LOG_LINES))
            if [ "$NEW_LINES" -gt 0 ]; then
                tail -$((NEW_LINES > 15 ? 15 : NEW_LINES)) "$LOG" 2>/dev/null | grep -E "ERROR|WARNING|REGISTER|FAIL|opened|ioctl|addService|BR_" | while IFS= read -r l; do _log "  NP: $l"; done
            fi
            LAST_LOG_LINES=$(wc -l < "$LOG" 2>/dev/null || echo 0)

            # Increase backoff up to max 5s
            BACKOFF=$((BACKOFF + 1))
            [ "$BACKOFF" -gt 5 ] && BACKOFF=5

            # Re-apply sepolicy and check denials periodically
            [ "$((WAIT_REG % 10))" -eq 0 ] && apply_sepolicy 2>/dev/null
            [ "$((WAIT_REG % 12))" -eq 0 ] && {
                dmesg 2>/dev/null | grep 'avc:.*denied' | grep -iE 'service_manager|servicemanager|binder|proc_net' | tail -5 | while IFS= read -r l; do _log "  DENIAL: $l"; done
                dmesg 2>/dev/null | grep -iE 'service_manager.*netstats|netstats.*service' | tail -5 | while IFS= read -r l; do _log "  SM: $l"; done
            }

            _log "Registration: ${WAIT_REG}s, proxy=$(pidof netproxy 2>/dev/null || echo dead), log_lines=$(wc -l < "$LOG" 2>/dev/null || echo ?)"
        done
        if [ "$NPROXY_REGISTERED" -eq 0 ]; then
            _log "Netproxy NOT registered after ${WAIT_REG}s"
            _log "  Check logs: grep 'WARNING\|FATAL\|failed' $LOG"
            grep -i "WARNING\|ERROR\|FAILED\|denied\|BR_" "$LOG" 2>/dev/null | tail -20 | while IFS= read -r l; do _log "  $l"; done
        fi
    fi
else
    _log "FATAL: netproxy binary not found"
fi

# Phase 6b: Write netstats fallback if nothing else works
if [ "$BPF_STATS_OK" -eq 0 ] && [ "$NPROXY_REGISTERED" -eq 0 ] && [ "$QTAGUID_OK" -eq 0 ]; then
    _log "--- Phase 6b: Netstats file fallback ---"
    write_netstats_fallback
fi

# Phase 7: Restart SystemUI (to pick up our registered service)
# DON'T restart SystemUI if no stats mechanism is active - it could cause boot loops
if [ "$NPROXY_REGISTERED" -eq 1 ] || [ "$BPF_STATS_OK" -eq 1 ]; then
    _log "--- Phase 7: Restart SystemUI ---"
    sleep 3
    am force-stop com.android.systemui 2>/dev/null
    _log "SystemUI killed"
    sleep 8
    SYSUI_PID=$(pidof com.android.systemui 2>/dev/null)
    _log "SystemUI running as pid=$SYSUI_PID"
else
    _log "--- Phase 7: Skipping SystemUI restart (no stats mechanism active) ---"
fi

sleep 5

# Phase 7b: Netproxy log analysis
_log "--- Phase 7b: Netproxy Log Analysis ---"
NP_ERRORS=$(grep -ciE "ERROR|FATAL|FAILED|denied|WARNING" "$LOG" 2>/dev/null || echo 0)
NP_REG=$(grep -c "REGISTERED\|registered '" "$LOG" 2>/dev/null || echo 0)
NP_BINDER=$(grep -c "binder opened" "$LOG" 2>/dev/null || echo 0)
NP_TXNS=$(grep -c ">>> TX" "$LOG" 2>/dev/null || echo 0)
NP_REPLIES=$(grep -c "<<< REPLY\|REPLY SENT" "$LOG" 2>/dev/null || echo 0)
_log "  Errors/warnings: $NP_ERRORS"
_log "  Registrations: $NP_REG"
_log "  Binder opened: $NP_BINDER"
_log "  Transactions: $NP_TXNS"
_log "  Replies sent: $NP_REPLIES"
if [ "$NP_BINDER" -eq 0 ] && [ "$NPROXY_REGISTERED" -eq 1 ]; then
    _log "  WARNING: registered but binder NOT opened - check BINDER_VERSION ioctl"
fi
if [ "$NP_TXNS" -eq 0 ] && [ "$NPROXY_REGISTERED" -eq 1 ]; then
    _log "  WARNING: registered but NO transactions - SystemUI may use cached reference"
    _log "  Try force-stop SystemUI or reboot"
fi

# Phase 8: Summary
_log "============================================"
_log "SUMMARY:"
if [ "$BPF_STATS_OK" -eq 1 ]; then
    _log "  BPF maps restored: per-UID stats active"
fi
if [ "$NPROXY_REGISTERED" -eq 1 ]; then
    _log "  Netproxy registered: interface-level stats active"
fi
if [ "$QTAGUID_OK" -eq 1 ]; then
    _log "  xt_qtaguid available: legacy stats active"
fi
if [ "$BPF_STATS_OK" -eq 0 ] && [ "$NPROXY_REGISTERED" -eq 0 ] && [ "$QTAGUID_OK" -eq 0 ]; then
    _log "  Netstats file fallback: interface-level stats (no per-UID)"
fi
_log "============================================"
_log "=== service.sh complete ==="

# Phase 9: Watchdog (safe - no aggressive actions that could cause boot loops)
WD=0
while true; do
    sleep 300
    WD=$((WD+1))

    _log "--- Watchdog $WD ---"

    NSE=$(settings get global network_stats_enabled 2>/dev/null)
    [ "$NSE" != "1" ] && settings put global network_stats_enabled 1 2>/dev/null \
        && _log "[WD-$WD] Restored network_stats_enabled"

    RNM=$(settings get global restricted_networking_mode 2>/dev/null)
    [ "$RNM" = "1" ] && settings put global restricted_networking_mode 0 2>/dev/null \
        && _log "[WD-$WD] Cleared restricted_networking_mode"

    chmod 0644 /proc/net/dev 2>/dev/null
    chmod 0644 /proc/self/net/dev 2>/dev/null

    # Only restart netd if it died (not preemptively)
    NETD=$(getprop init.svc.netd 2>/dev/null)
    [ "$NETD" != "running" ] && [ "$NETD" != "" ] && setprop ctl.restart netd 2>/dev/null \
        && _log "[WD-$WD] Restarted netd (was: $NETD)"

    # BPF map restoration (gentle - don't restart bpfloader aggressively)
    if [ "$BPF_STATS_OK" -eq 1 ] && ! bpf_stats_ready; then
        _log "[WD-$WD] BPF maps lost, attempting gentle restore..."
        [ -d "$BPF_NETD/mainline_done" ] && rm -rf "$BPF_NETD/mainline_done" 2>/dev/null
        setprop ctl.restart netd 2>/dev/null
        sleep 10
        if bpf_stats_ready; then
            _log "[WD-$WD] BPF maps restored via netd restart"
        else
            _log "[WD-$WD] BPF maps still missing (netd restart insufficient)"
        fi
    fi

    # Netproxy heartbeat with log context on death
    NP_PID=$(pidof netproxy 2>/dev/null || echo "")
    if [ -n "$NPROXY_BIN" ]; then
        if [ -z "$NP_PID" ]; then
            _log "[WD-$WD] Proxy DIED, restarting..."
            _log "[WD-$WD]  Last netproxy log lines before death:"
            grep -E "ERROR|FATAL|FAILED|ioctl|binder|REGISTERED|TX#|SUMMARY|SENT" "$LOG" 2>/dev/null | tail -15 | while IFS= read -r l; do _log "  $l"; done
            NPROXY_PID=$(start_nproxy "$NPROXY_BIN")
            if [ -n "$NPROXY_PID" ]; then
                _log "[WD-$WD]  Restarted as PID $NPROXY_PID"
                for R in 1 2 3; do
                    sleep 5
                    if check_nproxy_registered; then
                        _log "[WD-$WD]  Re-registered"
                        am force-stop com.android.systemui 2>/dev/null || true
                        break
                    fi
                done
            fi
        else
            NPROXY_REG_CHECK=$(check_nproxy_registered && echo yes || echo no)
            if [ "$NPROXY_REG_CHECK" = "no" ]; then
                _log "[WD-$WD] Running PID $NP_PID but NOT registered, killing & restarting..."
                kill -9 "$NP_PID" 2>/dev/null
                sleep 2
                rm -f "$REGFILE" 2>/dev/null
                NPROXY_PID=$(start_nproxy "$NPROXY_BIN")
            fi
        fi
    fi

    # Health metrics
    NP_TXNS=$(grep -c "TX#" "$LOG" 2>/dev/null || echo 0)
    NP_TOTAL_LINES=$(wc -l < "$LOG" 2>/dev/null || echo 0)
    NP_REG_CHECK=$(check_nproxy_registered && echo yes || echo no)
    _log "[WD-$WD] maps=$(count_bpf_maps) proxy=$NP_PID reg=$NP_REG_CHECK txns=$NP_TXNS log_lines=$NP_TOTAL_LINES netd=$(getprop init.svc.netd 2>/dev/null)"

    if [ "$WD" -eq 1 ]; then
        _log "[WD-$WD] Full registration context:"
        grep -E "REGISTERED|addService|binder opened|opened /dev|Cannot open|passive mode|FATAL|ERROR.*binder" "$LOG" 2>/dev/null | tail -20 | while IFS= read -r l; do _log "  $l"; done
    fi
done
