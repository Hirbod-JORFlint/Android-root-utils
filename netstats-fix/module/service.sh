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
    local m
    m="$BPF_NETD/mainline_done"
    [ -d "$m" ] && [ "$(count_bpf_maps)" -eq 0 ]
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
    "$MP" --live "allow domain proc_net:file { read open getattr }"               2>/dev/null
    "$MP" --live "allow domain proc_net:dir { read search open }"                 2>/dev/null
    "$MP" --live "allow system_server proc_net:file { read open getattr }"        2>/dev/null
    "$MP" --live "allow system_server proc_net:dir { read search open }"          2>/dev/null
    "$MP" --live "allow system_app proc_net:file { read open getattr }"           2>/dev/null
    "$MP" --live "allow platform_app proc_net:file { read open getattr }"         2>/dev/null
    "$MP" --live "allow domain binder_device:chr_file { read write open ioctl }"  2>/dev/null
    "$MP" --live "allow domain servicemanager:service_manager { find add }"        2>/dev/null
    "$MP" --live "allow domain service_manager_service:service_manager { find add }" 2>/dev/null
    "$MP" --live "allow init bpfloader_exec:file { getattr open read execute execute_no_trans }" 2>/dev/null
    "$MP" --live "allow init bpfloader_platform_exec:file { getattr open read execute execute_no_trans }" 2>/dev/null
    "$MP" --live "allow bpfloader bpffs:dir { search read write add_name remove_name create }"   2>/dev/null
    "$MP" --live "allow bpfloader bpffs:file { create read write open map getattr setattr }"     2>/dev/null
    "$MP" --live "allow bpfloader proc_net:file { read open getattr }"             2>/dev/null
    "$MP" --live "allow netd bpffs:dir { search read write add_name remove_name }" 2>/dev/null
    "$MP" --live "allow netd bpffs:file { read write open map getattr }"           2>/dev/null
    "$MP" --live "allow crash_dump bpfloader:process { ptrace }"                  2>/dev/null
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
        _log "Binder not available yet, will retry in Phase 2/6"
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

_log "=== service.sh started ==="

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

MAP_COUNT=$(count_bpf_maps)
_log "BPF maps present: $MAP_COUNT"
for m in uid_owner_map app_uid_stats_map cookie_tag_map configuration_map stats_map_A stats_map_B; do
    p="$BPF_NETD/map_netd_$m"
    [ -e "$p" ] && _log "  $m: present" || _log "  $m: absent"
done

if stub_bpfloader_detected; then
    _log "*** bpfloader STUB detected (mainline_done present, 0 maps) ***"
fi

_log "--- SELinux denials (relevant) ---"
dmesg 2>/dev/null | grep 'avc:.*denied' | grep -iE 'bpf|netd|bpfloader|proc_net' | tail -10 | \
    while IFS= read -r line; do _log "  DENIED: $line"; done

BPF_RESTORE=0
if   [ "$KMAJOR" -gt 4 ]; then BPF_RESTORE=1
elif [ "$KMAJOR" -eq 4 ] && [ "$KMINOR" -ge 9 ]; then BPF_RESTORE=1
fi
_log "BPF restore eligible: $BPF_RESTORE (kernel $KMAJOR.$KMINOR)"

if [ "$BPF_RESTORE" -eq 0 ]; then
    _log "BPF not possible on kernel $KMAJOR.$KMINOR, using netproxy fallback"
fi

# Phase 1: Start netproxy EARLY so it can register before SystemUI re-queries
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

# Phase 2: BPF Repair
BPF_STATS_OK=0
if bpf_stats_ready; then
    BPF_STATS_OK=1
    _log "--- Phase 2: BPF maps already present ---"
elif [ "$BPF_RESTORE" -eq 0 ]; then
    _log "--- Phase 2: BPF not capable, skipping ---"
else
    _log "--- Phase 2: BPF Repair ---"

    CURRENT_OVERRIDE=$(getprop ro.bpf.kver_override 2>/dev/null)
    if [ "$CURRENT_OVERRIDE" != "$CORRECT_KVER" ]; then
        _log "Fixing kver_override: $CURRENT_OVERRIDE -> $CORRECT_KVER"
        resetprop ro.bpf.kver_override "$CORRECT_KVER" 2>/dev/null \
        || resetprop_phh ro.bpf.kver_override "$CORRECT_KVER" 2>/dev/null \
        || setprop ro.bpf.kver_override "$CORRECT_KVER" 2>/dev/null
    fi

    apply_sepolicy

    [ -d "$BPF_NETD/mainline_done" ] && rm -rf "$BPF_NETD/mainline_done" 2>/dev/null \
        && _log "Deleted mainline_done"

    echo 1 > /proc/sys/net/core/bpf_jit_enable 2>/dev/null

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
        _log "  BPF maps after attempt $ATTEMPT: $NEW (was: $MAP_COUNT)"
    done

    if bpf_stats_ready; then
        BPF_STATS_OK=1
        _log "BPF Repair SUCCESS!"
    else
        _log "BPF Repair FAILED after $ATTEMPT attempts"
        if stub_bpfloader_detected; then
            _log "  Cause: bpfloader is a STUB (patched to skip map creation)"
            _log "  Will rely on netproxy fallback"
        fi
        ls -la "$BPF_NETD/" 2>/dev/null | while IFS= read -r l; do _log "  $l"; done
    fi
fi

# Phase 3: xt_qtaguid fallback
QTAGUID_OK=0
STATSFILE_D="/data/local/tmp/netstats"
mkdir -p "$STATSFILE_D" 2>/dev/null

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

# Phase 6: Ensure netproxy is running
if [ "$BPF_STATS_OK" -eq 0 ]; then
    _log "--- Phase 6: Netproxy Fallback Check ---"

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

    if [ -n "$NPROXY_BIN" ]; then
        if [ -n "$NPROXY_PID" ] && ! kill -0 "$NPROXY_PID" 2>/dev/null; then
            NPROXY_PID=""
        fi
        if [ -z "$NPROXY_PID" ]; then
            _log "Starting netproxy (BPF fallback)..."
            NPROXY_PID=$(start_nproxy "$NPROXY_BIN")
        fi

        # Check if proxy registered successfully
        if [ -n "$NPROXY_PID" ]; then
            sleep 2
            if grep -q "registered '" "$LOG" 2>/dev/null; then
                _log "Netproxy registered in ServiceManager"
            elif grep -q "WARNING:" "$LOG" 2>/dev/null; then
                _log "Netproxy registration failed (continuing anyway)"
            fi
        fi
    else
        _log "FATAL: netproxy binary not found"
    fi
else
    _log "--- Phase 6: BPF working, proxy not needed ---"
fi

# Phase 7: Restart SystemUI
_log "--- Phase 7: Restart SystemUI ---"
sleep 3
killall -9 com.android.systemui 2>/dev/null \
    || pkill -9 -f com.android.systemui 2>/dev/null \
    || am force-stop com.android.systemui 2>/dev/null
_log "SystemUI killed"
sleep 8
SYSUI_PID=$(pidof com.android.systemui 2>/dev/null)
_log "SystemUI running as pid=$SYSUI_PID"

sleep 5

# Phase 8: Summary
_log "============================================"
_log "SUMMARY:"
if [ "$BPF_STATS_OK" -eq 1 ]; then
    _log "  BPF maps restored per-UID stats active"
elif [ -n "$NPROXY_PID" ] && kill -0 "$NPROXY_PID" 2>/dev/null; then
    _log "  Netproxy active (PID $NPROXY_PID) via /proc/net/dev"
elif [ "$QTAGUID_OK" -eq 1 ]; then
    _log "  xt_qtaguid active"
else
    _log "  No BPF/proxy/qtaguid only interface-level stats"
fi
_log "============================================"
_log "=== service.sh complete ==="

# Phase 9: Watchdog
WD=0
while true; do
    sleep 300
    WD=$((WD+1))

    NSE=$(settings get global network_stats_enabled 2>/dev/null)
    [ "$NSE" != "1" ] && settings put global network_stats_enabled 1 2>/dev/null \
        && _log "[WD-$WD] Restored network_stats_enabled"

    RNM=$(settings get global restricted_networking_mode 2>/dev/null)
    [ "$RNM" = "1" ] && settings put global restricted_networking_mode 0 2>/dev/null \
        && _log "[WD-$WD] Cleared restricted_networking_mode"

    NETD=$(getprop init.svc.netd 2>/dev/null)
    [ "$NETD" != "running" ] && setprop ctl.restart netd 2>/dev/null \
        && _log "[WD-$WD] Restarted netd"

    if [ "$BPF_STATS_OK" -eq 1 ] && ! bpf_stats_ready; then
        _log "[WD-$WD] BPF maps lost attempting restore..."
        [ -d "$BPF_NETD/mainline_done" ] && rm -rf "$BPF_NETD/mainline_done" 2>/dev/null
        stop bpfloader 2>/dev/null; sleep 1; start bpfloader 2>/dev/null
        sleep 10
        if bpf_stats_ready; then
            _log "[WD-$WD] BPF maps restored"
            setprop ctl.restart netd 2>/dev/null
        fi
    fi

    if [ "$BPF_STATS_OK" -eq 0 ] && [ -n "$NPROXY_BIN" ]; then
        if ! pidof netproxy > /dev/null 2>&1; then
            _log "[WD-$WD] Proxy died restarting..."
            NPROXY_PID=$(start_nproxy "$NPROXY_BIN")
            if [ -n "$NPROXY_PID" ]; then
                # Restart SystemUI to pick up new service reference
                killall -9 com.android.systemui 2>/dev/null || true
            fi
        fi
    fi

    # BPF stub bypass: if mainline_done exists but no maps, keep deleting it
    if stub_bpfloader_detected; then
        rm -rf "$BPF_NETD/mainline_done" 2>/dev/null
        _log "[WD-$WD] Deleted stale mainline_done from stub bpfloader"
    fi

    if [ "$((WD % 12))" -eq 0 ]; then
        _log "[WD-$WD] maps=$(count_bpf_maps) proxy=$(pidof netproxy 2>/dev/null || echo none) netd=$NETD"
    fi
done
