#!/system/bin/sh
MODDIR=${0%/*}
LOG=/data/local/tmp/netproxy.log

log() { echo "$(date) [service] $*" >> "$LOG"; }

BPF_DIR="/sys/fs/bpf/netd_shared"
BPF_MAP_OWNER="$BPF_DIR/map_netd_uid_owner_map"
BPF_MAP_APP_STATS="$BPF_DIR/map_netd_app_uid_stats_map"
BPF_MAP_COOKIE="$BPF_DIR/map_netd_cookie_tag_map"
BPF_MAP_CONFIG="$BPF_DIR/map_netd_configuration_map"
BPF_MAP_STATS_A="$BPF_DIR/map_netd_stats_map_A"
BPF_MAP_STATS_B="$BPF_DIR/map_netd_stats_map_B"

count_bpf_maps() {
    local c=0
    for m in "$BPF_MAP_OWNER" "$BPF_MAP_APP_STATS" "$BPF_MAP_COOKIE" \
             "$BPF_MAP_CONFIG" "$BPF_MAP_STATS_A" "$BPF_MAP_STATS_B"; do
        [ -e "$m" ] && c=$((c+1))
    done
    echo "$c"
}

bpf_stats_ready() {
    [ -e "$BPF_MAP_APP_STATS" ] && [ -e "$BPF_MAP_CONFIG" ]
}

# Multi-path binary resolution (shared with lite)
find_netproxy() {
    local probe
    for probe in \
        "$MODDIR/system/bin/netproxy" \
        "${0%/*}/system/bin/netproxy" \
        "/data/adb/modules/netstats-fix/system/bin/netproxy" \
        "/data/adb/modules/netstats-fix-lite/system/bin/netproxy" \
        "/system/bin/netproxy" \
        "$(dirname "$0" 2>/dev/null)/system/bin/netproxy"; do
        [ -f "$probe" ] && { echo "$probe"; return 0; }
    done
    local found
    found=$(find "$MODDIR" -name "netproxy" -type f 2>/dev/null | head -1)
    [ -n "$found" ] && { echo "$found"; return 0; }
    found=$(find /data/adb/modules -name "netproxy" -type f 2>/dev/null | head -1)
    [ -n "$found" ] && { echo "$found"; return 0; }
    return 1
}

select_arch_binary() {
    local base_bin="$1"
    local dir; dir=$(dirname "$base_bin")
    local arch; arch=$(getprop ro.product.cpu.abi 2>/dev/null)
    log "Detected arch: ${arch:-unknown}"
    case "$arch" in
        arm64-v8a|arm64)
            [ -f "$base_bin" ] && { echo "$base_bin"; return 0; }
            [ -f "$dir/netproxy_arm" ] && { echo "$dir/netproxy_arm"; return 0; }
            [ -f "$dir/../netproxy" ] && { echo "$dir/../netproxy"; return 0; }
            [ -f "$dir/../netproxy_arm" ] && { echo "$dir/../netproxy_arm"; return 0; }
            ;;
        armeabi-v7a|armeabi)
            [ -f "$dir/netproxy_arm" ] && { echo "$dir/netproxy_arm"; return 0; }
            [ -f "$base_bin" ] && { echo "$base_bin"; return 0; }
            ;;
        *)
            [ -f "$base_bin" ] && { echo "$base_bin"; return 0; }
            [ -f "$dir/netproxy_arm" ] && { echo "$dir/netproxy_arm"; return 0; }
            ;;
    esac
    return 1
}

start_proxy() {
    local bin="$1"
    if [ ! -f "$bin" ]; then
        log "start_proxy: binary not found at $bin"
        return 1
    fi
    chmod 755 "$bin"
    if ! head -c 4 "$bin" 2>/dev/null | grep -q $'\x7fELF'; then
        log "WARNING: $bin is not an ELF binary!"
    fi
    log "Starting netproxy: $bin"
    nohup "$bin" >> "$LOG" 2>&1 &
    local pid=$!
    log "Proxy launched (pid=$pid)"
    sleep 3
    if kill -0 "$pid" 2>/dev/null; then
        log "Proxy is running (PID $pid)"
        echo "$pid"
        return 0
    else
        log "Proxy exited prematurely, retrying..."
        nohup "$bin" >> "$LOG" 2>&1 &
        pid=$!
        log "Proxy retry launched (pid=$pid)"
        sleep 3
        if kill -0 "$pid" 2>/dev/null; then
            log "Proxy running after retry"
            echo "$pid"
            return 0
        fi
        log "Proxy failed both attempts"
        return 1
    fi
}

log "=== service.sh started ==="
WAIT=0
while [ "$(getprop sys.boot_completed)" != "1" ] && [ "$WAIT" -lt 180 ]; do
    sleep 1; WAIT=$((WAIT + 1))
done
log "Boot completed after ${WAIT}s"
sleep 20

# ==================== PHASE 1: Diagnostics ====================
log "--- Phase 1: Diagnostics ---"

KVER=$(uname -r 2>/dev/null)
KMAJOR=$(echo "$KVER" | cut -d. -f1)
KMINOR=$(echo "$KVER" | cut -d. -f2)
KPATCH=$(echo "$KVER" | cut -d. -f3 | grep -oE '^[0-9]+')
[ -z "$KMAJOR" ] && KMAJOR=0
[ -z "$KMINOR" ] && KMINOR=0
[ -z "$KPATCH" ] && KPATCH=0
log "Kernel: $KVER (parsed: $KMAJOR.$KMINOR.$KPATCH)"
log "Android: $(getprop ro.build.version.sdk 2>/dev/null)"
log "SELinux: $(getenforce 2>/dev/null)"

BPF_CAPABLE=0
[ "$KMAJOR" -gt 4 ] || { [ "$KMAJOR" -eq 4 ] && [ "$KMINOR" -ge 9 ]; } && BPF_CAPABLE=1
log "BPF capable kernel: $BPF_CAPABLE"

MAP_COUNT=$(count_bpf_maps)
log "BPF maps present: $MAP_COUNT"

for m in uid_owner_map app_uid_stats_map cookie_tag_map configuration_map stats_map_A stats_map_B uid_permission_map iface_stats_map; do
    eval "p=\$BPF_MAP_$(echo "$m" | tr '[:lower:]' '[:upper:]')"
    [ -e "$p" ] && s=present || s=absent
    log "  $m: $s"
done

ls -la "$BPF_DIR/" 2>/dev/null | while read line; do log "  BPF_DIR: $line"; done
[ -d "$BPF_DIR/mainline_done" ] && log "mainline_done: PRESENT" || log "mainline_done: absent"

log "netd: $(getprop init.svc.netd 2>/dev/null)"
log "bpfloader: $(getprop init.svc.bpfloader 2>/dev/null)"
log "network_stats_enabled: $(settings get global network_stats_enabled 2>/dev/null)"
log "restricted_networking_mode: $(settings get global restricted_networking_mode 2>/dev/null)"

# ==================== PHASE 2: SELinux Audit ====================
log "--- SELinux Denial Diagnostics ---"
dmesg 2>/dev/null | grep -i 'avc.*denied' | grep -iE 'bpf|netd|net_bw|bpfloader|proc_net|qtaguid' | tail -20 | while read line; do
    log "  DENIED: $line"
done
logcat -d -b all -e 'avc.*denied' 2>/dev/null | grep -iE 'bpf|netd|net_bw|bpfloader|proc_net|qtaguid' | tail -10 | while read line; do
    log "  LOGCAT: $line"
done

# ==================== PHASE 3: BPF Repair ====================
BPF_STATS_OK=0
if bpf_stats_ready; then
    BPF_STATS_OK=1
    log "--- Phase 3: BPF maps already present (no repair needed) ---"
elif [ "$BPF_CAPABLE" -eq 0 ]; then
    log "--- Phase 3: BPF not capable (kernel < 4.9) ---"
else
    log "--- Phase 3: BPF Repair ---"

    CORRECT_KVER="${KMAJOR}.${KMINOR}.${KPATCH}"
    CURRENT_OVERRIDE=$(getprop ro.bpf.kver_override 2>/dev/null)
    if [ "$CURRENT_OVERRIDE" != "$CORRECT_KVER" ]; then
        log "Step 1: Fixing kver_override ($CURRENT_OVERRIDE -> $CORRECT_KVER)"
        resetprop ro.bpf.kver_override "$CORRECT_KVER" 2>/dev/null
        resetprop_phh ro.bpf.kver_override "$CORRECT_KVER" 2>/dev/null
    else
        log "Step 1: kver_override already correct ($CORRECT_KVER)"
    fi

    [ -d "$BPF_DIR/mainline_done" ] && rm -rf "$BPF_DIR/mainline_done" 2>/dev/null && \
        log "Step 2: Deleted stale mainline_done"

    echo 1 > /proc/sys/net/core/bpf_jit_enable 2>/dev/null && \
        log "Step 3: BPF JIT enabled"

    BPF_ATTEMPT=0
    while [ "$BPF_ATTEMPT" -lt 2 ] && [ "$(count_bpf_maps)" -lt 6 ]; do
        BPF_ATTEMPT=$((BPF_ATTEMPT + 1))
        log "Step 4: Attempt $BPF_ATTEMPT - Restarting bpfloader..."

        stop bpfloader 2>/dev/null
        sleep 2
        start bpfloader 2>/dev/null

        BPF_WAIT=0
        while [ "$(getprop init.svc.bpfloader 2>/dev/null)" = "running" ] && [ "$BPF_WAIT" -lt 45 ]; do
            sleep 1; BPF_WAIT=$((BPF_WAIT + 1))
        done
        log "  bpfloader completed after ${BPF_WAIT}s (status: $(getprop init.svc.bpfloader 2>/dev/null))"
        sleep 3

        NEW_MAP_COUNT=$(count_bpf_maps)
        log "  BPF maps now: $NEW_MAP_COUNT (was: $MAP_COUNT)"
    done

    if bpf_stats_ready; then
        BPF_STATS_OK=1
        log "BPF Repair SUCCESS: Critical maps present!"
    else
        log "BPF Repair FAILED: Maps still missing after $BPF_ATTEMPT attempts"
        ls -la "$BPF_DIR/" 2>/dev/null | while read line; do log "  BPF_DIR: $line"; done
    fi
fi

# ==================== PHASE 4: Netd Restart ====================
if [ "$BPF_STATS_OK" -eq 1 ]; then
    log "--- Phase 4: Restarting netd ---"
    setprop ctl.restart netd 2>/dev/null
    NETD_WAIT=0
    while [ "$(getprop init.svc.netd 2>/dev/null)" != "running" ] && [ "$NETD_WAIT" -lt 30 ]; do
        sleep 1; NETD_WAIT=$((NETD_WAIT + 1))
    done
    sleep 5
    log "Netd restarted (waited ${NETD_WAIT}s)"
fi

# ==================== PHASE 5: Settings ====================
log "--- Phase 5: Settings ---"

settings put global restricted_networking_mode 0 2>/dev/null
log "restricted_networking_mode=0"

log "Setting network_stats_enabled=1..."
ATTEMPT=0
while [ "$ATTEMPT" -lt 10 ]; do
    ATTEMPT=$((ATTEMPT + 1))
    settings put global network_stats_enabled 1 2>/dev/null
    sleep 2
    NSE=$(settings get global network_stats_enabled 2>/dev/null)
    [ "$NSE" = "1" ] && log "network_stats_enabled=1 (attempt $ATTEMPT)" && break
    log "  attempt $ATTEMPT: got '$NSE'"
done

settings put global netstats_enabled 1 2>/dev/null
cmd netstats force-refresh 2>/dev/null && log "force-refresh: success" || log "force-refresh: not available"
cmd netstatscore force-refresh 2>/dev/null && log "force-refresh(core): success" || true

# ==================== PHASE 6: Native Proxy Fallback ====================
PROXY_RUNNING=0
TARGET_BIN=""

if [ "$BPF_STATS_OK" -eq 0 ]; then
    log "--- Phase 6: Native Proxy Fallback ---"

    chmod 0644 /proc/net/dev 2>/dev/null
    chmod 0644 /proc/self/net/dev 2>/dev/null

    magiskpolicy --live "allow * proc_net:file { read open getattr }" 2>/dev/null
    magiskpolicy --live "allow * proc_net:dir { read search open }" 2>/dev/null
    magiskpolicy --live "allow * binder_device:chr_file { read write open ioctl }" 2>/dev/null
    magiskpolicy --live "allow * binder:service_manager { find add }" 2>/dev/null
    magiskpolicy --live "allow * netd:fd use" 2>/dev/null
    magiskpolicy --live "allow * netd_socket:sock_file write" 2>/dev/null
    magiskpolicy --live "allow system_server proc_net:file { read open getattr }" 2>/dev/null
    magiskpolicy --live "allow system_server proc_net:dir { read search open }" 2>/dev/null

    PROXY_BIN=$(find_netproxy)
    if [ -z "$PROXY_BIN" ]; then
        log "FATAL: netproxy not found after exhaustive search"
        log "MODDIR=$MODDIR"
        log "Contents of $MODDIR:"
        ls -la "$MODDIR" 2>/dev/null >> "$LOG" || log "  (cannot list)"
        log "Contents of ${MODDIR}/system:"
        ls -la "$MODDIR/system" 2>/dev/null >> "$LOG" || log "  (cannot list)"
        log "Contents of ${MODDIR}/system/bin:"
        ls -la "$MODDIR/system/bin" 2>/dev/null >> "$LOG" || log "  (cannot list)"
        log "Searching /data/adb/modules:"
        ls -la /data/adb/modules/ 2>/dev/null >> "$LOG" || log "  (no modules dir)"
    else
        TARGET_BIN=$(select_arch_binary "$PROXY_BIN")
        [ -z "$TARGET_BIN" ] && TARGET_BIN="$PROXY_BIN"

        log "Found binary: $TARGET_BIN"
        PROXY_PID=$(start_proxy "$TARGET_BIN")
        if [ -n "$PROXY_PID" ] && [ "$PROXY_PID" -gt 0 ] 2>/dev/null; then
            PROXY_RUNNING=1
        fi
    fi
else
    log "--- Phase 6: BPF working, skipping proxy ---"
fi

# ==================== PHASE 7: Restart SystemUI ====================
log "--- Phase 7: Restart SystemUI ---"
sleep 3
killall -9 com.android.systemui 2>/dev/null || \
    pkill -9 -f "com.android.systemui" 2>/dev/null || \
    am force-stop com.android.systemui 2>/dev/null
log "SystemUI killed"
sleep 8
SYSUI_PID=$(pidof com.android.systemui 2>/dev/null)
log "SystemUI running as pid=$SYSUI_PID"

# ==================== PHASE 8: Summary ====================
log "============================================"
if [ "$BPF_STATS_OK" -eq 1 ]; then
    log "RESULT: BPF maps fixed - native stats active"
elif [ "$PROXY_RUNNING" -eq 1 ]; then
    log "RESULT: BPF failed, proxy fallback active"
    log "  /proc/net/dev provides interface-level stats"
else
    log "RESULT: No stats mechanism available"
    log "  Attempting emergency settings override..."
fi
log "============================================"
log "=== service.sh complete ==="

# ==================== PHASE 9: Watchdog ====================
WD_COUNT=0
while true; do
    sleep 300
    WD_COUNT=$((WD_COUNT + 1))

    NSE=$(settings get global network_stats_enabled 2>/dev/null)
    [ "$NSE" != "1" ] && settings put global network_stats_enabled 1 2>/dev/null && \
        log "[WD-$WD_COUNT] Corrected NSE (was: $NSE)"

    NETD_STATUS=$(getprop init.svc.netd 2>/dev/null)
    if [ "$NETD_STATUS" != "running" ]; then
        log "[WD-$WD_COUNT] netd not running ($NETD_STATUS), restarting..."
        setprop ctl.restart netd 2>/dev/null
    fi

    if [ "$BPF_STATS_OK" -eq 1 ] && [ ! -e "$BPF_MAP_APP_STATS" ]; then
        log "[WD-$WD_COUNT] BPF maps lost, restarting netd..."
        setprop ctl.restart netd 2>/dev/null
        sleep 10
    fi

    if [ "$PROXY_RUNNING" -eq 1 ] && [ -n "$TARGET_BIN" ] && [ -f "$TARGET_BIN" ]; then
        PROXY_PID_CHECK=$(pidof netproxy 2>/dev/null)
        if [ -z "$PROXY_PID_CHECK" ] || [ "$PROXY_PID_CHECK" = "0" ]; then
            log "[WD-$WD_COUNT] Proxy died, restarting..."
            start_proxy "$TARGET_BIN" > /dev/null && PROXY_RUNNING=1 || PROXY_RUNNING=0
        fi
    fi

    if [ "$(($WD_COUNT % 6))" -eq 0 ]; then
        M=$( [ -e "$BPF_MAP_OWNER" ] && echo Y || echo N )
        P=$( [ "$PROXY_RUNNING" -eq 1 ] && echo Y || echo N )
        log "[WD-$WD_COUNT] Status: maps=$M proxy=$P netd=$(getprop init.svc.netd 2>/dev/null)"
    fi
done
