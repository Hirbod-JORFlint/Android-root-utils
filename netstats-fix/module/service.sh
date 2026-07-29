#!/system/bin/sh
MODDIR=${0%/*}
LOG=/data/local/tmp/netproxy.log
PROXY_BIN="$MODDIR/system/bin/netproxy"

log() { echo "$(date) [service] $*" >> "$LOG"; }

# ============================================================
# BPF map paths
# ============================================================
BPF_DIR="/sys/fs/bpf/netd_shared"
BPF_MAP_OWNER="$BPF_DIR/map_netd_uid_owner_map"
BPF_MAP_APP_STATS="$BPF_DIR/map_netd_app_uid_stats_map"
BPF_MAP_COOKIE="$BPF_DIR/map_netd_cookie_tag_map"
BPF_MAP_CONFIG="$BPF_DIR/map_netd_configuration_map"
BPF_MAP_STATS_A="$BPF_DIR/map_netd_stats_map_A"
BPF_MAP_STATS_B="$BPF_DIR/map_netd_stats_map_B"
BPF_MAP_UID_PERM="$BPF_DIR/map_netd_uid_permission_map"
BPF_MAP_IFACE_STATS="$BPF_DIR/map_netd_iface_stats_map"

# Alternate BPF mount paths (some ROMs use different mountpoints)
BPF_DIR_ALT1="/sys/fs/bpf/netd_shared"
BPF_DIR_ALT2="/sys/fs/bpf"

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

# ============================================================
# PHASE 0: Wait for boot
# ============================================================
log "=== service.sh started ==="
WAIT=0
while [ "$(getprop sys.boot_completed)" != "1" ] && [ "$WAIT" -lt 180 ]; do
    sleep 1; WAIT=$((WAIT + 1))
done
log "Boot completed after ${WAIT}s"

# Wait a bit more for services to settle
sleep 20

# ============================================================
# PHASE 1: Diagnostics
# ============================================================
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
if [ "$KMAJOR" -gt 4 ] || { [ "$KMAJOR" -eq 4 ] && [ "$KMINOR" -ge 9 ]; }; then
    BPF_CAPABLE=1
fi
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

# ============================================================
# PHASE 2: SELinux Audit (collect denials without breaking)
# ============================================================
log "--- SELinux Denial Diagnostics ---"
dmesg 2>/dev/null | grep -i 'avc.*denied' | grep -iE 'bpf|netd|net_bw|bpfloader|proc_net|qtaguid' | tail -20 | while read line; do
    log "  DENIED: $line"
done
logcat -d -b all -e 'avc.*denied' 2>/dev/null | grep -iE 'bpf|netd|net_bw|bpfloader|proc_net|qtaguid' | tail -10 | while read line; do
    log "  LOGCAT: $line"
done

# ============================================================
# PHASE 3: BPF Repair (only if maps are missing and kernel >= 4.9)
# ============================================================
BPF_STATS_OK=0
if bpf_stats_ready; then
    BPF_STATS_OK=1
    log "--- Phase 3: BPF maps already present (no repair needed) ---"
elif [ "$BPF_CAPABLE" -eq 0 ]; then
    log "--- Phase 3: BPF not capable (kernel < 4.9) ---"
else
    log "--- Phase 3: BPF Repair ---"

    # Step 1: Verify kver_override
    CORRECT_KVER="${KMAJOR}.${KMINOR}.${KPATCH}"
    CURRENT_OVERRIDE=$(getprop ro.bpf.kver_override 2>/dev/null)
    if [ "$CURRENT_OVERRIDE" != "$CORRECT_KVER" ]; then
        log "Step 1: Fixing kver_override ($CURRENT_OVERRIDE -> $CORRECT_KVER)"
        resetprop ro.bpf.kver_override "$CORRECT_KVER" 2>/dev/null
        resetprop_phh ro.bpf.kver_override "$CORRECT_KVER" 2>/dev/null
    else
        log "Step 1: kver_override already correct ($CORRECT_KVER)"
    fi

    # Step 2: Delete stale mainline_done
    [ -d "$BPF_DIR/mainline_done" ] && rm -rf "$BPF_DIR/mainline_done" 2>/dev/null && \
        log "Step 2: Deleted stale mainline_done"

    # Step 3: Enable BPF JIT
    echo 1 > /proc/sys/net/core/bpf_jit_enable 2>/dev/null && \
        log "Step 3: BPF JIT enabled"

    # Step 4: Try to reload bpfloader (up to 2 attempts)
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

# ============================================================
# PHASE 4: Netd Restart (if BPF now working)
# ============================================================
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

# ============================================================
# PHASE 5: Settings
# ============================================================
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

# Also set netstats_enabled (AOSP compat)
settings put global netstats_enabled 1 2>/dev/null

cmd netstats force-refresh 2>/dev/null && log "force-refresh: success" || log "force-refresh: not available"
cmd netstatscore force-refresh 2>/dev/null && log "force-refresh(core): success" || true

# ============================================================
# PHASE 6: Native Proxy Fallback
# ============================================================
PROXY_RUNNING=0
if [ "$BPF_STATS_OK" -eq 0 ]; then
    log "--- Phase 6: Native Proxy Fallback ---"

    chmod 0644 /proc/net/dev 2>/dev/null
    chmod 0644 /proc/self/net/dev 2>/dev/null

    # Apply comprehensive SELinux policies via magiskpolicy
    magiskpolicy --live "allow * proc_net:file { read open getattr }" 2>/dev/null
    magiskpolicy --live "allow * proc_net:dir { read search open }" 2>/dev/null
    magiskpolicy --live "allow * binder_device:chr_file { read write open ioctl }" 2>/dev/null
    magiskpolicy --live "allow * binder:service_manager { find add }" 2>/dev/null
    magiskpolicy --live "allow * netd:fd use" 2>/dev/null
    magiskpolicy --live "allow * netd_socket:sock_file write" 2>/dev/null
    magiskpolicy --live "allow system_server proc_net:file { read open getattr }" 2>/dev/null
    magiskpolicy --live "allow system_server proc_net:dir { read search open }" 2>/dev/null

    # Try to find the right arch binary
    if [ -f "$PROXY_BIN" ]; then
        TARGET_BIN="$PROXY_BIN"
    else
        # Try alternate architectures
        ARCH=$(getprop ro.product.cpu.abi 2>/dev/null)
        case "$ARCH" in
            arm64-v8a|arm64)
                TARGET_BIN="$PROXY_BIN"
                [ ! -f "$TARGET_BIN" ] && TARGET_BIN="$MODDIR/system/bin/netproxy"
                ;;
            armeabi-v7a|armeabi)
                TARGET_BIN="$MODDIR/system/bin/netproxy_arm"
                [ ! -f "$TARGET_BIN" ] && TARGET_BIN="$PROXY_BIN"
                ;;
            *)
                TARGET_BIN="$PROXY_BIN"
                ;;
        esac
    fi

    if [ -f "$TARGET_BIN" ]; then
        chmod 755 "$TARGET_BIN"
        log "Starting netproxy: $TARGET_BIN"
        nohup "$TARGET_BIN" >> "$LOG" 2>&1 &
        PROXY_PID=$!
        log "Proxy launched (pid=$PROXY_PID)"
        PROXY_RUNNING=1
        sleep 2
        if kill -0 "$PROXY_PID" 2>/dev/null; then
            log "Proxy is running"
        else
            log "Proxy exited prematurely"
            PROXY_RUNNING=0
        fi
    else
        log "FATAL: netproxy not found at $TARGET_BIN"
    fi
else
    log "--- Phase 6: BPF working, skipping proxy ---"
fi

# ============================================================
# PHASE 7: Restart SystemUI
# ============================================================
log "--- Phase 7: Restart SystemUI ---"
sleep 3
killall -9 com.android.systemui 2>/dev/null || \
    pkill -9 -f "com.android.systemui" 2>/dev/null || \
    am force-stop com.android.systemui 2>/dev/null
log "SystemUI killed"
sleep 8
SYSUI_PID=$(pidof com.android.systemui 2>/dev/null)
log "SystemUI running as pid=$SYSUI_PID"

# ============================================================
# PHASE 8: Summary
# ============================================================
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

# ============================================================
# PHASE 9: Watchdog
# ============================================================
WD_COUNT=0
while true; do
    sleep 300
    WD_COUNT=$((WD_COUNT + 1))

    # Ensure network_stats_enabled stays 1
    NSE=$(settings get global network_stats_enabled 2>/dev/null)
    [ "$NSE" != "1" ] && settings put global network_stats_enabled 1 2>/dev/null && \
        log "[WD-$WD_COUNT] Corrected NSE (was: $NSE)"

    # Check if netd is running
    NETD_STATUS=$(getprop init.svc.netd 2>/dev/null)
    if [ "$NETD_STATUS" != "running" ]; then
        log "[WD-$WD_COUNT] netd not running ($NETD_STATUS), restarting..."
        setprop ctl.restart netd 2>/dev/null
    fi

    # If BPF stats were OK but maps are gone, restart netd
    if [ "$BPF_STATS_OK" -eq 1 ] && [ ! -e "$BPF_MAP_APP_STATS" ]; then
        log "[WD-$WD_COUNT] BPF maps lost, restarting netd..."
        setprop ctl.restart netd 2>/dev/null
        sleep 10
    fi

    # If proxy was running but died, restart it
    if [ "$PROXY_RUNNING" -eq 1 ] && [ -f "$TARGET_BIN" ]; then
        PROXY_PID=$(pidof netproxy 2>/dev/null || pidof "$TARGET_BIN" 2>/dev/null)
        if [ -z "$PROXY_PID" ] || [ "$PROXY_PID" = "0" ]; then
            log "[WD-$WD_COUNT] Proxy died, restarting..."
            nohup "$TARGET_BIN" >> "$LOG" 2>&1 &
            log "[WD-$WD_COUNT] Proxy restarted (pid=$!)"
        fi
    fi

    # Periodic status report
    if [ "$(($WD_COUNT % 6))" -eq 0 ]; then
        M=$( [ -e "$BPF_MAP_OWNER" ] && echo Y || echo N )
        P=$( [ "$PROXY_RUNNING" -eq 1 ] && echo Y || echo N )
        log "[WD-$WD_COUNT] Status: maps=$M proxy=$P netd=$(getprop init.svc.netd 2>/dev/null)"
    fi
done
