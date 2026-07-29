#!/system/bin/sh
MODDIR=${0%/*}
LOG=/data/local/tmp/netproxy.log
PROXY_BIN="$MODDIR/system/bin/netproxy"

log() { echo "$(date) [service] $*" >> "$LOG"; }

# ============================================================
# BPF map paths (CORRECT map_netd_ prefix)
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

count_bpf_maps() {
    local c=0
    [ -e "$BPF_MAP_OWNER" ] && c=$((c+1))
    [ -e "$BPF_MAP_APP_STATS" ] && c=$((c+1))
    [ -e "$BPF_MAP_COOKIE" ] && c=$((c+1))
    [ -e "$BPF_MAP_CONFIG" ] && c=$((c+1))
    [ -e "$BPF_MAP_STATS_A" ] && c=$((c+1))
    [ -e "$BPF_MAP_STATS_B" ] && c=$((c+1))
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
sleep 15

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
log "Kernel: $KVER"
log "Android: $(getprop ro.build.version.sdk)"

BPF_CAPABLE=0
if [ "$KMAJOR" -gt 4 ] || { [ "$KMAJOR" -eq 4 ] && [ "$KMINOR" -ge 9 ]; } 2>/dev/null; then
    BPF_CAPABLE=1
fi
log "BPF capable: $BPF_CAPABLE"

MAP_COUNT=$(count_bpf_maps)
log "BPF maps present: $MAP_COUNT"

for m in uid_owner_map app_uid_stats_map cookie_tag_map configuration_map stats_map_A stats_map_B uid_permission_map iface_stats_map; do
    eval "p=\"\$BPF_MAP_$(echo $m | tr 'a-z' 'A-Z')\""
    [ -e "$(eval echo \$BPF_MAP_$(echo $m | tr '[:lower:]' '[:upper:]'))" ] && s=present || s=absent
    log "  $m: $s"
done

ls -la "$BPF_DIR/" 2>/dev/null >> "$LOG"
[ -d "$BPF_DIR/mainline_done" ] && log "mainline_done: PRESENT" || log "mainline_done: absent"

log "netd: $(getprop init.svc.netd 2>/dev/null)"
log "bpfloader: $(getprop init.svc.bpfloader 2>/dev/null)"
log "SELinux: $(getenforce 2>/dev/null)"
log "network_stats_enabled: $(settings get global network_stats_enabled 2>/dev/null)"
log "restricted_networking_mode: $(settings get global restricted_networking_mode 2>/dev/null)"

# ============================================================
# PHASE 2: BPF Repair
# ============================================================
BPF_STATS_OK=0
if bpf_stats_ready; then
    BPF_STATS_OK=1
    log "--- Phase 2: BPF maps present (no repair) ---"
elif [ "$BPF_CAPABLE" -eq 0 ]; then
    log "--- Phase 2: BPF not capable (kernel < 4.9) ---"
else
    log "--- Phase 2: BPF Repair ---"

    CORRECT_KVER="${KMAJOR}.${KMINOR}.${KPATCH}"
    CURRENT_OVERRIDE=$(getprop ro.bpf.kver_override 2>/dev/null)
    if [ "$CURRENT_OVERRIDE" != "$CORRECT_KVER" ]; then
        log "Repair 1: Fixing ro.bpf.kver_override ($CURRENT_OVERRIDE -> $CORRECT_KVER)"
        resetprop ro.bpf.kver_override "$CORRECT_KVER" 2>/dev/null
        resetprop_phh ro.bpf.kver_override "$CORRECT_KVER" 2>/dev/null
    else
        log "Repair 1: ro.bpf.kver_override already correct"
    fi

    [ -d "$BPF_DIR/mainline_done" ] && rm -rf "$BPF_DIR/mainline_done" 2>/dev/null && log "Repair 2: Deleted stale mainline_done"

    echo 1 > /proc/sys/net/core/bpf_jit_enable 2>/dev/null

    log "Repair 2: Restarting bpfloader..."
    stop bpfloader 2>/dev/null
    sleep 3
    start bpfloader 2>/dev/null

    BPF_WAIT=0
    while [ "$(getprop init.svc.bpfloader 2>/dev/null)" = "running" ] && [ "$BPF_WAIT" -lt 45 ]; do
        sleep 1; BPF_WAIT=$((BPF_WAIT + 1))
    done
    log "Repair 2: bpfloader completed after ${BPF_WAIT}s"
    sleep 3

    NEW_MAP_COUNT=$(count_bpf_maps)
    log "Repair 2: BPF maps now: $NEW_MAP_COUNT (was: $MAP_COUNT)"

    if bpf_stats_ready; then
        BPF_STATS_OK=1
        log "Repair 2 SUCCESS: Critical BPF maps present!"
    else
        log "Repair 2: Critical maps still missing"
        ls -la "$BPF_DIR/" 2>/dev/null >> "$LOG"
        log "Repair 3: Capturing SELinux denials (setenforce 0 SKIPPED for safety)"
        dmesg 2>/dev/null | grep -i 'avc.*denied' | grep -iE 'bpf|netd|net_bw|bpfloader' | tail -20 >> "$LOG"
    fi
fi

# ============================================================
# PHASE 3: Netd Restart
# ============================================================
log "--- Phase 3: Netd Restart ---"
setprop ctl.restart netd 2>/dev/null
NETD_WAIT=0
while [ "$(getprop init.svc.netd 2>/dev/null)" != "running" ] && [ "$NETD_WAIT" -lt 30 ]; do
    sleep 1; NETD_WAIT=$((NETD_WAIT + 1))
done
sleep 5
log "Netd restarted (waited ${NETD_WAIT}s)"

# ============================================================
# PHASE 4: Settings
# ============================================================
log "--- Phase 4: Settings ---"

settings put global restricted_networking_mode 0 2>/dev/null
log "restricted_networking_mode=0"

log "Setting network_stats_enabled=1..."
ATTEMPT=0
while [ "$ATTEMPT" -lt 5 ]; do
    ATTEMPT=$((ATTEMPT + 1))
    settings put global network_stats_enabled 1 2>/dev/null
    sleep 2
    NSE=$(settings get global network_stats_enabled 2>/dev/null)
    [ "$NSE" = "1" ] && log "network_stats_enabled=1 (attempt $ATTEMPT)" && break
    log "  attempt $ATTEMPT: got '$NSE'"
done

cmd netstats force-refresh 2>/dev/null && log "cmd netstats force-refresh: success" || log "cmd netstats force-refresh: not available"

# ============================================================
# PHASE 5: Native Proxy Fallback (if BPF can't provide per-UID)
# ============================================================
PROXY_RUNNING=0
if [ "$BPF_STATS_OK" -eq 0 ]; then
    log "--- Phase 5: Native Proxy Fallback ---"
    chmod 0644 /proc/net/dev 2>/dev/null

    magiskpolicy --live "allow * proc_net:file { read open getattr }" 2>/dev/null
    magiskpolicy --live "allow * binder_device:chr_file { read write open ioctl }" 2>/dev/null
    magiskpolicy --live "allow * binder:service_manager { find add }" 2>/dev/null
    magiskpolicy --live "allow magisk proc_net:file { read open getattr }" 2>/dev/null
    magiskpolicy --live "allow magisk binder_device:chr_file { read write open ioctl }" 2>/dev/null
    magiskpolicy --live "allow magisk binder:service_manager { find add }" 2>/dev/null
    log "SELinux policies applied"

    if [ -f "$PROXY_BIN" ]; then
        log "netproxy size: $(stat -c%s "$PROXY_BIN" 2>/dev/null || wc -c < "$PROXY_BIN")"
        nohup "$PROXY_BIN" >> "$LOG" 2>&1 &
        PROXY_PID=$!
        log "proxy launched pid=$PROXY_PID"
        PROXY_RUNNING=1
    else
        log "FATAL: netproxy not found"
    fi
fi

# ============================================================
# PHASE 6: Restart SystemUI
# ============================================================
log "--- Phase 6: Restart SystemUI ---"
sleep 5
killall -9 com.android.systemui 2>/dev/null || pkill -9 -f "com.android.systemui" 2>/dev/null || am force-stop com.android.systemui 2>/dev/null
log "SystemUI killed"
sleep 8
log "SystemUI running as pid=$(pidof com.android.systemui 2>/dev/null)"

# ============================================================
# PHASE 7: Summary
# ============================================================
log "============================================"
if [ "$BPF_STATS_OK" -eq 1 ]; then
    log "RESULT: BPF maps fixed - native stats should work"
elif [ "$PROXY_RUNNING" -eq 1 ]; then
    log "RESULT: BPF repair failed, proxy fallback active"
    log "  Using /proc/net/dev for interface-level stats"
else
    log "RESULT: No stats mechanism available"
fi
log "============================================"
log "=== service.sh complete ==="

# ============================================================
# PHASE 8: Watchdog
# ============================================================
WD_COUNT=0
while true; do
    sleep 300
    WD_COUNT=$((WD_COUNT + 1))

    NSE=$(settings get global network_stats_enabled 2>/dev/null)
    [ "$NSE" != "1" ] && settings put global network_stats_enabled 1 2>/dev/null && log "[WD-$WD_COUNT] Corrected NSE (was: $NSE)"

    if [ "$BPF_STATS_OK" -eq 1 ] && [ ! -e "$BPF_MAP_APP_STATS" ]; then
        log "[WD-$WD_COUNT] BPF maps lost, restarting netd..."
        setprop ctl.restart netd 2>/dev/null
        sleep 10
    fi

    if [ "$(($WD_COUNT % 6))" -eq 0 ]; then
        M=$( [ -e "$BPF_MAP_OWNER" ] && echo Y || echo N )
        log "[WD-$WD_COUNT] Status: owner=$M netd=$(getprop init.svc.netd 2>/dev/null) NSE=$(settings get global network_stats_enabled 2>/dev/null)"
    fi
done
