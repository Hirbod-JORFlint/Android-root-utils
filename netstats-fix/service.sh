#!/system/bin/sh
# service.sh - Late_start: repair network stats on all devices
#
# CRITICAL CHANGES from v4.1:
# - REMOVED setenforce 0 (causes firmware-level reboot on devices like Infinity X)
# - Fixed BPF map name checks (map_netd_uid_owner_map, not uid_owner_map)
# - Added per-device safety detection for SELinux operations
# - Added proper fallback chain: BPF -> legacy -> interface-level

MODDIR=${0%/*}
LOG=/data/local/tmp/netstats-fix.log

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [service] $1" >> "$LOG"
}

log "=== service.sh started ==="

# ============================================================
# Wait for boot completion
# ============================================================
WAIT=0
while [ "$(getprop sys.boot_completed)" != "1" ] && [ "$WAIT" -lt 180 ]; do
    sleep 1
    WAIT=$((WAIT + 1))
done
log "Boot completed after ${WAIT}s"

# Extra settle for APEX activation, netd startup, and NSS initialization
sleep 15

# ============================================================
# PATHS (using CORRECT map_netd_ prefixed names)
# ============================================================
BPF_MAP_OWNER="/sys/fs/bpf/netd_shared/map_netd_uid_owner_map"
BPF_MAP_APP_STATS="/sys/fs/bpf/netd_shared/map_netd_app_uid_stats_map"
BPF_MAP_COOKIE="/sys/fs/bpf/netd_shared/map_netd_cookie_tag_map"
BPF_MAP_CONFIG="/sys/fs/bpf/netd_shared/map_netd_configuration_map"
BPF_MAP_STATS_A="/sys/fs/bpf/netd_shared/map_netd_stats_map_A"
BPF_MAP_STATS_B="/sys/fs/bpf/netd_shared/map_netd_stats_map_B"
BPF_MAP_UID_PERM="/sys/fs/bpf/netd_shared/map_netd_uid_permission_map"
BPF_MAP_IFACE_STATS="/sys/fs/bpf/netd_shared/map_netd_iface_stats_map"
BPF_CAPABLE=$(cat /data/local/tmp/.bpf_capable 2>/dev/null || echo 0)
CORRECT_KVER=$(cat /data/local/tmp/.bpf_kver 2>/dev/null || echo unknown)

# Safety: if saved version still has non-numeric suffixes, re-strip it
if echo "$CORRECT_KVER" | grep -qE '[^0-9.]'; then
    SAVED_MAJOR=$(echo "$CORRECT_KVER" | cut -d. -f1 | grep -oE '^[0-9]+')
    SAVED_MINOR=$(echo "$CORRECT_KVER" | cut -d. -f2 | grep -oE '^[0-9]+')
    SAVED_PATCH=$(echo "$CORRECT_KVER" | cut -d. -f3 | grep -oE '^[0-9]+')
    CORRECT_KVER="${SAVED_MAJOR}.${SAVED_MINOR}.${SAVED_PATCH}"
    log "Corrected version string to: $CORRECT_KVER"
fi

# ============================================================
# Helper: count BPF maps present
# ============================================================
count_bpf_maps() {
    local count=0
    [ -e /sys/fs/bpf/netd_shared/map_netd_uid_owner_map ] && count=$((count + 1))
    [ -e /sys/fs/bpf/netd_shared/map_netd_app_uid_stats_map ] && count=$((count + 1))
    [ -e /sys/fs/bpf/netd_shared/map_netd_cookie_tag_map ] && count=$((count + 1))
    [ -e /sys/fs/bpf/netd_shared/map_netd_configuration_map ] && count=$((count + 1))
    [ -e /sys/fs/bpf/netd_shared/map_netd_stats_map_A ] && count=$((count + 1))
    [ -e /sys/fs/bpf/netd_shared/map_netd_stats_map_B ] && count=$((count + 1))
    [ -e /sys/fs/bpf/netd_shared/map_netd_uid_permission_map ] && count=$((count + 1))
    [ -e /sys/fs/bpf/netd_shared/map_netd_iface_stats_map ] && count=$((count + 1))
    echo "$count"
}

# ============================================================
# Helper: check if specific BPF maps needed for stats exist
# ============================================================
bpf_stats_ready() {
    # For per-UID stats we need at minimum: app_uid_stats_map + configuration_map
    # For firewall we need: uid_owner_map
    if [ -e "$BPF_MAP_APP_STATS" ] && [ -e "$BPF_MAP_CONFIG" ]; then
        return 0
    fi
    return 1
}

# ============================================================
# PHASE 1: DIAGNOSTICS
# ============================================================
log "--- Phase 1: Diagnostics ---"

KVER=$(uname -r 2>/dev/null)
KMAJOR=$(echo "$KVER" | cut -d. -f1)
KMINOR=$(echo "$KVER" | cut -d. -f2)
KPATCH=$(echo "$KVER" | cut -d. -f3 | grep -oE '^[0-9]+')
log "Kernel: $KVER"

# BPF JIT
if [ -f /proc/sys/net/core/bpf_jit_enable ]; then
    log "BPF JIT: $(cat /proc/sys/net/core/bpf_jit_enable 2>/dev/null)"
else
    log "BPF JIT: sysctl not present"
fi

# Count BPF maps
MAP_COUNT=$(count_bpf_maps)
log "BPF maps present: $MAP_COUNT"

# Check individual critical maps
log "  uid_owner_map: $([ -e "$BPF_MAP_OWNER" ] && echo present || echo absent)"
log "  app_uid_stats_map: $([ -e "$BPF_MAP_APP_STATS" ] && echo present || echo absent)"
log "  cookie_tag_map: $([ -e "$BPF_MAP_COOKIE" ] && echo present || echo absent)"
log "  configuration_map: $([ -e "$BPF_MAP_CONFIG" ] && echo present || echo absent)"
log "  stats_map_A: $([ -e "$BPF_MAP_STATS_A" ] && echo present || echo absent)"
log "  stats_map_B: $([ -e "$BPF_MAP_STATS_B" ] && echo present || echo absent)"
log "  uid_permission_map: $([ -e "$BPF_MAP_UID_PERM" ] && echo present || echo absent)"
log "  iface_stats_map: $([ -e "$BPF_MAP_IFACE_STATS" ] && echo present || echo absent)"

# Full netd_shared contents
log "netd_shared contents:"
ls -la /sys/fs/bpf/netd_shared/ 2>/dev/null >> "$LOG"

# mainline_done marker
if [ -d /sys/fs/bpf/netd_shared/mainline_done ]; then
    log "mainline_done: PRESENT (netbpfload ran)"
else
    log "mainline_done: absent"
fi

# Service states
log "netd: $(getprop init.svc.netd 2>/dev/null)"
log "bpfloader: $(getprop init.svc.bpfloader 2>/dev/null)"

# ro.bpf.kver_override
KVER_PROP=$(getprop ro.bpf.kver_override 2>/dev/null)
log "ro.bpf.kver_override: ${KVER_PROP:-not set}"
log "Expected: ${CORRECT_KVER}"

# Settings
NSE=$(settings get global network_stats_enabled 2>/dev/null)
RNM=$(settings get global restricted_networking_mode 2>/dev/null)
log "network_stats_enabled: ${NSE:-null}"
log "restricted_networking_mode: ${RNM:-0}"

# SELinux
SELINUX=$(getenforce 2>/dev/null || echo unknown)
log "SELinux: $SELINUX"

# BPF capability
log "BPF capable (kernel assessment): $BPF_CAPABLE"

# Legacy interfaces
HAS_XTAGUID=0
HAS_UIDSTAT=0
if [ -f /proc/net/xt_qtaguid/stats ]; then
    HAS_XTAGUID=1
    log "xt_qtaguid: AVAILABLE ($(wc -l < /proc/net/xt_qtaguid/stats) lines)"
elif [ -c /dev/xt_qtaguid ]; then
    HAS_XTAGUID=2
    log "xt_qtaguid: device exists"
fi
if [ -d /proc/uid_stat ]; then
    HAS_UIDSTAT=1
    log "uid_stat: AVAILABLE ($(ls /proc/uid_stat/ 2>/dev/null | wc -l) UIDs)"
fi

# Capture BPF-related logcat messages
LOGCAT_BPF=$(logcat -d -b kernel,main 2>/dev/null | grep -iE 'bpf|netbpfload|BpfLoader|NetBpfLoad|BpfNetMaps|Firewall unavailable|Null bpf map' 2>/dev/null | tail -30)
if [ -n "$LOGCAT_BPF" ]; then
    log "BPF logcat messages:"
    echo "$LOGCAT_BPF" >> "$LOG"
fi

# ============================================================
# PHASE 2: BPF REPAIR (only if key maps missing)
# ============================================================
BPF_STATS_OK=0
if bpf_stats_ready; then
    BPF_STATS_OK=1
    log "--- Phase 2: BPF Maps Present (no repair needed) ---"
    # DO NOT restart bpfloader here - it would destroy working maps!
    # DO NOT delete mainline_done here - it prevents unnecessary re-loading!
else
    log "--- Phase 2: BPF Repair ---"

    # ---- Repair 1: Verify ro.bpf.kver_override is correct ----
    CURRENT_KVER_PROP=$(getprop ro.bpf.kver_override 2>/dev/null)
    if [ "$CURRENT_KVER_PROP" != "$CORRECT_KVER" ] && [ "$CORRECT_KVER" != "unknown" ]; then
        log "Repair 1: Fixing ro.bpf.kver_override"
        log "  Current: ${CURRENT_KVER_PROP:-not set} -> Expected: $CORRECT_KVER"
        if command -v resetprop_phh >/dev/null 2>&1; then
            resetprop_phh ro.bpf.kver_override "$CORRECT_KVER" 2>/dev/null
        elif command -v resetprop >/dev/null 2>&1; then
            resetprop ro.bpf.kver_override "$CORRECT_KVER" 2>/dev/null
        elif command -v magisk >/dev/null 2>&1; then
            magisk resetprop ro.bpf.kver_override "$CORRECT_KVER" 2>/dev/null
        fi
    else
        log "Repair 1: ro.bpf.kver_override already correct"
    fi

    # ---- Repair 2: Delete mainline_done and restart bpfloader ----
    # Only do this if maps are truly missing
    if [ -d /sys/fs/bpf/netd_shared/mainline_done ]; then
        rm -rf /sys/fs/bpf/netd_shared/mainline_done 2>/dev/null
        log "Repair 2: Deleted stale mainline_done"
    fi

    if [ -f /proc/sys/net/core/bpf_jit_enable ]; then
        echo 1 > /proc/sys/net/core/bpf_jit_enable 2>/dev/null
    fi

    log "Repair 2: Restarting bpfloader..."
    stop bpfloader 2>/dev/null
    sleep 3
    start bpfloader 2>/dev/null

    BPF_WAIT=0
    while [ "$(getprop init.svc.bpfloader 2>/dev/null)" = "running" ] && [ "$BPF_WAIT" -lt 45 ]; do
        sleep 1
        BPF_WAIT=$((BPF_WAIT + 1))
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
        log "  netd_shared:"
        ls -la /sys/fs/bpf/netd_shared/ 2>/dev/null >> "$LOG"
    fi

    # ---- Repair 3: CAPTURE DENIALS ONLY - NEVER setenforce 0 ----
    # CRITICAL: setenforce 0 causes firmware-level reboot on devices like
    # Infinity X / Huawei / Samsung with TIMA/RKP. NEVER call setenforce 0.
    if [ "$BPF_STATS_OK" -eq 0 ] && [ "$SELINUX" = "Enforcing" ]; then
        log "Repair 3: Capturing SELinux denials for diagnosis (permissive mode SKIPPED for safety)"
        # Capture current denials related to BPF
        dmesg 2>/dev/null | grep -i 'avc.*denied' | grep -iE 'bpf|netd|net_bw' | tail -30 >> "$LOG"
        logcat -d -b events 2>/dev/null | grep -iE 'avc.*denied.*bpf' | tail -20 >> "$LOG"
    fi
fi

# ============================================================
# PHASE 3: RESTART NETD TO PICK UP BPF MAPS
# ============================================================
log "--- Phase 3: Netd Restart ---"

# Even if maps exist, netd may have started before bpfloader finished.
# Restart netd so it re-opens the BPF maps.
log "Restarting netd to re-initialize BPF map access..."
setprop ctl.restart netd 2>/dev/null
NETD_WAIT=0
while [ "$(getprop init.svc.netd 2>/dev/null)" != "running" ] && [ "$NETD_WAIT" -lt 30 ]; do
    sleep 1
    NETD_WAIT=$((NETD_WAIT + 1))
done
sleep 5
log "Netd restarted (waited ${NETD_WAIT}s)"

# ============================================================
# PHASE 4: SETTINGS
# ============================================================
log "--- Phase 4: Settings ---"

# Ensure properties are set correctly via all available methods
RESETPROP_CMD=""
if command -v resetprop_phh >/dev/null 2>&1; then
    RESETPROP_CMD="resetprop_phh"
elif command -v resetprop >/dev/null 2>&1; then
    RESETPROP_CMD="resetprop"
elif command -v magisk >/dev/null 2>&1; then
    RESETPROP_CMD="magisk resetprop"
fi

if [ -n "$RESETPROP_CMD" ]; then
    $RESETPROP_CMD persist.sys.nobpf false 2>/dev/null
    $RESETPROP_CMD ro.net.stats 1 2>/dev/null
    $RESETPROP_CMD persist.sys.netstats 1 2>/dev/null
    if [ "$BPF_STATS_OK" -eq 0 ] && [ "$HAS_XTAGUID" -ge 1 ]; then
        $RESETPROP_CMD net.qtaguid_enabled 1 2>/dev/null
    fi
fi
log "Properties applied"

# Set network_stats_enabled with retry
log "Setting network_stats_enabled=1 with validation..."
ATTEMPT=0
MAX_ATTEMPTS=5
while [ "$ATTEMPT" -lt "$MAX_ATTEMPTS" ]; do
    ATTEMPT=$((ATTEMPT + 1))
    settings put global network_stats_enabled 1 2>/dev/null
    sleep 2

    NSE_NOW=$(settings get global network_stats_enabled 2>/dev/null)
    if [ "$NSE_NOW" = "1" ]; then
        log "network_stats_enabled=1 confirmed (attempt $ATTEMPT)"
        break
    else
        log "  attempt $ATTEMPT: got '$NSE_NOW' (expected '1'), retrying..."
    fi
done

# Final validation
NSE_FINAL=$(settings get global network_stats_enabled 2>/dev/null)
if [ "$NSE_FINAL" = "1" ]; then
    log "SUCCESS: network_stats_enabled=1"
else
    log "WARN: network_stats_enabled not 1 (final: $NSE_FINAL)"
    # Try via content provider
    if command -v content >/dev/null 2>&1; then
        content call --uri content://settings/global --method PUT \
            --arg network_stats_enabled --extra value:s:1 2>/dev/null
        sleep 2
        NSE_NOW=$(settings get global network_stats_enabled 2>/dev/null)
        log "network_stats_enabled after content provider: $NSE_NOW"
    fi
fi

# Force NetworkStatsService to refresh stats
log "Refreshing NetworkStatsService..."
if cmd netstats force-refresh 2>/dev/null; then
    log "  cmd netstats force-refresh: success"
else
    log "  cmd netstats force-refresh: not available"
fi

# ============================================================
# PHASE 5: FINAL VERIFICATION
# ============================================================
log "--- Phase 5: Final Verification ---"

# Re-check BPF maps after netd restart
FINAL_MAP_COUNT=$(count_bpf_maps)
log "FINAL BPF maps: $FINAL_MAP_COUNT"

FINAL_OWNER=0
if [ -e "$BPF_MAP_OWNER" ]; then
    FINAL_OWNER=1
    log "FINAL uid_owner_map: PRESENT"
else
    log "FINAL uid_owner_map: absent"
fi

FINAL_APPSTATS=0
if [ -e "$BPF_MAP_APP_STATS" ]; then
    FINAL_APPSTATS=1
    log "FINAL app_uid_stats_map: PRESENT"
else
    log "FINAL app_uid_stats_map: absent"
fi

FINAL_CONFIG=0
if [ -e "$BPF_MAP_CONFIG" ]; then
    FINAL_CONFIG=1
    log "FINAL configuration_map: PRESENT"
else
    log "FINAL configuration_map: absent"
fi

FINAL_XTAGUID=0
if [ -f /proc/net/xt_qtaguid/stats ]; then
    FINAL_XTAGUID=1
    XTAGUID_LINES=$(wc -l < /proc/net/xt_qtaguid/stats 2>/dev/null || echo "?")
    log "FINAL xt_qtaguid: AVAILABLE ($XTAGUID_LINES lines)"
fi

FINAL_UIDSTAT=0
if [ -d /proc/uid_stat ]; then
    FINAL_UIDSTAT=1
    UIDSTAT_COUNT=$(ls /proc/uid_stat/ 2>/dev/null | wc -l)
    log "FINAL uid_stat: AVAILABLE ($UIDSTAT_COUNT UIDs)"
fi

FINAL_NSE=$(settings get global network_stats_enabled 2>/dev/null)
log "FINAL network_stats_enabled: $FINAL_NSE"
log "FINAL ro.bpf.kver_override: $(getprop ro.bpf.kver_override 2>/dev/null)"

log ""
log "============================================"
log "DIAGNOSTIC SUMMARY:"
log "============================================"

# Determine which stats method is available
if [ "$FINAL_APPSTATS" -eq 1 ] && [ "$FINAL_CONFIG" -eq 1 ]; then
    log "BPF per-UID stats: INFRASTRUCTURE READY"
    log "  (maps exist; cgroup_skb programs need kernel >= 5.0 for per-UID data)"
elif [ "$FINAL_XTAGUID" -eq 1 ]; then
    log "xt_qtaguid per-UID stats: AVAILABLE (legacy)"
elif [ "$FINAL_UIDSTAT" -eq 1 ]; then
    log "uid_stat per-UID TCP stats: AVAILABLE (limited)"
else
    log "Per-UID stats: NOT AVAILABLE"
fi

if [ "$FINAL_NSE" = "1" ]; then
    log "Interface-level stats: ENABLED"
else
    log "Interface-level stats: DISABLED (got: $FINAL_NSE)"
fi

# Overall assessment
if [ "$FINAL_OWNER" -eq 1 ] && [ "$FINAL_APPSTATS" -eq 1 ]; then
    log ""
    log "RESULT: BPF maps are present and accessible"
    log "  - Per-app firewall: READY (uid_owner_map present)"
    log "  - Per-app traffic stats: READY (app_uid_stats_map present)"
    log "  - Traffic indicator should work on kernel >= 5.0"
    if [ "$KMAJOR" -lt 5 ]; then
        log "  - NOTE: Kernel $KMAJOR.$KMINOR < 5.0, cgroup_skb may not"
        log "    collect per-UID data. Interface-level stats will be used."
    fi
elif [ "$FINAL_XTAGUID" -eq 1 ]; then
    log ""
    log "RESULT: Legacy per-UID stats available"
    log "  Traffic indicator should show per-app traffic."
else
    log ""
    log "RESULT: No per-UID stats mechanism available"
    log "  Traffic indicator will show total traffic per interface."
fi

log "============================================"

# ============================================================
# PHASE 6: LIGHTWEIGHT WATCHDOG
# ============================================================
log ""
log "=== WATCHDOG STARTED (monitoring interval: 5 min) ==="
WATCHDOG_COUNT=0

while true; do
    sleep 300
    WATCHDOG_COUNT=$((WATCHDOG_COUNT + 1))

    # Verify critical setting
    NSE_CHECK=$(settings get global network_stats_enabled 2>/dev/null)
    if [ "$NSE_CHECK" != "1" ]; then
        settings put global network_stats_enabled 1 2>/dev/null
        log "[WD-$WATCHDOG_COUNT] Corrected network_stats_enabled (was: $NSE_CHECK)"
    fi

    # Verify BPF maps if they were working
    if [ "$FINAL_OWNER" -eq 1 ]; then
        if [ ! -e "$BPF_MAP_OWNER" ]; then
            log "[WD-$WATCHDOG_COUNT] WARNING: uid_owner_map lost! Restarting netd..."
            setprop ctl.restart netd 2>/dev/null
            sleep 10
            if [ -e "$BPF_MAP_OWNER" ]; then
                log "[WD-$WATCHDOG_COUNT] uid_owner_map restored"
            else
                log "[WD-$WATCHDOG_COUNT] uid_owner_map still absent"
            fi
        fi
    fi

    # Lightweight status log (every 6 cycles = 30 min)
    if [ "$(($WATCHDOG_COUNT % 6))" -eq 0 ]; then
        NOMAP=$([ -e "$BPF_MAP_OWNER" ] && echo "Y" || echo "N")
        NNETD=$(getprop init.svc.netd 2>/dev/null | cut -c1-3)
        NSE=$(settings get global network_stats_enabled 2>/dev/null)
        log "[WD-$WATCHDOG_COUNT] Status: owner=$NOMAP netd=$NNETD NSE=$NSE"
    fi
done
