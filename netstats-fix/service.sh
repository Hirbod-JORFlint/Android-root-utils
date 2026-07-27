#!/system/bin/sh
# service.sh - Late_start: repair network stats on all devices
#
# Strategy:
#   1. Verify BPF maps (may have been created by post-fs-data retry)
#   2. If not, try one more bpfloader restart with correct properties
#   3. Ensure network_stats_enabled=1
#   4. Set up watchdog for persistent settings
#
# Key insight: The APEX's netbpfload has BPF program variants for kernels
# 4.9-5.10+. If ro.bpf.kver_override is set correctly (to the ACTUAL
# kernel version), netbpfload loads the right variant. Our post-fs-data.sh
# handles this. This script verifies and does final recovery.

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
# PATHS
# ============================================================
BPF_MAP="/sys/fs/bpf/netd_shared/map_netd_uid_stats_map"
BPF_OWNER="/sys/fs/bpf/netd_shared/map_netd_uid_owner_map"
BPF_CAPABLE=$(cat /data/local/tmp/.bpf_capable 2>/dev/null || echo 0)
CORRECT_KVER=$(cat /data/local/tmp/.bpf_kver 2>/dev/null || echo unknown)

# ============================================================
# PHASE 1: DIAGNOSTICS
# ============================================================
log "--- Phase 1: Diagnostics ---"

KVER=$(uname -r 2>/dev/null)
KMAJOR=$(echo "$KVER" | cut -d. -f1)
KMINOR=$(echo "$KVER" | cut -d. -f2)
log "Kernel: $KVER"

# BPF JIT
if [ -f /proc/sys/net/core/bpf_jit_enable ]; then
    log "BPF JIT: $(cat /proc/sys/net/core/bpf_jit_enable 2>/dev/null)"
else
    log "BPF JIT: sysctl not present"
fi

# BPF maps
BPF_STATS_OK=0
if [ -e "$BPF_MAP" ] && [ -e "$BPF_OWNER" ]; then
    BPF_STATS_OK=1
    log "BPF maps: PRESENT"
else
    log "BPF maps: MISSING"
    log "  uid_stats_map: $([ -e "$BPF_MAP" ] && echo present || echo absent)"
    log "  uid_owner_map: $([ -e "$BPF_OWNER" ] && echo present || echo absent)"
fi

# netd_shared contents
log "netd_shared contents:"
ls -la /sys/fs/bpf/netd_shared/ 2>/dev/null >> "$LOG"

# mainline_done marker
if [ -d /sys/fs/bpf/netd_shared/mainline_done ]; then
    log "mainline_done: PRESENT (netbpfload ran)"
else
    log "mainline_done: absent (clean state)"
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

# Capture BPF-related dmesg
DMESG_RESTRICT=$(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null)
log "dmesg_restrict: ${DMESG_RESTRICT:-unknown}"

BPF_DMESG=$(dmesg 2>/dev/null | grep -iE 'bpf|netd.*map|bpfloader|netbpfload|BpfLoader|NetBpfLoad' 2>/dev/null | tail -30)
if [ -n "$BPF_DMESG" ]; then
    log "BPF kernel messages:"
    echo "$BPF_DMESG" >> "$LOG"
else
    # Fallback to logcat
    LOGCAT_BPF=$(logcat -d -b kernel,main 2>/dev/null | grep -iE 'bpf|netbpfload|BpfLoader|NetBpfLoad' 2>/dev/null | tail -20)
    if [ -n "$LOGCAT_BPF" ]; then
        log "BPF logcat messages:"
        echo "$LOGCAT_BPF" >> "$LOG"
    else
        log "No BPF messages found in dmesg or logcat"
    fi
fi

# ============================================================
# PHASE 2: BPF REPAIR (only if maps missing and recovery is possible)
# ============================================================

if [ "$BPF_STATS_OK" -eq 0 ]; then
    log "--- Phase 2: BPF Repair ---"

    # ---- Repair 1: Verify ro.bpf.kver_override is correct ----
    # post-fs-data.sh should have set this, but verify
    CURRENT_KVER_PROP=$(getprop ro.bpf.kver_override 2>/dev/null)
    if [ "$CURRENT_KVER_PROP" != "$CORRECT_KVER" ] && [ "$CORRECT_KVER" != "unknown" ]; then
        log "Repair 1: Fixing ro.bpf.kver_override"
        log "  Current: ${CURRENT_KVER_PROP:-not set}"
        log "  Expected: $CORRECT_KVER"
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

    # ---- Repair 2: Restart bpfloader (mainline_done deleted in post-fs-data) ----
    if [ -d /sys/fs/bpf/netd_shared/mainline_done ]; then
        rm -rf /sys/fs/bpf/netd_shared/mainline_done 2>/dev/null
        log "Repair 2: Deleted stale mainline_done"
    fi

    # Ensure BPF JIT is enabled if available
    if [ -f /proc/sys/net/core/bpf_jit_enable ]; then
        echo 1 > /proc/sys/net/core/bpf_jit_enable 2>/dev/null
    fi

    log "Repair 2: Restarting bpfloader (attempt 1)..."
    stop bpfloader 2>/dev/null
    sleep 2
    start bpfloader 2>/dev/null

    # Wait for completion
    BPF_WAIT=0
    while [ "$(getprop init.svc.bpfloader 2>/dev/null)" = "running" ] && [ "$BPF_WAIT" -lt 30 ]; do
        sleep 1
        BPF_WAIT=$((BPF_WAIT + 1))
    done
    log "Repair 2: bpfloader completed after ${BPF_WAIT}s"
    sleep 3

    if [ -e "$BPF_MAP" ] && [ -e "$BPF_OWNER" ]; then
        BPF_STATS_OK=1
        log "Repair 2 SUCCESS: BPF maps present!"
    else
        log "Repair 2: BPF maps still missing"
        log "  netd_shared:"
        ls -la /sys/fs/bpf/netd_shared/ 2>/dev/null >> "$LOG"
    fi

    # ---- Repair 3: Try with SELinux permissive (diagnostic only) ----
    if [ "$BPF_STATS_OK" -eq 0 ] && [ "$SELINUX" = "Enforcing" ]; then
        log "Repair 3: Testing with SELinux permissive..."
        setenforce 0 2>/dev/null

        # Clean and retry
        rm -rf /sys/fs/bpf/netd_shared/mainline_done 2>/dev/null
        stop bpfloader 2>/dev/null
        sleep 1
        start bpfloader 2>/dev/null

        BPF_WAIT=0
        while [ "$(getprop init.svc.bpfloader 2>/dev/null)" = "running" ] && [ "$BPF_WAIT" -lt 30 ]; do
            sleep 1
            BPF_WAIT=$((BPF_WAIT + 1))
        done
        sleep 3

        if [ -e "$BPF_MAP" ] && [ -e "$BPF_OWNER" ]; then
            BPF_STATS_OK=1
            log "Repair 3 SUCCESS: BPF maps present with SELinux permissive!"
            log "  Capture denials for permanent sepolicy fix:"
            dmesg 2>/dev/null | grep -i 'avc.*denied' | grep -i bpf | tail -20 >> "$LOG"
        else
            log "Repair 3: BPF maps still missing even with SELinux permissive"
            log "  This kernel likely cannot support the required BPF programs"
        fi

        setenforce 1 2>/dev/null
        log "  SELinux restored to Enforcing"
    fi

    # ---- Repair 4: Check if ro.bpf.kver_override was the issue ----
    if [ "$BPF_STATS_OK" -eq 0 ]; then
        log "Repair 4: Analyzing failure reason..."
        KVER_MAJOR=$(echo "$KVER" | cut -d. -f1)
        KVER_MINOR=$(echo "$KVER" | cut -d. -f2)

        if [ "$KVER_MAJOR" -lt 4 ] || { [ "$KVER_MAJOR" -eq 4 ] && [ "$KVER_MINOR" -lt 9 ]; }; then
            log "  Kernel $KVER is too old for any BPF support"
            log "  The APEX's netbpfload cannot load programs on this kernel"
        elif [ "$KVER_MAJOR" -eq 4 ] && [ "$KVER_MINOR" -lt 15 ]; then
            log "  Kernel $KVER has limited BPF support"
            log "  cgroup_skb not fully supported in kernel < 5.0"
            log "  Interface-level stats will be used as fallback"
        elif [ "$KVER_MAJOR" -eq 4 ] && [ "$KVER_MINOR" -le 19 ]; then
            log "  Kernel $KVER should support BPF (4.15-4.19)"
            log "  Check dmesg above for specific failure reasons"
        else
            log "  Kernel $KVER should support full BPF (>= 5.0)"
            log "  Check dmesg above for specific failure reasons"
        fi
    fi

    # ---- Final attempt: if BPF failed, diagnostics complete ----
    if [ "$BPF_STATS_OK" -eq 0 ]; then
        log "Repair complete: BPF maps could not be loaded"
        log "Continuing with legacy fallback in Phase 3..."
    fi
fi

# ============================================================
# PHASE 3: LEGACY FALLBACK
# ============================================================
log "--- Phase 3: Legacy Fallback ---"

# Check for legacy per-UID interfaces
if [ "$BPF_STATS_OK" -eq 0 ]; then
    # xt_qtaguid is the primary legacy fallback
    if [ "$HAS_XTAGUID" -eq 0 ]; then
        log "Fallback: Attempting xt_qtaguid module load..."
        QTAG_FOUND=0
        
        # Check if module exists anywhere
        for MODPATH in /vendor/lib/modules /system/lib/modules /lib/modules; do
            if [ -d "$MODPATH" ]; then
                QTAG_MOD=$(find "$MODPATH" -name "*xt_qtaguid*" 2>/dev/null | head -1)
                if [ -n "$QTAG_MOD" ]; then
                    log "  Found xt_qtaguid module: $QTAG_MOD"
                    insmod "$QTAG_MOD" 2>/dev/null
                    sleep 1
                    if [ -f /proc/net/xt_qtaguid/stats ]; then
                        HAS_XTAGUID=1
                        QTAG_FOUND=1
                        log "  xt_qtaguid module loaded successfully!"
                        break
                    fi
                fi
            fi
        done
        
        # Try modprobe as well
        if [ "$QTAG_FOUND" -eq 0 ]; then
            if modprobe xt_qtaguid 2>/dev/null; then
                sleep 1
                if [ -f /proc/net/xt_qtaguid/stats ]; then
                    HAS_XTAGUID=1
                    log "  xt_qtaguid loaded via modprobe"
                fi
            fi
        fi
        
        if [ "$HAS_XTAGUID" -eq 0 ]; then
            log "  xt_qtaguid module not available"
        fi
    fi
    
    # uid_stat is secondary fallback
    if [ "$HAS_UIDSTAT" -eq 0 ] && [ -d /proc/uid_stat ]; then
        HAS_UIDSTAT=1
        log "Fallback: uid_stat available"
    fi
fi

# Determine which fallback is in use
if [ "$BPF_STATS_OK" -eq 0 ]; then
    if [ "$HAS_XTAGUID" -ge 1 ]; then
        log "Fallback method: xt_qtaguid (per-UID)"
    elif [ "$HAS_UIDSTAT" -eq 1 ]; then
        log "Fallback method: uid_stat (per-UID TCP)"
    else
        log "Fallback method: none (interface-level only)"
    fi
fi

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

# Restart netd to pick up property changes
log "Restarting netd..."
setprop ctl.restart netd 2>/dev/null
sleep 10
log "netd state: $(getprop init.svc.netd 2>/dev/null)"

# Set network_stats_enabled with aggressive retry (FIX for Infinity X issue)
log "Setting network_stats_enabled=1 with validation..."
ATTEMPT=0
MAX_ATTEMPTS=8
while [ "$ATTEMPT" -lt "$MAX_ATTEMPTS" ]; do
    ATTEMPT=$((ATTEMPT + 1))
    settings put global network_stats_enabled 1 2>/dev/null
    sleep 1
    
    NSE_NOW=$(settings get global network_stats_enabled 2>/dev/null)
    if [ "$NSE_NOW" = "1" ]; then
        log "network_stats_enabled=1 confirmed (attempt $ATTEMPT)"
        break
    elif [ -n "$NSE_NOW" ]; then
        log "  attempt $ATTEMPT: got '$NSE_NOW' (expected '1'), retrying..."
    else
        log "  attempt $ATTEMPT: got empty/null, retrying..."
    fi
    
    # Wait longer between attempts
    sleep 2
done

# Final validation
NSE_FINAL=$(settings get global network_stats_enabled 2>/dev/null)
if [ "$NSE_FINAL" = "1" ]; then
    log "SUCCESS: network_stats_enabled=1 (final: $NSE_FINAL)"
else
    log "WARN: network_stats_enabled not 1 (final: $NSE_FINAL), trying alternatives..."
    
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
# PHASE 5: VERIFICATION & DIAGNOSTICS
# ============================================================
log "--- Phase 5: Verification & Diagnostics ---"

FINAL_BPF=0
if [ -e "$BPF_MAP" ] && [ -e "$BPF_OWNER" ]; then
    FINAL_BPF=1
    log "FINAL BPF maps: PRESENT"
else
    log "FINAL BPF maps: absent"
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

if [ "$FINAL_BPF" -eq 1 ]; then
    log "✓ BPF per-UID stats: WORKING"
elif [ "$FINAL_XTAGUID" -eq 1 ]; then
    log "✓ xt_qtaguid per-UID stats: WORKING (legacy)"
elif [ "$FINAL_UIDSTAT" -eq 1 ]; then
    log "◐ uid_stat per-UID TCP stats: AVAILABLE (limited)"
else
    log "✗ Per-UID stats: NOT AVAILABLE"
fi

if [ "$FINAL_NSE" = "1" ]; then
    log "✓ Interface-level stats: ENABLED"
else
    log "✗ Interface-level stats: DISABLED (got: $FINAL_NSE)"
fi

# Overall assessment
if [ "$FINAL_BPF" -eq 1 ] || [ "$FINAL_XTAGUID" -eq 1 ]; then
    log ""
    log "RESULT: PER-UID STATS ARE AVAILABLE"
    log "Traffic indicator should show per-app traffic."
elif [ "$FINAL_NSE" = "1" ]; then
    log ""
    log "RESULT: PARTIAL (interface-level only)"
    log "Traffic indicator will show total traffic per interface."
    log "Per-app traffic will not be visible."
    log ""
    log "RECOMMENDED FIXES:"
    log "  1. Flash a ROM with kernel >= 5.4"
    log "  2. Compile xt_qtaguid module for this kernel"
    log "  3. Check with your device maintainer for BPF support"
else
    log ""
    log "RESULT: STATS COLLECTION DISABLED"
    log "Traffic indicator will not work."
fi

log "============================================"

# ============================================================
# PHASE 6: WATCHDOG (persistent monitoring)
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
    if [ "$FINAL_BPF" -eq 1 ]; then
        if [ ! -e "$BPF_MAP" ] || [ ! -e "$BPF_OWNER" ]; then
            log "[WD-$WATCHDOG_COUNT] WARNING: BPF maps lost! Attempting recovery..."
            rm -rf /sys/fs/bpf/netd_shared/mainline_done 2>/dev/null
            stop bpfloader 2>/dev/null
            sleep 2
            start bpfloader 2>/dev/null
            
            WAIT=0
            while [ "$(getprop init.svc.bpfloader 2>/dev/null)" = "running" ] && [ "$WAIT" -lt 20 ]; do
                sleep 1
                WAIT=$((WAIT + 1))
            done
            sleep 2
            
            if [ -e "$BPF_MAP" ] && [ -e "$BPF_OWNER" ]; then
                log "[WD-$WATCHDOG_COUNT] BPF maps restored successfully"
            else
                log "[WD-$WATCHDOG_COUNT] BPF maps recovery failed"
                FINAL_BPF=0
            fi
        fi
    fi
    
    # Periodic statistics refresh
    if [ "$(($WATCHDOG_COUNT % 6))" -eq 0 ]; then
        if cmd netstats force-refresh 2>/dev/null; then
            :  # silent success
        fi
    fi
    
    # Lightweight status log (every 6 cycles = 30 min)
    if [ "$(($WATCHDOG_COUNT % 6))" -eq 0 ]; then
        NBPF=$([ -e "$BPF_MAP" ] && echo "P" || echo "A")
        NNETD=$(getprop init.svc.netd 2>/dev/null | cut -c1-3)
        NSE=$(settings get global network_stats_enabled 2>/dev/null)
        log "[WD-$WATCHDOG_COUNT] Status: BPF=$NBPF netd=$NNETD NSE=$NSE"
    fi
    
    # Detect if BPF maps appeared after a kernel module was loaded
    if [ "$FINAL_BPF" -eq 0 ] && [ -e "$BPF_MAP" ] && [ -e "$BPF_OWNER" ]; then
        log "[WD-$WATCHDOG_COUNT] BPF maps detected! System now has full per-UID stats."
        FINAL_BPF=1
    fi
done
