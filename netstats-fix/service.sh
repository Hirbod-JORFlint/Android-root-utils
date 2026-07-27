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

    # ---- Repair 2: Delete mainline_done and restart bpfloader ----
    if [ -d /sys/fs/bpf/netd_shared/mainline_done ]; then
        rm -rf /sys/fs/bpf/netd_shared/mainline_done 2>/dev/null
        log "Repair 2: Deleted mainline_done"
    fi

    # Ensure BPF JIT is enabled
    if [ -f /proc/sys/net/core/bpf_jit_enable ]; then
        echo 1 > /proc/sys/net/core/bpf_jit_enable 2>/dev/null
    fi

    log "Repair 2: Restarting bpfloader..."
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
        elif [ "$KVER_MAJOR" -eq 4 ] && [ "$KVER_MINOR" -le 14 ]; then
            log "  Kernel $KVER has limited BPF support"
            log "  cgroup_skb may not be fully supported"
            log "  Some BPF programs may still load (non-cgroup_skb types)"
        else
            log "  Kernel $KVER should support BPF"
            log "  Check dmesg above for specific failure reasons"
        fi
    fi

    # ---- Final attempt: if BPF failed, try xt_qtaguid module ----
    if [ "$BPF_STATS_OK" -eq 0 ]; then
        log "Attempting xt_qtaguid module load..."

        # Check if module exists anywhere
        for MODPATH in /vendor/lib/modules /system/lib/modules /lib/modules; do
            if [ -d "$MODPATH" ]; then
                QTAG_MOD=$(find "$MODPATH" -name "xt_qtaguid*" -o -name "xt_qtaguid.ko" 2>/dev/null | head -1)
                if [ -n "$QTAG_MOD" ]; then
                    log "  Found xt_qtaguid module: $QTAG_MOD"
                    insmod "$QTAG_MOD" 2>/dev/null
                    if [ -f /proc/net/xt_qtaguid/stats ]; then
                        HAS_XTAGUID=1
                        log "  xt_qtaguid module loaded successfully!"
                    fi
                fi
            fi
        done

        # Try modprobe as well
        if [ "$HAS_XTAGUID" -eq 0 ]; then
            modprobe xt_qtaguid 2>/dev/null
            if [ -f /proc/net/xt_qtaguid/stats ]; then
                HAS_XTAGUID=1
                log "  xt_qtaguid loaded via modprobe"
            fi
        fi

        if [ "$HAS_XTAGUID" -eq 0 ]; then
            log "  xt_qtaguid module not available"
        fi
    fi
fi

# ============================================================
# PHASE 3: ENSURE SETTINGS
# ============================================================
log "--- Phase 3: Settings ---"

# Ensure properties are set correctly
if command -v resetprop_phh >/dev/null 2>&1; then
    resetprop_phh persist.sys.nobpf false 2>/dev/null
    resetprop_phh ro.net.stats 1 2>/dev/null
    resetprop_phh persist.sys.netstats 1 2>/dev/null
    if [ "$BPF_STATS_OK" -eq 0 ] && [ "$HAS_XTAGUID" -ge 1 ]; then
        resetprop_phh net.qtaguid_enabled 1 2>/dev/null
    fi
elif command -v resetprop >/dev/null 2>&1; then
    resetprop persist.sys.nobpf false 2>/dev/null
    resetprop ro.net.stats 1 2>/dev/null
    resetprop persist.sys.netstats 1 2>/dev/null
    if [ "$BPF_STATS_OK" -eq 0 ] && [ "$HAS_XTAGUID" -ge 1 ]; then
        resetprop net.qtaguid_enabled 1 2>/dev/null
    fi
elif command -v magisk >/dev/null 2>&1; then
    magisk resetprop persist.sys.nobpf false 2>/dev/null
    magisk resetprop ro.net.stats 1 2>/dev/null
    magisk resetprop persist.sys.netstats 1 2>/dev/null
    if [ "$BPF_STATS_OK" -eq 0 ] && [ "$HAS_XTAGUID" -ge 1 ]; then
        magisk resetprop net.qtaguid_enabled 1 2>/dev/null
    fi
fi
log "Properties applied"

# Restart netd to pick up property changes
log "Restarting netd..."
setprop ctl.restart netd 2>/dev/null
sleep 10
log "netd state: $(getprop init.svc.netd 2>/dev/null)"

# Set network_stats_enabled with retry
log "Setting network_stats_enabled=1..."
for i in 1 2 3 4 5; do
    settings put global network_stats_enabled 1 2>/dev/null
    sleep 2
    NSE_NOW=$(settings get global network_stats_enabled 2>/dev/null)
    if [ "$NSE_NOW" = "1" ]; then
        log "network_stats_enabled confirmed (attempt $i)"
        break
    fi
    log "  attempt $i: ${NSE_NOW:-empty}, retrying..."
done

# Final NSE check
NSE_NOW=$(settings get global network_stats_enabled 2>/dev/null)
if [ "$NSE_NOW" != "1" ]; then
    log "WARN: network_stats_enabled still not 1, trying content provider..."
    content call --uri content://settings/global --method PUT \
        --arg network_stats_enabled --extra value:s:1 2>/dev/null
    sleep 3
    NSE_NOW=$(settings get global network_stats_enabled 2>/dev/null)
    log "network_stats_enabled (content provider): ${NSE_NOW:-empty}"
fi

# Force NetworkStatsService to refresh stats (SAFE method, no SIGHUP)
log "Refreshing NetworkStatsService..."
if cmd netstats force-refresh 2>/dev/null; then
    log "  cmd netstats force-refresh: success"
else
    log "  cmd netstats force-refresh: not available"
fi

# ============================================================
# PHASE 4: FINAL VERIFICATION
# ============================================================
log "--- Phase 4: Verification ---"

FINAL_BPF=0
if [ -e "$BPF_MAP" ] && [ -e "$BPF_OWNER" ]; then
    FINAL_BPF=1
fi

FINAL_XTAGUID=0
if [ -f /proc/net/xt_qtaguid/stats ]; then
    FINAL_XTAGUID=1
fi

FINAL_UIDSTAT=0
if [ -d /proc/uid_stat ]; then
    FINAL_UIDSTAT=1
fi

FINAL_NSE=$(settings get global network_stats_enabled 2>/dev/null)

log "FINAL BPF maps: $([ "$FINAL_BPF" -eq 1 ] && echo PRESENT || echo absent)"
log "FINAL xt_qtaguid: $([ "$FINAL_XTAGUID" -eq 1 ] && echo AVAILABLE || echo absent)"
log "FINAL uid_stat: $([ "$FINAL_UIDSTAT" -eq 1 ] && echo AVAILABLE || echo absent)"
log "FINAL network_stats_enabled: ${FINAL_NSE:-empty}"
log "FINAL ro.bpf.kver_override: $(getprop ro.bpf.kver_override 2>/dev/null)"

log ""
log "============================================"

if [ "$FINAL_BPF" -eq 1 ]; then
    log "RESULT: BPF maps PRESENT"
    log "Per-UID traffic stats are WORKING."
    log "Traffic indicator should show per-app traffic."
elif [ "$FINAL_XTAGUID" -eq 1 ]; then
    log "RESULT: xt_qtaguid AVAILABLE"
    log "Per-UID stats available via legacy fallback."
    log "Traffic indicator should show per-app traffic."
elif [ "$FINAL_UIDSTAT" -eq 1 ]; then
    log "RESULT: uid_stat AVAILABLE"
    log "Per-UID TCP stats available."
    log "Traffic indicator may show per-app traffic."
else
    log "RESULT: No per-UID stats source available"
    log ""
    log "This kernel ($(uname -r)) cannot support BPF-based"
    log "per-UID network stats, and no legacy fallback exists."
    log ""
    log "Interface-level stats are active (network_stats_enabled=1)."
    log "The traffic indicator will show TOTAL traffic per interface."
    log ""
    log "POSSIBLE SOLUTIONS:"
    log "1. Flash a ROM with kernel >= 5.4 (full BPF support)"
    log "2. Check if xt_qtaguid module can be compiled for this kernel"
    log "3. Use a different GSI with kernel >= 5.10"
fi

log "============================================"

# ============================================================
# PHASE 5: WATCHDOG
# ============================================================

log "=== Watchdog started (every 5 min) ==="
WATCHDOG_COUNT=0
while true; do
    sleep 300
    WATCHDOG_COUNT=$((WATCHDOG_COUNT + 1))

    # Re-verify network_stats_enabled
    NSE=$(settings get global network_stats_enabled 2>/dev/null)
    if [ "$NSE" != "1" ]; then
        settings put global network_stats_enabled 1 2>/dev/null
        log "Watchdog [$WATCHDOG_COUNT]: corrected network_stats_enabled"
    fi

    # If BPF maps exist, check they're still there
    if [ "$FINAL_BPF" -eq 1 ]; then
        if [ ! -e "$BPF_MAP" ] || [ ! -e "$BPF_OWNER" ]; then
            log "Watchdog [$WATCHDOG_COUNT]: BPF maps LOST! Restarting bpfloader..."
            rm -rf /sys/fs/bpf/netd_shared/mainline_done 2>/dev/null
            stop bpfloader 2>/dev/null
            sleep 1
            start bpfloader 2>/dev/null
            sleep 10
            if [ -e "$BPF_MAP" ] && [ -e "$BPF_OWNER" ]; then
                log "Watchdog [$WATCHDOG_COUNT]: BPF maps restored"
            else
                log "Watchdog [$WATCHDOG_COUNT]: BPF maps still missing"
            fi
        fi
    fi

    # Periodic stats refresh
    if [ "$((WATCHDOG_COUNT % 6))" -eq 0 ]; then
        cmd netstats force-refresh 2>/dev/null
        log "Watchdog [$WATCHDOG_COUNT]: periodic stats refresh"
    fi

    # Light status log
    NBPF=$([ -e "$BPF_MAP" ] && echo P || echo A)
    NNETD=$(getprop init.svc.netd 2>/dev/null)
    NSE=$(settings get global network_stats_enabled 2>/dev/null)
    log "Watchdog [$WATCHDOG_COUNT]: BPF=$NBPF netd=$NNETD NSE=$NSE"

    # If BPF maps suddenly appeared (e.g., after kernel module load)
    if [ "$FINAL_BPF" -eq 0 ] && [ "$NBPF" = "P" ]; then
        log "Watchdog [$WATCHDOG_COUNT]: BPF maps appeared! System now has per-UID stats."
        FINAL_BPF=1
    fi
done
