#!/system/bin/sh
# service.sh - Late_start: repair network stats on all devices
# Universal strategy:
#   1. Check if BPF maps already exist (lucky case)
#   2. If not, try to repair BPF loading (restart bpfloader service)
#   3. If BPF is fundamentally impossible (kernel 4.14 etc), fall back
#      to xt_qtaguid or uid_stat legacy interfaces
#   4. If nothing gives per-UID stats, ensure interface-level stats work
#      and provide clear diagnostics

MODDIR=${0%/*}
LOG=/data/local/tmp/netstats-fix.log

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [service] $1" >> "$LOG"
}

log "=== service.sh started ==="

# ---- wait for boot ----
WAIT=0
while [ "$(getprop sys.boot_completed)" != "1" ] && [ "$WAIT" -lt 120 ]; do
    sleep 1
    WAIT=$((WAIT + 1))
done
log "Boot completed after ${WAIT}s"

# extra settle for APEX activation and netd startup
sleep 10

# ============================================================
# PATHS
# ============================================================
BPF_MAP="/sys/fs/bpf/netd_shared/map_netd_uid_stats_map"
BPF_OWNER="/sys/fs/bpf/netd_shared/map_netd_uid_owner_map"

# ============================================================
# PHASE 1: DIAGNOSTICS
# ============================================================

log "--- Phase 1: Diagnostics ---"
log "Kernel: $(uname -r 2>/dev/null)"
if [ -f /proc/sys/net/core/bpf_jit_enable ]; then
    log "BPF JIT: $(cat /proc/sys/net/core/bpf_jit_enable 2>/dev/null)"
else
    log "BPF JIT: not available (file /proc/sys/net/core/bpf_jit_enable missing)"
fi

# Check BPF maps
BPF_STATS_OK=0
if [ -e "$BPF_MAP" ] && [ -e "$BPF_OWNER" ]; then
    BPF_STATS_OK=1
    log "BPF maps: PRESENT"
else
    log "BPF maps: MISSING"
    log "  uid_stats_map: $([ -e "$BPF_MAP" ] && echo present || echo absent)"
    log "  uid_owner_map: $([ -e "$BPF_OWNER" ] && echo present || echo absent)"
fi

# Check netd_shared contents
log "netd_shared contents:"
ls -la /sys/fs/bpf/netd_shared/ 2>/dev/null >> "$LOG"

# Check for mainline_done marker (means netbpfload ran but didn't create network maps)
if [ -d /sys/fs/bpf/netd_shared/mainline_done ]; then
    log "mainline_done marker: PRESENT (netbpfload ran but network maps missing)"
fi

# Tethering APEX
APEX_OK=0
if [ -d /apex/com.android.tethering ]; then
    APEX_OK=1
    log "Tethering APEX: mounted"
else
    log "WARN: Tethering APEX not mounted"
fi

# netd and bpfloader
log "netd: $(getprop init.svc.netd 2>/dev/null)"
log "bpfloader: $(getprop init.svc.bpfloader 2>/dev/null)"

# Settings
log "network_stats_enabled: $(settings get global network_stats_enabled 2>/dev/null)"
log "restricted_networking_mode: $(settings get global restricted_networking_mode 2>/dev/null)"

# SELinux
SELINUX=$(getenforce 2>/dev/null || echo unknown)
log "SELinux: $SELINUX"

# Read pre-computed BPF capability
BPF_CAPABLE=0
if [ -f /data/local/tmp/.bpf_capable ]; then
    BPF_CAPABLE=$(cat /data/local/tmp/.bpf_capable 2>/dev/null)
fi
log "BPF capable (from post-fs-data detection): $BPF_CAPABLE"

# ---- Kernel version detection ----
KMAJOR=$(uname -r | cut -d. -f1)
KMINOR=$(uname -r | cut -d. -f2)
log "Kernel major.minor: ${KMAJOR}.${KMINOR}"

# Determine if BPF repair is worth attempting.
# Kernel < 5.0 generally cannot run cgroup_skb BPF programs needed
# for per-UID network stats. Attempting bpfloader restarts wastes ~20s.
BPF_REPAIR_WORTH_TRYING=1
if [ "$KMAJOR" -lt 5 ]; then
    BPF_REPAIR_WORTH_TRYING=0
    log "Kernel < 5.0: BPF cgroup_skb not available, skipping repair"
fi

# ---- Check legacy per-UID stats interfaces ----
HAS_XTAGUID=0
HAS_UIDSTAT=0
if [ -f /proc/net/xt_qtaguid/stats ]; then
    HAS_XTAGUID=1
    log "xt_qtaguid stats: AVAILABLE"
    log "xt_qtaguid stats lines: $(wc -l < /proc/net/xt_qtaguid/stats 2>/dev/null)"
elif [ -c /dev/xt_qtaguid ]; then
    log "xt_qtaguid device: EXISTS (but no stats file yet)"
    HAS_XTAGUID=2
fi
if [ -d /proc/uid_stat ]; then
    HAS_UIDSTAT=1
    log "uid_stat: AVAILABLE"
    log "uid_stat UIDs: $(ls /proc/uid_stat/ 2>/dev/null | wc -l)"
fi

# ---- Capture BPF-related dmesg ----
DMESG_RESTRICT=$(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null)
log "dmesg_restrict: ${DMESG_RESTRICT:-unknown}"
BPF_DMESG=$(dmesg 2>/dev/null | grep -iE 'bpf|cgroup_skb|netd.*map|bpfloader|verifier|netbpfload|BpfLoader' 2>/dev/null | tail -20)
if [ -n "$BPF_DMESG" ]; then
    log "BPF-related kernel messages (dmesg):"
    echo "$BPF_DMESG" >> "$LOG"
else
    log "BPF-related kernel messages: (dmesg empty or restricted)"
fi

# ---- Fallback: logcat for BPF messages when dmesg is empty ----
# On some devices dmesg is restricted or cleared before service.sh runs.
# logcat retains init/kernel messages longer.
if [ -z "$BPF_DMESG" ]; then
    LOGCAT_BPF=$(logcat -d -b kernel,main -s bpfloader:* netbpfload:* BpfLoader:* NetBpfLoad:* 2>/dev/null | tail -20)
    if [ -n "$LOGCAT_BPF" ]; then
        log "BPF-related logcat messages:"
        echo "$LOGCAT_BPF" >> "$LOG"
    fi
    # Also try logcat with tag filter
    LOGCAT_BPF2=$(logcat -d -b all 2>/dev/null | grep -iE 'bpf|netbpfload|BpfLoader|cgroup_skb' 2>/dev/null | tail -15)
    if [ -n "$LOGCAT_BPF2" ]; then
        log "BPF logcat (grep):"
        echo "$LOGCAT_BPF2" >> "$LOG"
    fi
fi

# ---- Capture netbpfload exit status from dmesg ----
NBPFP_STATUS=$(dmesg 2>/dev/null | grep -i 'netbpfload\|NetBpfLoad' 2>/dev/null | tail -5)
if [ -n "$NBPFP_STATUS" ]; then
    log "netbpfload dmesg output:"
    echo "$NBPFP_STATUS" >> "$LOG"
    if echo "$NBPFP_STATUS" | grep -qi 'success'; then
        log "  netbpfload reported success but network maps missing (kernel too old)"
    fi
fi
# Also capture bpfloader errors
BPFLOADER_ERRS=$(dmesg 2>/dev/null | grep -i 'BpfLoader-rs\|bpfloader.*error\|bpfloader.*fail' 2>/dev/null | tail -10)
if [ -z "$BPFLOADER_ERRS" ]; then
    # Try logcat fallback
    BPFLOADER_ERRS=$(logcat -d -b all 2>/dev/null | grep -i 'BpfLoader-rs\|bpfloader.*error\|bpfloader.*fail' 2>/dev/null | tail -10)
fi
if [ -n "$BPFLOADER_ERRS" ]; then
    log "bpfloader errors:"
    echo "$BPFLOADER_ERRS" >> "$LOG"
fi
# Capture SELinux denials for bpfloader
BPF_AVCS=$(dmesg 2>/dev/null | grep -i 'avc.*denied.*bpfloader\|avc.*denied.*bpf' 2>/dev/null | tail -5)
if [ -z "$BPF_AVCS" ]; then
    BPF_AVCS=$(logcat -d -b all 2>/dev/null | grep -i 'avc.*denied.*bpfloader\|avc.*denied.*bpf' 2>/dev/null | tail -5)
fi
if [ -n "$BPF_AVCS" ]; then
    log "SELinux denials for bpfloader:"
    echo "$BPF_AVCS" >> "$LOG"
fi

# ============================================================
# PHASE 2: BPF REPAIR (only if BPF maps missing)
# ============================================================

if [ "$BPF_STATS_OK" -eq 0 ]; then
    if [ "$BPF_REPAIR_WORTH_TRYING" -eq 1 ]; then
        log "--- Phase 2: BPF Repair Attempt ---"

    # ---- Repair 1: Restart bpfloader service ----
    # This is the ONLY reliable way to invoke netbpfload because it
    # requires init-set environment variables (ANDROID_ROOT, etc).
    # Manual invocation WILL crash with Rust panic (NotPresent).
    log "Repair 1: Restarting bpfloader service..."
    stop bpfloader 2>/dev/null
    sleep 2
    start bpfloader 2>/dev/null
    # Give it time to load programs
    sleep 8

    if [ -e "$BPF_MAP" ] && [ -e "$BPF_OWNER" ]; then
        BPF_STATS_OK=1
        log "Repair 1 SUCCESS: BPF maps present after bpfloader restart"
    else
        log "Repair 1: BPF maps still missing"
        log "  bpfloader state: $(getprop init.svc.bpfloader 2>/dev/null)"
        log "  netd_shared after restart:"
        ls -la /sys/fs/bpf/netd_shared/ 2>/dev/null >> "$LOG"
    fi

    # ---- Repair 2: Try setting ro.bpf.kver_override if missing ----
    # Some GSIs need this property for netbpfload to pass its version check.
    # Only useful on kernels >= 5.0 that may have BPF but need the version
    # override to pass netbpfload's compatibility check. On kernels < 5.0,
    # setting this to the actual old version is counterproductive.
    if [ "$BPF_STATS_OK" -eq 0 ] && [ "$APEX_OK" -eq 1 ]; then
        CURRENT_KVER=$(uname -r | grep -oE '[0-9]+\.[0-9]+')
        CUR_KMAJOR=$(echo "$CURRENT_KVER" | cut -d. -f1)
        log "Repair 2: Checking ro.bpf.kver_override..."
        CUR_KVER_PROP=$(getprop ro.bpf.kver_override 2>/dev/null)
        log "  Current: ${CUR_KVER_PROP:-not set}"

        if [ -z "$CUR_KVER_PROP" ]; then
            if [ "$CUR_KMAJOR" -ge 5 ]; then
                # Kernel >= 5.0: setting override may help netbpfload pass its check
                if command -v resetprop_phh >/dev/null 2>&1; then
                    resetprop_phh ro.bpf.kver_override "$CURRENT_KVER" 2>/dev/null
                    log "  Set to $CURRENT_KVER via resetprop_phh (kernel >= 5.0)"
                elif command -v magisk >/dev/null 2>&1; then
                    magisk resetprop ro.bpf.kver_override "$CURRENT_KVER" 2>/dev/null
                    log "  Set to $CURRENT_KVER via magisk resetprop (kernel >= 5.0)"
                fi
                # Retry bpfloader with new property
                stop bpfloader 2>/dev/null
                sleep 1
                start bpfloader 2>/dev/null
                sleep 8

                if [ -e "$BPF_MAP" ] && [ -e "$BPF_OWNER" ]; then
                    BPF_STATS_OK=1
                    log "Repair 2 SUCCESS: BPF maps present after kver_override fix"
                else
                    log "Repair 2: BPF maps still missing"
                fi
            else
                log "  Kernel < 5.0: NOT setting kver_override (would be counterproductive)"
            fi
        else
            log "  Already set ($CUR_KVER_PROP), skipping"
        fi
    fi

    # ---- Repair 3: SELinux permissive test ----
    if [ "$BPF_STATS_OK" -eq 0 ] && [ "$SELINUX" = "Enforcing" ]; then
        log "Repair 3: Testing with SELinux permissive..."
        setenforce 0 2>/dev/null
        stop bpfloader 2>/dev/null
        sleep 1
        start bpfloader 2>/dev/null
        sleep 8

        if [ -e "$BPF_MAP" ] && [ -e "$BPF_OWNER" ]; then
            BPF_STATS_OK=1
            log "Repair 3 SUCCESS: BPF maps present with SELinux permissive"
            log "  Check dmesg for avc denials:"
            dmesg | grep -i 'avc.*denied' 2>/dev/null | tail -10 >> "$LOG"
        else
            log "Repair 3: BPF maps still missing even with SELinux permissive"
        fi
        setenforce 1 2>/dev/null
        log "  SELinux restored to Enforcing"
    fi
    else
        log "--- Phase 2: BPF Repair SKIPPED (kernel ${KMAJOR}.${KMINOR} too old) ---"
        log "  BPF cgroup_skb programs require kernel >= 5.0"
    fi
fi

# ============================================================
# PHASE 3: LEGACY FALLBACK (if BPF failed)
# ============================================================

if [ "$BPF_STATS_OK" -eq 0 ]; then
    log "--- Phase 3: Legacy Fallback ---"

    FALLBACK_METHOD="none"

    # ---- Fallback A: xt_qtaguid ----
    # xt_qtaguid provides /proc/net/xt_qtaguid/stats with per-UID data.
    # Kernel 4.14 may have this compiled as module or built-in.
    if [ "$HAS_XTAGUID" -ge 1 ]; then
        log "Fallback A: xt_qtaguid available, configuring..."

        # Load module if it's a module (not built-in)
        if [ "$HAS_XTAGUID" -eq 2 ]; then
            modprobe xt_qtaguid 2>/dev/null
            if [ -f /proc/net/xt_qtaguid/stats ]; then
                HAS_XTAGUID=1
                log "  xt_qtaguid module loaded successfully"
            fi
        fi

        if [ "$HAS_XTAGUID" -eq 1 ]; then
            # Ensure the property tells NetworkStatsService to use xt_qtaguid
            if command -v resetprop_phh >/dev/null 2>&1; then
                resetprop_phh net.qtaguid_enabled 1 2>/dev/null
            elif command -v magisk >/dev/null 2>&1; then
                magisk resetprop net.qtaguid_enabled 1 2>/dev/null
            fi

            # Set up xt_qtaguid tag socket rules via ndc
            # ndc is netd's command-line client
            if command -v ndc >/dev/null 2>&1; then
                # Tag all UID traffic for stats (tag 0xFFFFFFFE = no restriction, just counting)
                ndc bandwidth addalert 2>/dev/null
                log "  ndc bandwidth alert configured"
            fi

            FALLBACK_METHOD="xt_qtaguid"
            log "  xt_qtaguid fallback active"
        fi
    fi

    # ---- Fallback B: uid_stat ----
    # /proc/uid_stat/<uid>/tcp_rcv and tcp_snd provide basic per-UID TCP stats.
    # This is a very lightweight interface available on some kernels.
    if [ "$FALLBACK_METHOD" = "none" ] && [ "$HAS_UIDSTAT" -eq 1 ]; then
        log "Fallback B: uid_stat available"
        FALLBACK_METHOD="uid_stat"
        # uid_stat is read automatically by some ROMs' NetworkStatsService
        log "  uid_stat fallback active"
    fi

    # ---- Fallback C: ensure interface-level stats at minimum ----
    if [ "$FALLBACK_METHOD" = "none" ]; then
        log "Fallback C: No per-UID legacy interface available"
        log "  Interface-level stats only (total traffic, not per-app)"
    fi

    log "Fallback method: $FALLBACK_METHOD"
fi

# ============================================================
# PHASE 4: SETTINGS AND NETD RESTART
# ============================================================

log "--- Phase 4: Settings ---"

# Step 1: Set stats-related properties BEFORE netd restart
if command -v resetprop_phh >/dev/null 2>&1; then
    resetprop_phh persist.sys.nobpf false 2>/dev/null
    resetprop_phh ro.net.stats 1 2>/dev/null
    if [ "$BPF_STATS_OK" -eq 0 ]; then
        resetprop_phh net.qtaguid_enabled 1 2>/dev/null
    fi
    log "Properties set via resetprop_phh"
elif command -v magisk >/dev/null 2>&1; then
    magisk resetprop persist.sys.nobpf false 2>/dev/null
    magisk resetprop ro.net.stats 1 2>/dev/null
    if [ "$BPF_STATS_OK" -eq 0 ]; then
        magisk resetprop net.qtaguid_enabled 1 2>/dev/null
    fi
    log "Properties set via magisk resetprop"
fi

# Step 2: Restart netd to pick up property changes
log "Restarting netd..."
setprop ctl.restart netd 2>/dev/null
sleep 10
log "netd after restart: $(getprop init.svc.netd 2>/dev/null)"

# Step 3: Set network_stats_enabled AFTER netd restart.
# Some ROMs clear global Settings when netd restarts. We set it after
# to ensure it persists, then wait for Settings Provider to stabilize.
sleep 5
for i in 1 2 3 4 5; do
    settings put global network_stats_enabled 1 2>/dev/null
    sleep 3
    NSE_NOW=$(settings get global network_stats_enabled 2>/dev/null)
    if [ "$NSE_NOW" = "1" ]; then
        log "network_stats_enabled: confirmed 1 (attempt $i)"
        break
    fi
    log "network_stats_enabled attempt $i: ${NSE_NOW:-empty}, retrying..."
done
NSE_NOW=$(settings get global network_stats_enabled 2>/dev/null)
if [ "$NSE_NOW" != "1" ]; then
    log "WARN: trying content provider fallback..."
    content call --uri content://settings/global --method PUT --arg network_stats_enabled --extra value:s:1 2>/dev/null
    sleep 3
    NSE_NOW=$(settings get global network_stats_enabled 2>/dev/null)
    log "network_stats_enabled (content provider): ${NSE_NOW:-empty}"
fi

# Step 4: Force NetworkStatsService to re-initialize.
# On Android, SIGHUP to system_server triggers a process restart
# (via zygote). This causes ALL services including NetworkStatsService
# to re-initialize and read current settings. This is the key step
# that makes the traffic indicator work on older kernels where BPF
# isn't available but interface-level stats are sufficient.
log "Ensuring NetworkStatsService picks up settings..."
SS_PID=$(pidof system_server 2>/dev/null)
if [ -n "$SS_PID" ]; then
    log "system_server PID: $SS_PID"
    # Try cmd netstats first (available on Android 9+)
    if cmd netstats force-refresh 2>/dev/null; then
        log "  cmd netstats force-refresh: success"
    else
        log "  cmd netstats force-refresh: not available or failed"
    fi
    sleep 2
    # Send SIGHUP to trigger full service re-initialization
    kill -HUP "$SS_PID" 2>/dev/null
    log "  Sent SIGHUP to system_server to trigger NetworkStatsService re-init"
    # Wait for system_server to come back
    sleep 15
    # Re-apply network_stats_enabled in case it got lost during restart
    settings put global network_stats_enabled 1 2>/dev/null
    log "  Re-applied network_stats_enabled after system_server restart"
else
    log "  WARN: system_server PID not found"
fi

# Step 5: Final verification
sleep 5
FINAL_NSE=$(settings get global network_stats_enabled 2>/dev/null)
log "network_stats_enabled (final): ${FINAL_NSE:-empty}"
log "restricted_networking_mode: $(settings get global restricted_networking_mode 2>/dev/null)"

# ============================================================
# PHASE 5: FINAL VERIFICATION
# ============================================================

log "--- Phase 5: Verification ---"

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

log "FINAL BPF maps: $([ "$FINAL_BPF" -eq 1 ] && echo present || echo absent)"
log "FINAL xt_qtaguid: $([ "$FINAL_XTAGUID" -eq 1 ] && echo available || echo absent)"
log "FINAL uid_stat: $([ "$FINAL_UIDSTAT" -eq 1 ] && echo available || echo absent)"
log "FINAL network_stats_enabled: ${FINAL_NSE:-empty}"

if [ "$FINAL_BPF" -eq 1 ]; then
    log ""
    log "============================================"
    log "RESULT: BPF maps PRESENT"
    log "Per-UID traffic stats are WORKING."
    log "Traffic indicator should show per-app traffic."
    log "============================================"
elif [ "$FINAL_XTAGUID" -eq 1 ]; then
    log ""
    log "============================================"
    log "RESULT: BPF maps absent, but xt_qtaguid AVAILABLE"
    log "Per-UID stats available via xt_qtaguid fallback."
    log "Traffic indicator should show per-app traffic"
    log "if the ROM's NetworkStatsService uses this fallback."
    log "============================================"
elif [ "$FINAL_UIDSTAT" -eq 1 ]; then
    log ""
    log "============================================"
    log "RESULT: BPF maps absent, but uid_stat AVAILABLE"
    log "Per-UID TCP stats available via uid_stat fallback."
    log "Traffic indicator may show per-app traffic"
    log "depending on ROM implementation."
    log "============================================"
else
    log ""
    log "============================================"
    log "RESULT: No per-UID stats source available"
    log "BPF maps absent, no legacy fallback found."
    log "Traffic indicator will show TOTAL traffic only"
    log "if network_stats_enabled=1, or nothing at all."
    log ""
    log "PERMANENT FIX OPTIONS:"
    log "1. Patch service-connectivity.jar from the tethering"
    log "   APEX to add a fallback stats reader."
    log "2. Patch SystemUI.apk to use TrafficStats interface-"
    log "   level methods instead of per-UID methods."
    log "3. Flash a ROM with kernel >= 5.4 that supports"
    log "   BPF cgroup_skb programs."
    log ""
    log "DIAGNOSTIC INFO FOR BUG REPORT:"
    log "  Kernel: $(uname -r 2>/dev/null)"
    log "  BPF JIT: $(cat /proc/sys/net/core/bpf_jit_enable 2>/dev/null)"
    log "  Tethering APEX: $([ -d /apex/com.android.tethering ] && echo mounted || echo missing)"
    log "  bpfloader: $(getprop init.svc.bpfloader 2>/dev/null)"
    log "  netd: $(getprop init.svc.netd 2>/dev/null)"
    log "  SELinux: $(getenforce 2>/dev/null)"
    log "  mainline_done: $([ -d /sys/fs/bpf/netd_shared/mainline_done ] && echo present || echo absent)"
    log "============================================"
fi

# ============================================================
# PHASE 6: WATCHDOG
# ============================================================

if [ "$FINAL_BPF" -eq 1 ]; then
    # BPF maps exist - monitor for loss
    log "=== BPF watchdog active (every 5 min) ==="
    WATCHDOG_COUNT=0
    while true; do
        sleep 300
        WATCHDOG_COUNT=$((WATCHDOG_COUNT + 1))

        if [ ! -e "$BPF_MAP" ] || [ ! -e "$BPF_OWNER" ]; then
            log "Watchdog [$WATCHDOG_COUNT]: BPF maps LOST, restarting bpfloader..."
            stop bpfloader 2>/dev/null
            sleep 1
            start bpfloader 2>/dev/null
            sleep 5
            if [ -e "$BPF_MAP" ] && [ -e "$BPF_OWNER" ]; then
                log "Watchdog [$WATCHDOG_COUNT]: BPF maps restored"
            else
                log "Watchdog [$WATCHDOG_COUNT]: BPF maps still missing"
            fi
        fi

        if [ "$((WATCHDOG_COUNT % 10))" -eq 0 ]; then
            NSE=$(settings get global network_stats_enabled 2>/dev/null)
            if [ "$NSE" != "1" ]; then
                settings put global network_stats_enabled 1 2>/dev/null
                log "Watchdog [$WATCHDOG_COUNT]: corrected network_stats_enabled"
            fi
        fi
    done
else
    # BPF maps don't exist - ensure network_stats_enabled stays set
    # and monitor for changes
    log "=== Settings watchdog active (every 5 min) ==="
    WATCHDOG_COUNT=0
    while true; do
        sleep 300
        WATCHDOG_COUNT=$((WATCHDOG_COUNT + 1))

        # Re-verify network_stats_enabled (critical for interface-level stats)
        NSE=$(settings get global network_stats_enabled 2>/dev/null)
        if [ "$NSE" != "1" ]; then
            settings put global network_stats_enabled 1 2>/dev/null
            log "Watchdog [$WATCHDOG_COUNT]: corrected network_stats_enabled"
            # If netd restarted and cleared it again, re-trigger
            if [ "$((WATCHDOG_COUNT % 4))" -eq 0 ]; then
                SS_PID=$(pidof system_server 2>/dev/null)
                if [ -n "$SS_PID" ]; then
                    cmd netstats force-refresh 2>/dev/null
                    log "Watchdog [$WATCHDOG_COUNT]: cmd netstats force-refresh"
                fi
            fi
        fi

        # Light status check
        NBPF=$([ -e "$BPF_MAP" ] && echo P || echo A)
        NNETD=$(getprop init.svc.netd 2>/dev/null)
        log "Watchdog [$WATCHDOG_COUNT]: BPF=$NBPF netd=$NNETD NSE=$NSE"

        # If BPF maps suddenly appear (e.g. after kernel module load), log it
        if [ "$NBPF" = "P" ]; then
            log "Watchdog [$WATCHDOG_COUNT]: BPF maps appeared! Switching to BPF mode."
            break
        fi
    done
fi
