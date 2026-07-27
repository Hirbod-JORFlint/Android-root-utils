#!/system/bin/sh
# service.sh - Late_start: repair BPF loading and verify network stats
# Runs after boot_completed. Attempts to fix per-UID traffic accounting
# by repairing BPF program loading from the tethering APEX.

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
# PHASE 1: DIAGNOSTICS
# ============================================================

log "--- Phase 1: Diagnostics ---"

# Kernel info
log "Kernel: $(uname -r 2>/dev/null)"
log "Kernel BPF support: $(zcat /proc/config.gz 2>/dev/null | grep -c 'CONFIG_BPF=y\|CONFIG_BPF_SYSCALL=y\|CONFIG_CGROUP_BPF=y' || echo 'config.gz unavailable')"
log "Kernel BPF JIT: $(cat /proc/sys/net/core/bpf_jit_enable 2>/dev/null || echo 'N/A')"

# BPF filesystem
log "BPF fs mounted: $(mount | grep -c 'bpf.*\/sys\/fs\/bpf')"
log "BPF dir permissions: $(ls -ld /sys/fs/bpf 2>/dev/null)"

# BPF maps
BPF_MAP="/sys/fs/bpf/netd_shared/map_netd_uid_stats_map"
BPF_OWNER="/sys/fs/bpf/netd_shared/map_netd_uid_owner_map"
BPF_STATS_OK=0

if [ -e "$BPF_MAP" ] && [ -e "$BPF_OWNER" ]; then
    BPF_STATS_OK=1
    log "BPF maps: PRESENT (uid_stats + uid_owner)"
else
    log "BPF maps: MISSING"
    log "  uid_stats_map: $([ -e "$BPF_MAP" ] && echo present || echo absent)"
    log "  uid_owner_map: $([ -e "$BPF_OWNER" ] && echo present || echo absent)"
fi

# List all BPF maps for reference
log "All BPF maps under /sys/fs/bpf/netd_shared:"
ls -la /sys/fs/bpf/netd_shared/ 2>/dev/null >> "$LOG"
log "All BPF maps under /sys/fs/bpf:"
ls -la /sys/fs/bpf/ 2>/dev/null >> "$LOG"

# Cgroup hierarchy
log "Cgroup mounts:"
mount | grep 'cgroup' >> "$LOG" 2>/dev/null
if [ -d /dev/cgroup ]; then
    log "  /dev/cgroup: exists"
    ls /dev/cgroup/ 2>/dev/null >> "$LOG"
elif [ -d /sys/fs/cgroup ]; then
    log "  /sys/fs/cgroup: exists"
    ls /sys/fs/cgroup/ 2>/dev/null >> "$LOG"
fi

# Tethering APEX
if [ -d /apex/com.android.tethering ]; then
    log "Tethering APEX: mounted"
    log "  netbpfload: $([ -f /apex/com.android.tethering/bin/netbpfload ] && echo present || echo missing)"
    log "  service-connectivity.jar: $([ -f /apex/com.android.tethering/javalib/service-connectivity.jar ] && echo present || echo missing)"
else
    log "WARN: Tethering APEX not mounted"
fi

# netd status
log "netd service: $(getprop init.svc.netd 2>/dev/null)"
log "bpfloader service: $(getprop init.svc.bpfloader 2>/dev/null)"

# Settings
log "restricted_networking_mode: $(settings get global restricted_networking_mode 2>/dev/null)"
log "network_stats_enabled: $(settings get global network_stats_enabled 2>/dev/null)"

# SELinux
SELINUX_STATUS=$(getenforce 2>/dev/null || echo "unknown")
log "SELinux: $SELINUX_STATUS"

# ============================================================
# PHASE 2: BPF REPAIR (if maps are missing)
# ============================================================

if [ "$BPF_STATS_OK" -eq 0 ]; then
    log "--- Phase 2: BPF Repair Attempt ---"

    REPAIR_ATTEMPTED=1

    # ---- Repair step 1: Restart bpfloader service ----
    # The bpfloader service in netbpfload.rc is set to /system/bin/false
    # but the tethering APEX should override it. Restarting may trigger
    # the APEX override to activate properly.
    log "Repair 1: Restarting bpfloader service..."
    stop bpfloader 2>/dev/null
    sleep 2
    start bpfloader 2>/dev/null
    sleep 5

    if [ -e "$BPF_MAP" ] && [ -e "$BPF_OWNER" ]; then
        BPF_STATS_OK=1
        log "Repair 1 SUCCESS: BPF maps now present after bpfloader restart"
    else
        log "Repair 1: BPF maps still missing after bpfloader restart"
    fi

    # ---- Repair step 2: Manually run netbpfload from APEX ----
    if [ "$BPF_STATS_OK" -eq 0 ] && [ -f /apex/com.android.tethering/bin/netbpfload ]; then
        log "Repair 2: Manually invoking netbpfload from tethering APEX..."
        /apex/com.android.tethering/bin/netbpfload 2>> "$LOG"
        NBPFP_EXIT=$?
        log "Repair 2: netbpfload exited with code $NBPFP_EXIT"
        sleep 3

        if [ -e "$BPF_MAP" ] && [ -e "$BPF_OWNER" ]; then
            BPF_STATS_OK=1
            log "Repair 2 SUCCESS: BPF maps now present after manual netbpfload"
        else
            log "Repair 2: BPF maps still missing after manual netbpfload"
        fi
    else
        log "Repair 2: SKIPPED (netbpfload not found)"
    fi

    # ---- Repair step 3: Ensure cgroup hierarchy is mounted ----
    # cgroup_skb BPF programs need cgroup net_cls/net_prio controllers.
    # On some GSIs the cgroup mounts are incomplete.
    if ! mount | grep -q 'cgroup'; then
        log "Repair 3: Attempting to mount cgroup hierarchy..."
        mkdir -p /dev/cgroup 2>/dev/null
        mount -t cgroup -o cpu,cpuacct none /dev/cgroup 2>/dev/null
        mkdir -p /dev/cgroup/net_cls 2>/dev/null
        mount -t cgroup -o net_cls,net_prio none /dev/cgroup/net_cls 2>/dev/null
        if mount | grep -q 'cgroup'; then
            log "Repair 3: Cgroup mounts created"
            # Retry bpfloader after cgroup mount
            stop bpfloader 2>/dev/null
            sleep 1
            start bpfloader 2>/dev/null
            sleep 5
            if [ -e "$BPF_MAP" ] && [ -e "$BPF_OWNER" ]; then
                BPF_STATS_OK=1
                log "Repair 3 SUCCESS: BPF maps present after cgroup mount + bpfloader restart"
            fi
        else
            log "Repair 3: WARN - Failed to mount cgroup hierarchy"
        fi
    else
        log "Repair 3: Cgroup already mounted, skipping"
    fi

    # ---- Repair step 4: Temporary SELinux permissive test ----
    if [ "$BPF_STATS_OK" -eq 0 ] && [ "$SELINUX_STATUS" = "Enforcing" ]; then
        log "Repair 4: Testing SELinux permissive (temporary)..."
        setenforce 0 2>/dev/null
        stop bpfloader 2>/dev/null
        sleep 1
        start bpfloader 2>/dev/null
        sleep 5

        if [ -e "$BPF_MAP" ] && [ -e "$BPF_OWNER" ]; then
            BPF_STATS_OK=1
            log "Repair 4 SUCCESS: BPF maps present with SELinux permissive"
            log "Repair 4: Check dmesg for avc denials to identify the blocking rule"
            dmesg | grep -i 'avc.*denied.*bpf\|avc.*denied.*netd\|avc.*denied.*bpfloader' 2>/dev/null >> "$LOG"
        else
            log "Repair 4: BPF maps still missing even with SELinux permissive"
        fi

        # Restore enforcing
        setenforce 1 2>/dev/null
        log "Repair 4: SELinux restored to Enforcing"
    else
        log "Repair 4: SKIPPED (SELinux not enforcing or BPF already fixed)"
    fi
fi

# ============================================================
# PHASE 3: FALLBACK / SETTINGS
# ============================================================

log "--- Phase 3: Settings and fallback ---"

# Ensure network_stats_enabled is set (enables interface-level stats collection)
# This is the minimum needed for any traffic data
settings put global network_stats_enabled 1 2>/dev/null
log "network_stats_enabled: $(settings get global network_stats_enabled 2>/dev/null)"

# Ensure restricted_networking_mode stays at whatever phh set it
# (we don't override this - it controls the firewall, not stats)
log "restricted_networking_mode: $(settings get global restricted_networking_mode 2>/dev/null)"

# ---- Resetprop: ensure stats-related properties are correct ----
if command -v resetprop_phh >/dev/null 2>&1; then
    resetprop_phh persist.sys.nobpf false 2>/dev/null
    resetprop_phh ro.net.stats 1 2>/dev/null
    log "Properties set via resetprop_phh"
elif command -v magisk >/dev/null 2>&1; then
    magisk resetprop persist.sys.nobpf false 2>/dev/null
    magisk resetprop ro.net.stats 1 2>/dev/null
    log "Properties set via magisk resetprop"
fi

# ---- Restart netd to pick up changes ----
log "Restarting netd..."
setprop ctl.restart netd 2>/dev/null
sleep 10
log "netd service after restart: $(getprop init.svc.netd 2>/dev/null)"

# ============================================================
# PHASE 4: VERIFICATION
# ============================================================

log "--- Phase 4: Verification ---"

# Re-check BPF maps
FINAL_STATS=$([ -e "$BPF_MAP" ] && echo present || echo absent)
FINAL_OWNER=$([ -e "$BPF_OWNER" ] && echo present || echo absent)
log "FINAL BPF uid_stats_map: $FINAL_STATS"
log "FINAL BPF uid_owner_map: $FINAL_OWNER"

if [ "$FINAL_STATS" = "present" ] && [ "$FINAL_OWNER" = "present" ]; then
    log "RESULT: BPF maps are PRESENT - per-UID stats should work"
    log "The traffic indicator should now show per-app traffic."
else
    log "RESULT: BPF maps are MISSING - per-UID stats will not work"
    log "The traffic indicator will NOT show per-app traffic."
    log ""
    log "DIAGNOSTIC SUMMARY FOR BUG REPORT:"
    log "  Kernel: $(uname -r 2>/dev/null)"
    log "  BPF maps: absent"
    log "  BPF fs: $(mount | grep -c 'bpf') mounts"
    log "  Cgroup: $(mount | grep -c 'cgroup') mounts"
    log "  Tethering APEX: $([ -d /apex/com.android.tethering ] && echo mounted || echo missing)"
    log "  netbpfload: $([ -f /apex/com.android.tethering/bin/netbpfload ] && echo present || echo missing)"
    log "  bpfloader svc: $(getprop init.svc.bpfloader 2>/dev/null)"
    log "  netd svc: $(getprop init.svc.netd 2>/dev/null)"
    log "  SELinux: $(getenforce 2>/dev/null)"
    log ""
    log "  If BPF programs cannot load on this kernel, the only"
    log "  fix is to patch the Java framework (service-connectivity.jar"
    log "  or SystemUI.apk) to use interface-level stats instead of"
    log "  per-UID BPF stats."
fi

log "network_stats_enabled: $(settings get global network_stats_enabled 2>/dev/null)"
log "netd status: $(getprop init.svc.netd 2>/dev/null)"
log "All BPF maps under /sys/fs/bpf/netd_shared:"
ls -la /sys/fs/bpf/netd_shared/ 2>/dev/null >> "$LOG"

# ============================================================
# PHASE 5: WATCHDOG (only if BPF maps exist)
# ============================================================

if [ "$FINAL_STATS" = "present" ] && [ "$FINAL_OWNER" = "present" ]; then
    log "=== BPF watchdog active (checking every 5 min) ==="
    WATCHDOG_COUNT=0
    while true; do
        sleep 300
        WATCHDOG_COUNT=$((WATCHDOG_COUNT + 1))

        if [ ! -e "$BPF_MAP" ] || [ ! -e "$BPF_OWNER" ]; then
            log "Watchdog [$WATCHDOG_COUNT]: BPF maps LOST, attempting repair..."
            stop bpfloader 2>/dev/null
            sleep 1
            start bpfloader 2>/dev/null
            sleep 5

            if [ -e "$BPF_MAP" ] && [ -e "$BPF_OWNER" ]; then
                log "Watchdog [$WATCHDOG_COUNT]: BPF maps restored"
            else
                log "Watchdog [$WATCHDOG_COUNT]: BPF maps still missing after repair"
            fi
        fi

        # Every 10 cycles (~50 min), verify settings
        if [ "$((WATCHDOG_COUNT % 10))" -eq 0 ]; then
            NSE=$(settings get global network_stats_enabled 2>/dev/null)
            if [ "$NSE" != "1" ]; then
                settings put global network_stats_enabled 1 2>/dev/null
                log "Watchdog [$WATCHDOG_COUNT]: corrected network_stats_enabled"
            fi
        fi
    done
else
    log "=== BPF watchdog SKIPPED (maps absent, no point monitoring) ==="
    log "=== Module will log diagnostics only ==="

    # Even without BPF, periodically log the state for diagnostics
    WATCHDOG_COUNT=0
    while true; do
        sleep 600
        WATCHDOG_COUNT=$((WATCHDOG_COUNT + 1))
        log "Diag [$WATCHDOG_COUNT]: BPF maps=$([ -e "$BPF_MAP" ] && echo P || echo A) netd=$(getprop init.svc.netd 2>/dev/null) nse=$(settings get global network_stats_enabled 2>/dev/null)"
    done
fi
