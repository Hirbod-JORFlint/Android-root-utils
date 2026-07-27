#!/system/bin/sh
# post-fs-data.sh - Early boot: force correct BPF environment
# This runs AFTER init's exec_start bpfloader, so netbpfload has already
# executed (and likely failed on old kernels). We fix the environment
# and force a clean retry.

MODDIR=${0%/*}
LOG=/data/local/tmp/netstats-fix.log

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [post-fs-data] $1" >> "$LOG"
}

: > "$LOG"
log "=== post-fs-data.sh started ==="

# ---- System info ----
KVER=$(uname -r 2>/dev/null || echo unknown)
KMAJOR=$(echo "$KVER" | cut -d. -f1)
KMINOR=$(echo "$KVER" | cut -d. -f2)
KPATCH=$(echo "$KVER" | cut -d. -f3 | cut -d- -f1)
ANDROID=$(getprop ro.build.version.release 2>/dev/null)
SDK=$(getprop ro.build.version.sdk 2>/dev/null)
BUILD=$(getprop ro.build.display.id 2>/dev/null)

log "Kernel: $KVER"
log "Android: $ANDROID (SDK $SDK)"
log "Build: $BUILD"

# ---- 1. Detect correct kernel version string for netbpfload ----
# netbpfload checks ro.bpf.kver_override to decide which BPF programs to load.
# If set too high, it loads programs the kernel can't handle.
# If set to the ACTUAL version, it loads the correct variant.
# The format is "major.minor.patch" matching uname -r output.
CORRECT_KVER="${KMAJOR}.${KMINOR}.${KPATCH}"
log "Correct kernel version for BPF: $CORRECT_KVER"

# ---- 2. Delete mainline_done BEFORE anything else (CRITICAL FIX) ----
# This must happen BEFORE we interact with bpfloader.
# bpfloader checks for mainline_done; if present, it skips loading.
# We delete it first to ensure a clean slate.
if [ -d /sys/fs/bpf/netd_shared/mainline_done ]; then
    rm -rf /sys/fs/bpf/netd_shared/mainline_done 2>/dev/null
    log "Deleted mainline_done marker (PRIORITY)"
else
    log "mainline_done not present (clean state)"
fi

# ---- 3. Mount BPF filesystem if needed ----
if ! mount | grep -q 'bpf.*\/sys\/fs\/bpf'; then
    mount -t bpf bpf /sys/fs/bpf 2>/dev/null
    log "Mounted BPF filesystem"
else
    log "BPF filesystem already mounted"
fi
chmod 0755 /sys/fs/bpf 2>/dev/null
chmod -R 0755 /sys/fs/bpf/ 2>/dev/null

# ---- 4. Ensure netd_shared directory exists ----
mkdir -p /sys/fs/bpf/netd_shared 2>/dev/null
chmod 0755 /sys/fs/bpf/netd_shared 2>/dev/null

# ---- 5. Set ro.bpf.kver_override to ACTUAL kernel version ----
# This is THE critical property. netbpfload uses it to select which
# BPF program variants to load. Setting it too high = loading programs
# the kernel can't handle. Setting it correctly = loading compatible variants.
CURRENT_KVER_PROP=$(getprop ro.bpf.kver_override 2>/dev/null)
log "ro.bpf.kver_override: ${CURRENT_KVER_PROP:-not set}"

if [ "$CURRENT_KVER_PROP" != "$CORRECT_KVER" ]; then
    RESETPROP_SET=0
    if command -v resetprop_phh >/dev/null 2>&1; then
        resetprop_phh ro.bpf.kver_override "$CORRECT_KVER" 2>/dev/null
        RESETPROP_SET=1
        log "Set ro.bpf.kver_override=$CORRECT_KVER via resetprop_phh"
    fi
    
    if [ "$RESETPROP_SET" -eq 0 ] && command -v resetprop >/dev/null 2>&1; then
        resetprop ro.bpf.kver_override "$CORRECT_KVER" 2>/dev/null
        RESETPROP_SET=1
        log "Set ro.bpf.kver_override=$CORRECT_KVER via resetprop"
    fi
    
    if [ "$RESETPROP_SET" -eq 0 ] && command -v magisk >/dev/null 2>&1; then
        magisk resetprop ro.bpf.kver_override "$CORRECT_KVER" 2>/dev/null
        RESETPROP_SET=1
        log "Set ro.bpf.kver_override=$CORRECT_KVER via magisk resetprop"
    fi
    
    if [ "$RESETPROP_SET" -eq 0 ]; then
        log "WARN: Unable to set ro.bpf.kver_override (no resetprop tool available)"
    fi
else
    log "ro.bpf.kver_override already correct ($CORRECT_KVER)"
fi

# ---- 6. Set additional properties to help BPF loading ----
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
fi
log "Set helper properties"

# ---- 7. Enable BPF JIT if possible ----
if [ -f /proc/sys/net/core/bpf_jit_enable ]; then
    echo 1 > /proc/sys/net/core/bpf_jit_enable 2>/dev/null
    log "Enabled BPF JIT"
else
    log "BPF JIT sysctl not available (non-critical)"
fi

# ---- 8. Check results BEFORE restarting ----
BPF_MAP="/sys/fs/bpf/netd_shared/map_netd_uid_stats_map"
BPF_OWNER="/sys/fs/bpf/netd_shared/map_netd_uid_owner_map"

if [ -e "$BPF_MAP" ] && [ -e "$BPF_OWNER" ]; then
    log "BPF maps already present (initial state)"
else
    log "BPF maps missing, will attempt retry via service.sh"
fi

# ---- 9. Log legacy interfaces for diagnostics ----
if [ -f /proc/net/xt_qtaguid/stats ]; then
    log "xt_qtaguid: AVAILABLE"
elif [ -c /dev/xt_qtaguid ]; then
    log "xt_qtaguid: device exists (may need loading)"
else
    log "xt_qtaguid: not found"
fi

if [ -d /proc/uid_stat ]; then
    log "uid_stat: AVAILABLE"
else
    log "uid_stat: not found"
fi

# ---- 10. Log APEX and cgroup status ----
if [ -d /apex/com.android.tethering ]; then
    log "Tethering APEX: mounted"
else
    log "WARN: Tethering APEX not mounted"
fi

if mount | grep -q 'cgroup'; then
    log "Cgroup: mounted"
else
    log "WARN: No cgroup mounts"
fi

# ---- 11. Record BPF capability for service.sh ----
# Improved logic: only 5.0+ supports cgroup_skb reliably
BPF_CAPABLE=0
if [ "$KMAJOR" -ge 5 ]; then
    BPF_CAPABLE=1
    log "BPF capable (kernel >= 5.0): YES"
else
    log "BPF capable (kernel < 5.0): Limited (cgroup_skb unlikely)"
fi
echo "$BPF_CAPABLE" > /data/local/tmp/.bpf_capable 2>/dev/null

# Record the correct kernel version for service.sh
echo "$CORRECT_KVER" > /data/local/tmp/.bpf_kver 2>/dev/null

log "=== post-fs-data.sh complete ==="
