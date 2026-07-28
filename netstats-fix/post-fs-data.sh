#!/system/bin/sh
# post-fs-data.sh - Early boot: force correct BPF environment
# Runs AFTER init's exec_start bpfloader, so netbpfload has already
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
# Strip ALL non-numeric suffixes from patch version
# Handles: "193" (clean), "193-perf-g743cb02" (EvoX), "186-g911263112f80-dirty" (Infinity X),
# "141+" (Axion - the + causes netbpfload version parsing failure!)
KPATCH=$(echo "$KVER" | cut -d. -f3 | grep -oE '^[0-9]+')
ANDROID=$(getprop ro.build.version.release 2>/dev/null)
SDK=$(getprop ro.build.version.sdk 2>/dev/null)
BUILD=$(getprop ro.build.display.id 2>/dev/null)

log "Kernel: $KVER"
log "Android: $ANDROID (SDK $SDK)"
log "Build: $BUILD"

# ---- Correct kernel version for BPF program selection ----
# netbpfload checks ro.bpf.kver_override to decide which BPF programs to load.
# The BPF .o has variants for: 4_9, 4_14 (cgroupsock only), 4_19, 5_4, 5_10, 5_10_25q2
# netbpfload selects the HIGHEST variant <= ro.bpf.kver_override
# Setting it too high loads programs the kernel can't handle.
# We set it to the ACTUAL kernel version so netbpfload picks the best match.
# CRITICAL: The version string MUST be pure "major.minor.patch" with no suffixes.
# Suffixes like "+" (e.g. "4.14.141+") cause netbpfload to fail version parsing,
# resulting in ZERO maps being created (observed on Axion OS).
CORRECT_KVER="${KMAJOR}.${KMINOR}.${KPATCH}"
log "Correct kernel version for BPF: $CORRECT_KVER"

# ---- Delete mainline_done BEFORE anything else ----
# bpfloader checks for mainline_done; if present, it skips loading.
# We delete it first to ensure a clean slate for retry.
if [ -d /sys/fs/bpf/netd_shared/mainline_done ]; then
    rm -rf /sys/fs/bpf/netd_shared/mainline_done 2>/dev/null
    log "Deleted mainline_done marker"
else
    log "mainline_done not present (clean state)"
fi

# ---- Mount BPF filesystem if needed ----
if ! mount | grep -q 'bpf.*\/sys\/fs\/bpf'; then
    mount -t bpf bpf /sys/fs/bpf 2>/dev/null
    log "Mounted BPF filesystem"
else
    log "BPF filesystem already mounted"
fi
chmod 0755 /sys/fs/bpf 2>/dev/null
chmod -R 0755 /sys/fs/bpf/ 2>/dev/null

# ---- Ensure netd_shared directory exists ----
mkdir -p /sys/fs/bpf/netd_shared 2>/dev/null
chmod 0755 /sys/fs/bpf/netd_shared 2>/dev/null

# ---- Set ro.bpf.kver_override to ACTUAL kernel version ----
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

# ---- Set additional properties to help BPF loading ----
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

# ---- Enable BPF JIT if possible ----
if [ -f /proc/sys/net/core/bpf_jit_enable ]; then
    echo 1 > /proc/sys/net/core/bpf_jit_enable 2>/dev/null
    log "Enabled BPF JIT"
else
    log "BPF JIT sysctl not available (non-critical)"
fi

# ---- Check BPF maps (using CORRECT names) ----
# The BPF .o defines maps with short names like "uid_owner_map", "app_uid_stats_map".
# netbpfload prepends "map_netd_" and pins to /sys/fs/bpf/netd_shared/
BPF_MAP_OWNER="/sys/fs/bpf/netd_shared/map_netd_uid_owner_map"
BPF_MAP_APP_STATS="/sys/fs/bpf/netd_shared/map_netd_app_uid_stats_map"
BPF_MAP_COOKIE="/sys/fs/bpf/netd_shared/map_netd_cookie_tag_map"
BPF_MAP_CONFIG="/sys/fs/bpf/netd_shared/map_netd_configuration_map"
BPF_MAP_STATS_A="/sys/fs/bpf/netd_shared/map_netd_stats_map_A"
BPF_MAP_STATS_B="/sys/fs/bpf/netd_shared/map_netd_stats_map_B"

MAPS_FOUND=0
MAPS_EXPECTED=6
[ -e "$BPF_MAP_OWNER" ] && MAPS_FOUND=$((MAPS_FOUND + 1))
[ -e "$BPF_MAP_APP_STATS" ] && MAPS_FOUND=$((MAPS_FOUND + 1))
[ -e "$BPF_MAP_COOKIE" ] && MAPS_FOUND=$((MAPS_FOUND + 1))
[ -e "$BPF_MAP_CONFIG" ] && MAPS_FOUND=$((MAPS_FOUND + 1))
[ -e "$BPF_MAP_STATS_A" ] && MAPS_FOUND=$((MAPS_FOUND + 1))
[ -e "$BPF_MAP_STATS_B" ] && MAPS_FOUND=$((MAPS_FOUND + 1))

log "BPF maps found: $MAPS_FOUND/$MAPS_EXPECTED"
log "  uid_owner_map: $([ -e "$BPF_MAP_OWNER" ] && echo present || echo absent)"
log "  app_uid_stats_map: $([ -e "$BPF_MAP_APP_STATS" ] && echo present || echo absent)"
log "  cookie_tag_map: $([ -e "$BPF_MAP_COOKIE" ] && echo present || echo absent)"
log "  configuration_map: $([ -e "$BPF_MAP_CONFIG" ] && echo present || echo absent)"
log "  stats_map_A: $([ -e "$BPF_MAP_STATS_A" ] && echo present || echo absent)"
log "  stats_map_B: $([ -e "$BPF_MAP_STATS_B" ] && echo present || echo absent)"

# ---- Log legacy interfaces for diagnostics ----
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

# ---- Log APEX and cgroup status ----
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

# ---- Record BPF capability for service.sh ----
BPF_CAPABLE=0
if [ "$KMAJOR" -ge 5 ]; then
    BPF_CAPABLE=1
    log "BPF capable (kernel >= 5.0): YES (cgroup_skb supported)"
elif [ "$KMAJOR" -eq 4 ] && [ "$KMINOR" -ge 14 ]; then
    BPF_CAPABLE=1
    log "BPF capable (kernel 4.14+): partial (cgroup_skb may work with backports)"
elif [ "$KMAJOR" -eq 4 ] && [ "$KMINOR" -ge 9 ]; then
    BPF_CAPABLE=0
    log "BPF limited (kernel 4.9): cgroup_skb unlikely, maps may still load"
else
    BPF_CAPABLE=0
    log "BPF not capable (kernel < 4.9)"
fi
echo "$BPF_CAPABLE" > /data/local/tmp/.bpf_capable 2>/dev/null

# Record the correct kernel version for service.sh
echo "$CORRECT_KVER" > /data/local/tmp/.bpf_kver 2>/dev/null

# Record map count for service.sh
echo "$MAPS_FOUND" > /data/local/tmp/.bpf_map_count 2>/dev/null

log "=== post-fs-data.sh complete ==="
