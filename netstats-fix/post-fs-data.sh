#!/system/bin/sh
# post-fs-data.sh - Early boot: prepare BPF and accounting infrastructure
# Runs before zygote, after /data is mounted

MODDIR=${0%/*}
LOG=/data/local/tmp/netstats-fix.log

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [post-fs-data] $1" >> "$LOG"
}

: > "$LOG"
log "=== post-fs-data.sh started ==="
log "Kernel: $(uname -r 2>/dev/null)"
log "Android: $(getprop ro.build.version.release 2>/dev/null) (SDK $(getprop ro.build.version.sdk 2>/dev/null))"
log "Build: $(getprop ro.build.display.id 2>/dev/null)"

# ---- 1. Mount BPF filesystem ----
if ! mount | grep -q 'bpf.*\/sys\/fs\/bpf'; then
    mount -t bpf bpf /sys/fs/bpf 2>/dev/null
    if mount | grep -q 'bpf.*\/sys\/fs\/bpf'; then
        log "BPF filesystem mounted successfully"
    else
        log "WARN: Failed to mount BPF filesystem"
    fi
else
    log "BPF filesystem already mounted"
fi
chmod 0755 /sys/fs/bpf 2>/dev/null
chmod -R 0755 /sys/fs/bpf/ 2>/dev/null

# ---- 2. Ensure netd_shared directory exists ----
mkdir -p /sys/fs/bpf/netd_shared 2>/dev/null
chmod 0755 /sys/fs/bpf/netd_shared 2>/dev/null

# ---- 3. Early BPF capability detection ----
# Determine if this kernel can support cgroup_skb BPF programs.
# Kernel 4.14 and below generally lack the necessary BPF features.
KMAJOR=$(uname -r | cut -d. -f1)
KMINOR=$(uname -r | cut -d. -f2)
if [ "$KMAJOR" -lt 4 ] || { [ "$KMAJOR" -eq 4 ] && [ "$KMINOR" -lt 15 ]; }; then
    log "Kernel $KMAJOR.$KMINOR < 4.15: cgroup_skb BPF likely unavailable"
    echo 0 > /data/local/tmp/.bpf_capable 2>/dev/null
elif [ "$KMAJOR" -eq 4 ] && [ "$KMINOR" -le 14 ]; then
    # 4.14 *may* have BPF but cgroup_skb support is patchy on Android
    log "Kernel 4.14.x: cgroup_skb BPF may be unavailable (checking further)"
    echo 1 > /data/local/tmp/.bpf_capable 2>/dev/null
else
    log "Kernel $KMAJOR.$KMINOR: cgroup_skb BPF likely supported"
    echo 1 > /data/local/tmp/.bpf_capable 2>/dev/null
fi

# ---- 4. Check for legacy per-UID stats interfaces ----
if [ -f /proc/net/xt_qtaguid/stats ]; then
    log "Legacy stats: /proc/net/xt_qtaguid/stats EXISTS"
elif [ -d /proc/uid_stat ]; then
    log "Legacy stats: /proc/uid_stat/ EXISTS"
else
    log "Legacy stats: none found (no xt_qtaguid, no uid_stat)"
fi

# ---- 5. Clear stale netstats databases ----
CLEARED=0
for f in /data/misc/netstats/iface_stats.xml \
         /data/misc/netstats/netstats_global.bin \
         /data/misc/netstats/netstats_uid.xml \
         /data/misc/netstats/netstats_uid_s_tag.bin \
         /data/misc/netstats/netstats_uid_iface_stat.bin; do
    if [ -f "$f" ]; then
        rm -f "$f" 2>/dev/null
        CLEARED=$((CLEARED + 1))
    fi
done
log "Cleared $CLEARED stale netstats files"

# ---- 6. Log current BPF map status ----
BPF_MAP="/sys/fs/bpf/netd_shared/map_netd_uid_stats_map"
BPF_OWNER="/sys/fs/bpf/netd_shared/map_netd_uid_owner_map"
log "BPF uid_stats_map: $([ -e "$BPF_MAP" ] && echo present || echo absent)"
log "BPF uid_owner_map: $([ -e "$BPF_OWNER" ] && echo present || echo absent)"

# ---- 7. Log APEX and cgroup status ----
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

log "=== post-fs-data.sh complete ==="
