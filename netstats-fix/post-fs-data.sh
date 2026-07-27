#!/system/bin/sh
# post-fs-data.sh - Early boot: prepare BPF and accounting infrastructure
# Runs before zygote, after /data is mounted

MODDIR=${0%/*}
LOG=/data/local/tmp/netstats-fix.log

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [post-fs-data] $1" >> "$LOG"
}

# Clear previous log for clean diagnostics
: > "$LOG"
log "=== post-fs-data.sh started ==="
log "Kernel: $(uname -r 2>/dev/null)"
log "Android: $(getprop ro.build.version.release 2>/dev/null) (SDK $(getprop ro.build.version.sdk 2>/dev/null))"

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

# ---- 2. Ensure netd_shared BPF directory exists ----
mkdir -p /sys/fs/bpf/netd_shared 2>/dev/null
chmod 0755 /sys/fs/bpf/netd_shared 2>/dev/null

# ---- 3. Check cgroup mounts (needed for cgroup_skb BPF programs) ----
# The cgroup_skb BPF program type requires a properly mounted cgroup hierarchy
# with the net_cls and net_prio controllers. Without this, netbpfload fails.
CGROUP_MOUNTED=0
if mount | grep -q 'cgroup'; then
    CGROUP_MOUNTED=1
    log "Cgroup hierarchy: mounted"
    mount | grep 'cgroup' | head -5 >> "$LOG"
else
    log "WARN: No cgroup mounts found - BPF cgroup_skb programs will fail"
fi

# ---- 4. Reset stale netstats databases ----
# Clear data accumulated while BPF accounting was broken
# This prevents confusing old broken data with fresh correct data
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

# ---- 5. Log BPF map status at this early stage ----
BPF_MAP="/sys/fs/bpf/netd_shared/map_netd_uid_stats_map"
BPF_OWNER="/sys/fs/bpf/netd_shared/map_netd_uid_owner_map"
log "BPF uid_stats_map: $([ -e "$BPF_MAP" ] && echo present || echo absent)"
log "BPF uid_owner_map: $([ -e "$BPF_OWNER" ] && echo present || echo absent)"

# ---- 6. Log tethering APEX status ----
if [ -d /apex/com.android.tethering ]; then
    log "Tethering APEX: mounted at /apex/com.android.tethering"
    ls -la /apex/com.android.tethering/bin/netbpfload 2>/dev/null >> "$LOG"
else
    log "WARN: Tethering APEX not mounted - netbpfload unavailable"
fi

log "=== post-fs-data.sh complete ==="
