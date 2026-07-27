#!/system/bin/sh
# customize.sh - Magisk/KernelSU module installer
# Runs during module installation

ui_print "========================================"
ui_print "  EvoX GSI Network Stats Fix  v2.0"
ui_print "========================================"
ui_print ""

# ---- Install-time diagnostics ----
ui_print "- Collecting device info..."

KVER=$(uname -r 2>/dev/null || echo "unknown")
ui_print "  Kernel: $KVER"

# Check BPF filesystem
if mount | grep -q 'bpf.*\/sys\/fs\/bpf'; then
    ui_print "  BPF filesystem: mounted"
else
    ui_print "  BPF filesystem: NOT mounted (will attempt mount at boot)"
fi

# Check BPF maps
BPF_MAP="/sys/fs/bpf/netd_shared/map_netd_uid_stats_map"
BPF_OWNER="/sys/fs/bpf/netd_shared/map_netd_uid_owner_map"
if [ -e "$BPF_MAP" ] && [ -e "$BPF_OWNER" ]; then
    ui_print "  BPF stats maps: PRESENT"
else
    ui_print "  BPF stats maps: MISSING"
    ui_print "    uid_stats_map: $([ -e "$BPF_MAP" ] && echo present || echo absent)"
    ui_print "    uid_owner_map: $([ -e "$BPF_OWNER" ] && echo present || echo absent)"
    ui_print "  (This is the root cause - will attempt repair at boot)"
fi

# Check tethering APEX
if [ -d /apex/com.android.tethering ]; then
    ui_print "  Tethering APEX: mounted"
    if [ -f /apex/com.android.tethering/bin/netbpfload ]; then
        ui_print "  netbpfload: present"
    else
        ui_print "  netbpfload: MISSING from APEX"
    fi
else
    ui_print "  Tethering APEX: NOT mounted"
fi

# Check cgroup mounts (needed for cgroup_skb BPF programs)
if mount | grep -q 'cgroup'; then
    ui_print "  Cgroup: mounted"
else
    ui_print "  Cgroup: NOT mounted (BPF cgroup_skb will fail)"
fi

# Check kernel BPF support
if [ -d /sys/fs/bpf ]; then
    ui_print "  /sys/fs/bpf: exists"
else
    ui_print "  /sys/fs/bpf: MISSING"
fi

# Check restricted_networking_mode
RNM=$(settings get global restricted_networking_mode 2>/dev/null || echo "unknown")
ui_print "  restricted_networking_mode: $RNM"

NSE=$(settings get global network_stats_enabled 2>/dev/null || echo "unknown")
ui_print "  network_stats_enabled: $NSE"

ui_print ""

# ---- Set permissions ----
set_perm_recursive $MODPATH 0 0 0755 0644
set_perm $MODPATH/post-fs-data.sh 0 0 0755
set_perm $MODPATH/service.sh 0 0 0755

ui_print "- Permissions set"
ui_print ""
ui_print "What this module does:"
ui_print "  1. Prepares BPF filesystem and cgroup mounts"
ui_print "  2. Attempts to repair BPF program loading"
ui_print "     from the tethering APEX"
ui_print "  3. Falls back to interface-level stats"
ui_print "  4. Collects detailed diagnostics"
ui_print ""
ui_print "- Install complete. Reboot required."
ui_print "========================================"
