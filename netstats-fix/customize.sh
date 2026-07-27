#!/system/bin/sh
# customize.sh - Magisk/KernelSU module installer
# Runs during module installation

ui_print "========================================"
ui_print "  EvoX GSI Network Stats Fix  v3.0"
ui_print "========================================"
ui_print ""
ui_print "Universal network traffic indicator fix"
ui_print "for Android 12-16 GSIs."
ui_print ""

# ---- Install-time diagnostics ----
ui_print "- Device diagnostics..."

KVER=$(uname -r 2>/dev/null || echo unknown)
ui_print "  Kernel: $KVER"

KMAJOR=$(echo "$KVER" | cut -d. -f1)
KMINOR=$(echo "$KVER" | cut -d. -f2)

# BPF filesystem
if mount | grep -q 'bpf.*\/sys\/fs\/bpf'; then
    ui_print "  BPF filesystem: mounted"
else
    ui_print "  BPF filesystem: not mounted"
fi

# BPF maps
BPF_MAP="/sys/fs/bpf/netd_shared/map_netd_uid_stats_map"
BPF_OWNER="/sys/fs/bpf/netd_shared/map_netd_uid_owner_map"
if [ -e "$BPF_MAP" ] && [ -e "$BPF_OWNER" ]; then
    ui_print "  BPF maps: PRESENT (may already be working)"
else
    ui_print "  BPF maps: MISSING"
    ui_print "    uid_stats_map: $([ -e "$BPF_MAP" ] && echo P || echo A)"
    ui_print "    uid_owner_map: $([ -e "$BPF_OWNER" ] && echo P || echo A)"
fi

# mainline_done marker (netbpfload ran but maps missing)
if [ -d /sys/fs/bpf/netd_shared/mainline_done ]; then
    ui_print "  mainline_done: yes (BPF loader ran but skipped network maps)"
fi

# Tethering APEX
if [ -d /apex/com.android.tethering ]; then
    ui_print "  Tethering APEX: mounted"
else
    ui_print "  Tethering APEX: NOT mounted"
fi

# Legacy stats interfaces
if [ -f /proc/net/xt_qtaguid/stats ]; then
    ui_print "  xt_qtaguid: AVAILABLE (legacy fallback possible)"
elif [ -c /dev/xt_qtaguid ]; then
    ui_print "  xt_qtaguid: device exists (module may need loading)"
else
    ui_print "  xt_qtaguid: not found"
fi
if [ -d /proc/uid_stat ]; then
    ui_print "  uid_stat: AVAILABLE (legacy fallback possible)"
else
    ui_print "  uid_stat: not found"
fi

# Kernel BPF capability assessment
if [ "$KMAJOR" -lt 4 ] || { [ "$KMAJOR" -eq 4 ] && [ "$KMINOR" -lt 15 ]; }; then
    ui_print "  BPF capability: kernel too old for cgroup_skb"
elif [ "$KMAJOR" -eq 4 ] && [ "$KMINOR" -le 14 ]; then
    ui_print "  BPF capability: kernel 4.14 (cgroup_skb unlikely)"
else
    ui_print "  BPF capability: kernel should support cgroup_skb"
fi

# Settings
RNM=$(settings get global restricted_networking_mode 2>/dev/null || echo unknown)
ui_print "  restricted_networking_mode: $RNM"
NSE=$(settings get global network_stats_enabled 2>/dev/null || echo unknown)
ui_print "  network_stats_enabled: $NSE"

ui_print ""

# ---- Set permissions ----
set_perm_recursive $MODPATH 0 0 0755 0644
set_perm $MODPATH/post-fs-data.sh 0 0 0755
set_perm $MODPATH/service.sh 0 0 0755
[ -f "$MODPATH/sepolicy.rule" ] && set_perm $MODPATH/sepolicy.rule 0 0 0644

ui_print "- Permissions set"
ui_print ""
ui_print "Strategy:"
ui_print "  1. Try to repair BPF program loading"
ui_print "  2. Fall back to xt_qtaguid/uid_stat if needed"
ui_print "  3. Ensure interface-level stats at minimum"
ui_print ""
ui_print "- Install complete. Reboot required."
ui_print "  After reboot, check: cat /data/local/tmp/netstats-fix.log"
ui_print "========================================"
