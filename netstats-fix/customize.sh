#!/system/bin/sh
# customize.sh - Magisk/KernelSU module installer
# Runs during module installation

ui_print "========================================"
ui_print "  Network Stats Fix (Universal GSI)"
ui_print "  v5.0 by Flint"
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
KPATCH=$(echo "$KVER" | cut -d. -f3 | cut -d- -f1)
ui_print "  Kernel version detected: ${KMAJOR}.${KMINOR}.${KPATCH}"

# Android version
ANDROID=$(getprop ro.build.version.release 2>/dev/null)
SDK=$(getprop ro.build.version.sdk 2>/dev/null)
ui_print "  Android: $ANDROID (SDK $SDK)"

# BPF filesystem
if mount | grep -q 'bpf.*\/sys\/fs\/bpf'; then
    ui_print "  BPF filesystem: mounted"
else
    ui_print "  BPF filesystem: not mounted (will mount at boot)"
fi

# BPF maps (using CORRECT names with map_netd_ prefix)
MAP_COUNT=0
for MAP in map_netd_uid_owner_map map_netd_app_uid_stats_map map_netd_cookie_tag_map \
           map_netd_configuration_map map_netd_stats_map_A map_netd_stats_map_B; do
    if [ -e "/sys/fs/bpf/netd_shared/$MAP" ]; then
        MAP_COUNT=$((MAP_COUNT + 1))
    fi
done
ui_print "  BPF maps present: $MAP_COUNT/6"

if [ "$MAP_COUNT" -ge 4 ]; then
    ui_print "  BPF maps: GOOD (most maps present)"
elif [ "$MAP_COUNT" -gt 0 ]; then
    ui_print "  BPF maps: PARTIAL (some maps present, repair will try)"
else
    ui_print "  BPF maps: MISSING (module will attempt repair)"
fi

# mainline_done marker
if [ -d /sys/fs/bpf/netd_shared/mainline_done ]; then
    ui_print "  mainline_done: present (module will force retry)"
fi

# Tethering APEX
if [ -d /apex/com.android.tethering ]; then
    ui_print "  Tethering APEX: mounted"
else
    ui_print "  Tethering APEX: NOT mounted (required for BPF)"
fi

# Legacy stats interfaces
LEGACY_AVAILABLE=0
if [ -f /proc/net/xt_qtaguid/stats ]; then
    ui_print "  xt_qtaguid: AVAILABLE (per-UID legacy)"
    LEGACY_AVAILABLE=1
elif [ -c /dev/xt_qtaguid ]; then
    ui_print "  xt_qtaguid: device exists"
else
    ui_print "  xt_qtaguid: not found"
fi

if [ -d /proc/uid_stat ]; then
    ui_print "  uid_stat: AVAILABLE (TCP legacy)"
    LEGACY_AVAILABLE=1
else
    ui_print "  uid_stat: not found"
fi

# Current settings
RNM=$(settings get global restricted_networking_mode 2>/dev/null || echo "unknown")
NSE=$(settings get global network_stats_enabled 2>/dev/null || echo "unknown")
ui_print "  restricted_networking_mode: $RNM"
ui_print "  network_stats_enabled: $NSE"

# ro.bpf.kver_override
KVER_PROP=$(getprop ro.bpf.kver_override 2>/dev/null)
ui_print "  ro.bpf.kver_override: ${KVER_PROP:-not set}"

# SELinux
SELINUX=$(getenforce 2>/dev/null || echo unknown)
ui_print "  SELinux: $SELINUX"

ui_print ""

# ---- Capability assessment ----
ui_print "- Capability Assessment:"

if [ "$KMAJOR" -lt 4 ] || { [ "$KMAJOR" -eq 4 ] && [ "$KMINOR" -lt 9 ]; }; then
    ui_print "  Kernel is too old (< 4.9)"
    ui_print "    Cannot support BPF at all"
    ui_print "    Will use legacy fallback if available"
elif [ "$KMAJOR" -lt 5 ]; then
    ui_print "  Kernel $KMAJOR.$KMINOR has LIMITED BPF"
    ui_print "    cgroup_skb not fully supported (< 5.0)"
    ui_print "    BPF maps may still load; interface-level stats as fallback"
else
    ui_print "  Kernel $KMAJOR.$KMINOR supports full BPF"
    ui_print "    cgroup_skb programs should work for per-UID stats"
fi

if [ "$LEGACY_AVAILABLE" -eq 1 ]; then
    ui_print "  Legacy interfaces available as fallback"
fi

ui_print ""

# ---- What the module will do ----
ui_print "- Module Installation:"
ui_print "  1. Sets ro.bpf.kver_override to actual kernel version"
ui_print "  2. Deletes mainline_done to force BPF reload"
ui_print "  3. Adds SELinux policies for netd BPF map access"
ui_print "  4. Ensures network_stats_enabled=1"
ui_print "  5. Monitors and maintains settings"
ui_print ""
ui_print "  v5.0 changes:"
ui_print "  - FIXED: BPF map name checks (map_netd_ prefix)"
ui_print "  - FIXED: Removed setenforce 0 (was causing boot loops)"
ui_print "  - IMPROVED: SELinux policies for netd BPF access"
ui_print ""

# ---- Set permissions ----
ui_print "- Setting permissions..."
set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/post-fs-data.sh" 0 0 0755
set_perm "$MODPATH/service.sh" 0 0 0755
[ -f "$MODPATH/sepolicy.rule" ] && set_perm "$MODPATH/sepolicy.rule" 0 0 0644

ui_print "- Permissions set"
ui_print ""

# ---- Next steps ----
ui_print "- Next steps:"
ui_print "  1. Reboot your device"
ui_print "  2. Wait 2 minutes for module to initialize"
ui_print "  3. Check logs: cat /data/local/tmp/netstats-fix.log"
ui_print ""
ui_print "========================================"
ui_print "- Installation Complete"
ui_print "- Reboot required for changes to take effect"
ui_print "========================================"
