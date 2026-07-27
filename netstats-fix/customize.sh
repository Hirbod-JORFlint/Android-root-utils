#!/system/bin/sh
# customize.sh - Magisk/KernelSU module installer
# Runs during module installation

ui_print "========================================"
ui_print "  Network Stats Fix (Universal GSI)"
ui_print "  v4.1 by Flint"
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

# BPF maps
BPF_MAP="/sys/fs/bpf/netd_shared/map_netd_uid_stats_map"
BPF_OWNER="/sys/fs/bpf/netd_shared/map_netd_uid_owner_map"
if [ -e "$BPF_MAP" ] && [ -e "$BPF_OWNER" ]; then
    ui_print "  BPF maps: PRESENT (already working)"
else
    ui_print "  BPF maps: MISSING (module will repair)"
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

ui_print ""

# ---- Capability assessment ----
ui_print "- Capability Assessment:"

if [ "$KMAJOR" -lt 4 ] || { [ "$KMAJOR" -eq 4 ] && [ "$KMINOR" -lt 9 ]; }; then
    ui_print "  ✗ Kernel is too old (< 4.9)"
    ui_print "    Cannot support BPF at all"
    ui_print "    Will use legacy fallback if available"
elif [ "$KMAJOR" -lt 5 ]; then
    ui_print "  ◐ Kernel $KMAJOR.$KMINOR has LIMITED BPF"
    ui_print "    cgroup_skb not supported (< 5.0)"
    ui_print "    Will use legacy fallback or interface-level stats"
else
    ui_print "  ✓ Kernel $KMAJOR.$KMINOR supports full BPF"
    ui_print "    cgroup_skb programs should load"
fi

if [ "$LEGACY_AVAILABLE" -eq 1 ]; then
    ui_print "  ✓ Legacy interfaces available"
    ui_print "    Fallback to per-UID stats possible"
else
    ui_print "  ⚠ No legacy interfaces detected"
    ui_print "    Will depend on BPF or interface-level stats"
fi

ui_print ""

# ---- What the module will do ----
ui_print "- Module Installation:"
ui_print "  1. Sets ro.bpf.kver_override to actual kernel"
ui_print "  2. Deletes mainline_done to force BPF reload"
ui_print "  3. Attempts BPF repair with correct settings"
ui_print "  4. Falls back to legacy if BPF unavailable"
ui_print "  5. Ensures network_stats_enabled=1"
ui_print "  6. Monitors and maintains settings"
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
ui_print "- Diagnostics:"
ui_print "  ro.bpf.kver_override: getprop ro.bpf.kver_override"
ui_print "  Stats enabled: settings get global network_stats_enabled"
ui_print "  BPF maps: ls -la /sys/fs/bpf/netd_shared/"
ui_print "  xt_qtaguid: cat /proc/net/xt_qtaguid/stats"
ui_print ""
ui_print "========================================"
ui_print "- Installation Complete"
ui_print "- Reboot required for changes to take effect"
ui_print "========================================"
