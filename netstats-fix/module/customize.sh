#!/system/bin/sh

ui_print ""
ui_print "  ╔══════════════════════════════════════════╗"
ui_print "  ║      Network Stats Fix for GSI v17      ║"
ui_print "  ║  Universal traffic indicator fix        ║"
ui_print "  ║  Fake BPF maps + binder proxy + uid_stat ║"
ui_print "  ╚══════════════════════════════════════════╝"
ui_print ""

SYSTEM_VARIANT="system"
if [ -d "/system_axion" ]; then
    SYSTEM_VARIANT="system_axion"
    ui_print "[*] Detected: Axion OS (/system_axion)"
elif [ -d "/system_infinity" ]; then
    SYSTEM_VARIANT="system_infinity"
    ui_print "[*] Detected: Infinity X (/system_infinity)"
elif [ -d "/system" ]; then
    SYSTEM_VARIANT="system"
    ui_print "[*] Detected: Standard AOSP (/system)"
fi

KERNEL=$(uname -r 2>/dev/null)
KMAJOR=$(echo "$KERNEL" | cut -d. -f1)
KMINOR=$(echo "$KERNEL" | cut -d. -f2)
KPATCH=$(echo "$KERNEL" | cut -d. -f3 | grep -oE '^[0-9]+')
KMAJOR=${KMAJOR:-0}; KMINOR=${KMINOR:-0}; KPATCH=${KPATCH:-0}
ui_print "[*] Kernel: $KERNEL ($KMAJOR.$KMINOR.$KPATCH)"
SDK=$(getprop ro.build.version.sdk 2>/dev/null || echo "?")
REL=$(getprop ro.build.version.release 2>/dev/null || echo "?")
ui_print "[*] Android: $REL (SDK $SDK)"

BPF_CAPABLE=0
if [ "$KMAJOR" -gt 4 ] || { [ "$KMAJOR" -eq 4 ] && [ "$KMINOR" -ge 9 ]; }; then
    BPF_CAPABLE=1
    ui_print "[*] Kernel supports eBPF (>= 4.9)"
fi

if [ "$BPF_CAPABLE" -eq 0 ]; then
    ui_print "[*] Kernel too old for BPF per-UID stats"
    ui_print "[*] Will use native proxy + file fallback"
fi

if  [ -f /proc/net/dev ]; then
    ui_print "[*] /proc/net/dev: accessible"
else
    ui_print "[!] /proc/net/dev: NOT FOUND (stat monitoring will fail)"
fi

if [ -d /apex/com.android.tethering ] || [ -f /apex/com.android.tethering/apex_manifest.json ]; then
    ui_print "[*] Tethering APEX: present"
else
    ui_print "[!] Tethering APEX: absent (stats service may be in /system)"
fi

BPF_OVERRIDE=$(getprop ro.bpf.kver_override 2>/dev/null || echo "not set")
ui_print "[*] BPF kver_override: $BPF_OVERRIDE"
ui_print "[*] SELinux: $(getenforce 2>/dev/null || echo unknown)"
ROM=$(getprop ro.build.display.id 2>/dev/null || getprop ro.build.description 2>/dev/null || echo "unknown")
ui_print "[*] ROM: $ROM"

set_perm $MODPATH/system/bin/netproxy 0 0 755
if [ -f "$MODPATH/system/bin/netproxy_arm" ]; then
    set_perm $MODPATH/system/bin/netproxy_arm 0 0 755
fi

ui_print ""
ui_print "[✓] Installation complete!"
ui_print "[i] Reboot to apply the fix."
ui_print "[i] Check logs: cat /data/local/tmp/netproxy.log"
ui_print "[i] Debug: cat /data/local/tmp/netproxy_stats"
ui_print ""
