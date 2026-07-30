#!/system/bin/sh

ui_print ""
ui_print "  ╔══════════════════════════════════════════╗"
ui_print "  ║      Network Stats Fix for GSI v12      ║"
ui_print "  ║  Universal traffic indicator fix        ║"
ui_print "  ╚══════════════════════════════════════════╝"
ui_print ""

SYSTEM_VARIANT="system"
if [ -d "/system_axion" ]; then
    SYSTEM_VARIANT="system_axion"
    ui_print "[*] Detected: Axion OS"
elif [ -d "/system_infinity" ]; then
    SYSTEM_VARIANT="system_infinity"
    ui_print "[*] Detected: Infinity X"
elif [ -d "/system" ]; then
    SYSTEM_VARIANT="system"
    ui_print "[*] Detected: Standard AOSP"
fi

KERNEL=$(uname -r 2>/dev/null)
KMAJOR=$(echo "$KERNEL" | cut -d. -f1)
KMINOR=$(echo "$KERNEL" | cut -d. -f2)
ui_print "[*] Kernel: $KERNEL"
ui_print "[*] Android: $(getprop ro.build.version.sdk 2>/dev/null) ($(getprop ro.build.version.release 2>/dev/null))"

BPF_CAPABLE=0
if [ -n "$KMAJOR" ] && [ -n "$KMINOR" ]; then
    if [ "$KMAJOR" -gt 4 ] || { [ "$KMAJOR" -eq 4 ] && [ "$KMINOR" -ge 9 ]; }; then
        BPF_CAPABLE=1
        ui_print "[*] Kernel supports BPF (>= 4.9)"
    fi
fi

if [ "$BPF_CAPABLE" -eq 0 ]; then
    ui_print "[*] Kernel too old for BPF per-UID stats"
    ui_print "[*] Will use native proxy fallback"
fi

ROM=$(getprop ro.build.display.id 2>/dev/null || getprop ro.build.description 2>/dev/null || echo "unknown")
ui_print "[*] ROM: $ROM"

APEX=$(getprop apexd.state 2>/dev/null || echo "unknown")
ui_print "[*] APEX state: $APEX"

if [ -f /apex/com.android.tethering/apex_manifest.json ] || [ -d /apex/com.android.tethering ]; then
    ui_print "[*] Tethering APEX: present"
else
    ui_print "[!] Tethering APEX: absent (bpfloader may use system fallback)"
fi

set_perm $MODPATH/system/bin/netproxy 0 0 755
if [ -f "$MODPATH/system/bin/netproxy_arm" ]; then
    set_perm $MODPATH/system/bin/netproxy_arm 0 0 755
fi

ui_print ""
ui_print "[✓] Installation complete!"
ui_print "[i] Reboot to apply the fix."
ui_print "[i] Check logs: cat /data/local/tmp/netproxy.log"
ui_print ""
