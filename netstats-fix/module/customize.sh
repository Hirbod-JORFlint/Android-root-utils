#!/system/bin/sh
# customize.sh - Install-time checks for netstats-fix v7 (Binder proxy)
# Runs during module installation via Magisk/KernelSU

ui_print "- Installing Network Stats Fix v7 (Binder proxy)"

# Detect Android version
API_LEVEL=$(getprop ro.build.version.sdk 2>/dev/null)
if [ -n "$API_LEVEL" ] && [ "$API_LEVEL" -lt 35 ]; then
    ui_print "Warning: This module is designed for Android 16 (API 35+)"
    ui_print "Your device is running API $API_LEVEL"
    ui_print "The traffic indicator fix may not work correctly"
fi

# Set permissions for proxy DEX
set_perm $MODPATH/proxy.dex 0 0 644

ui_print ""
ui_print "Installation complete!"
ui_print "Reboot to apply the traffic indicator fix."
ui_print ""
