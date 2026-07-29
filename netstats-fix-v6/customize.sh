#!/system/bin/sh
# customize.sh - Install-time checks for netstats-fix v6
# Runs during module installation via Magisk/KernelSU

# Detect Android version
API_LEVEL=$(getprop ro.build.version.sdk 2>/dev/null)
if [ -n "$API_LEVEL" ] && [ "$API_LEVEL" -lt 35 ]; then
    ui_print "Warning: This module is designed for Android 16 (API 35+)"
    ui_print "Your device is running API $API_LEVEL"
    ui_print "The traffic indicator fix may not work correctly"
fi

# Detect architecture
ARCH=$(getprop ro.product.cpu.abi 2>/dev/null)
ui_print "Device architecture: $ARCH"

# Detect kernel version
KERNEL=$(uname -r 2>/dev/null)
ui_print "Kernel: $KERNEL"

# Set permissions
set_perm_recursive $MODPATH/system 0 0 755 644
set_perm_recursive $MODPATH/system/system_ext 0 0 755 644
set_perm $MODPATH/system/system_ext/priv-app/SystemUI/SystemUI.apk 0 0 644

ui_print ""
ui_print "Installation complete!"
ui_print "Reboot to apply the traffic indicator fix."
ui_print ""
ui_print "NOTE: If traffic still doesn't show, try enabling"
ui_print "'Show network traffic' in SystemUI Tuner settings."
