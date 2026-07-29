#!/system/bin/sh
ui_print "- Installing Network Stats Fix v9 (Raw Binder ioctl)"
set_perm $MODPATH/system/bin/netproxy 0 0 755
ui_print ""
ui_print "Installation complete!"
ui_print "Reboot to apply the fix."
ui_print "After boot check: cat /data/local/tmp/netproxy.log"
