#!/system/bin/sh
ui_print "- Installing Network Stats Fix v10"
ui_print ""
ui_print "Note: This module does NOT set SELinux permissive."
ui_print "All policies are applied via sepolicy.rule."
ui_print ""

set_perm $MODPATH/system/bin/netproxy 0 0 755

ui_print ""
ui_print "Installation complete!"
ui_print "Reboot to apply the fix."
ui_print "After boot check: cat /data/local/tmp/netproxy.log"
