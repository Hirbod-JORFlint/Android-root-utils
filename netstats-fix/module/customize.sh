#!/system/bin/sh
ui_print "- Installing Network Stats Fix v8 (Native Binder JNI)"
set_perm $MODPATH/proxy.dex 0 0 644
set_perm $MODPATH/system/lib64/libbinder_pool.so 0 0 644
ui_print ""
ui_print "Installation complete!"
ui_print "Reboot to apply the fix."
ui_print "After boot check: cat /data/local/tmp/netproxy.log"
