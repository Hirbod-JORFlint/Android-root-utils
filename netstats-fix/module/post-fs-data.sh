#!/system/bin/sh
chmod 0644 /proc/net/dev 2>/dev/null
KERNEL_MAJOR=$(uname -r 2>/dev/null | cut -d. -f1)
KERNEL_MAJOR=${KERNEL_MAJOR:-0}
if [ "$KERNEL_MAJOR" -lt 5 ] 2>/dev/null; then
    for MP in /system/lib/modules/xt_qtaguid.ko /vendor/lib/modules/xt_qtaguid.ko; do
        [ -f "$MP" ] && insmod "$MP" 2>/dev/null && break
    done
    [ ! -e /dev/xt_qtaguid ] && mknod /dev/xt_qtaguid c 10 229 2>/dev/null
    chmod 0666 /dev/xt_qtaguid 2>/dev/null
fi
exit 0
