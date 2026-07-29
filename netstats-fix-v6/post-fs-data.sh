#!/system/bin/sh
# post-fs-data.sh - Early boot initialization for netstats-fix v6
# Runs after /data is decrypted

# Ensure /proc/net/dev is world-readable (SystemUI needs this)
chmod 0644 /proc/net/dev 2>/dev/null

# Load xt_qtaguid module early for kernels <5.0
# We use shell arithmetic comparison to avoid requiring bc
KERNEL_MAJOR=$(uname -r 2>/dev/null | cut -d. -f1)
KERNEL_MAJOR=${KERNEL_MAJOR:-0}
if [ "$KERNEL_MAJOR" -lt 5 ] 2>/dev/null; then
    for MODPATH in /system/lib/modules/xt_qtaguid.ko /vendor/lib/modules/xt_qtaguid.ko; do
        [ -f "$MODPATH" ] && insmod "$MODPATH" 2>/dev/null && break
    done
    # Create qtaguid device node if missing
    [ ! -e /dev/xt_qtaguid ] && mknod /dev/xt_qtaguid c 10 229 2>/dev/null
    chmod 0666 /dev/xt_qtaguid 2>/dev/null
fi

exit 0
