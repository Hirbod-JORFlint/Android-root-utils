#!/system/bin/sh
MODDIR=${0%/*}
LOG=/data/local/tmp/netproxy.log

echo "$(date) [post-fs-data] === post-fs-data.sh started ===" > "$LOG"

echo "$(date) [post-fs-data] Kernel: $(uname -r)" >> "$LOG"
echo "$(date) [post-fs-data] Android: $(getprop ro.build.version.sdk)" >> "$LOG"

chmod 0644 /proc/net/dev 2>/dev/null

KERNEL_MAJOR=$(uname -r 2>/dev/null | cut -d. -f1)
KERNEL_MAJOR=${KERNEL_MAJOR:-0}
KERNEL_MINOR=$(uname -r 2>/dev/null | cut -d. -f2)
KERNEL_MINOR=${KERNEL_MINOR:-0}
KERNEL_PATCH=$(uname -r 2>/dev/null | cut -d. -f3 | cut -d- -f1)
KERNEL_PATCH=${KERNEL_PATCH:-0}

echo "$(date) [post-fs-data] Kernel version: $KERNEL_MAJOR.$KERNEL_MINOR.$KERNEL_PATCH" >> "$LOG"

# Override BPF kernel version to match actual kernel
CURRENT_OVERRIDE=$(getprop ro.bpf.kver_override 2>/dev/null)
if [ -z "$CURRENT_OVERRIDE" ] || [ "$CURRENT_OVERRIDE" != "$KERNEL_MAJOR.$KERNEL_MINOR.$KERNEL_PATCH" ]; then
    resetprop ro.bpf.kver_override "$KERNEL_MAJOR.$KERNEL_MINOR.$KERNEL_PATCH" 2>/dev/null || \
    resetprop_phh ro.bpf.kver_override "$KERNEL_MAJOR.$KERNEL_MINOR.$KERNEL_PATCH" 2>/dev/null
    echo "$(date) [post-fs-data] Set ro.bpf.kver_override=$KERNEL_MAJOR.$KERNEL_MINOR.$KERNEL_PATCH" >> "$LOG"
fi

# Enable BPF JIT if available
echo 1 > /proc/sys/net/core/bpf_jit_enable 2>/dev/null && \
    echo "$(date) [post-fs-data] BPF JIT enabled" >> "$LOG" || \
    echo "$(date) [post-fs-data] BPF JIT not available (non-critical)" >> "$LOG"

# Load xt_qtaguid for legacy kernels (< 5.0)
if [ "$KERNEL_MAJOR" -lt 5 ] 2>/dev/null; then
    for MP in /system/lib/modules/xt_qtaguid.ko /vendor/lib/modules/xt_qtaguid.ko /vendor_dlkm/lib/modules/xt_qtaguid.ko; do
        [ -f "$MP" ] && insmod "$MP" 2>/dev/null && echo "$(date) [post-fs-data] Loaded $MP" >> "$LOG" && break
    done
    [ ! -e /dev/xt_qtaguid ] && mknod /dev/xt_qtaguid c 10 229 2>/dev/null
    chmod 0666 /dev/xt_qtaguid 2>/dev/null
    echo "$(date) [post-fs-data] xt_qtaguid fallback ready" >> "$LOG"
fi

echo "$(date) [post-fs-data] === post-fs-data.sh complete ===" >> "$LOG"
exit 0
