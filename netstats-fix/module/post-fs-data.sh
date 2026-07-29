#!/system/bin/sh
MODDIR=${0%/*}
LOG=/data/local/tmp/netproxy.log

echo "$(date) [post-fs-data] === started ===" > "$LOG"

echo "$(date) [post-fs-data] Kernel: $(uname -r)" >> "$LOG"
echo "$(date) [post-fs-data] Android: $(getprop ro.build.version.sdk 2>/dev/null)" >> "$LOG"
echo "$(date) [post-fs-data] Build: $(getprop ro.build.display.id 2>/dev/null || getprop ro.lineage.build.version 2>/dev/null || echo 'unknown')" >> "$LOG"

# Make /proc/net/dev world-readable
chmod 0644 /proc/net/dev 2>/dev/null
chmod 0644 /proc/self/net/dev 2>/dev/null

KERNEL_MAJOR=$(uname -r 2>/dev/null | cut -d. -f1)
KERNEL_MAJOR=${KERNEL_MAJOR:-0}
KERNEL_MINOR=$(uname -r 2>/dev/null | cut -d. -f2)
KERNEL_MINOR=${KERNEL_MINOR:-0}
KERNEL_PATCH=$(uname -r 2>/dev/null | cut -d. -f3 | cut -d- -f1)
KERNEL_PATCH=${KERNEL_PATCH:-0}

echo "$(date) [post-fs-data] Kernel version: $KERNEL_MAJOR.$KERNEL_MINOR.$KERNEL_PATCH" >> "$LOG"

# Override BPF kernel version to match actual kernel
CURRENT_OVERRIDE=$(getprop ro.bpf.kver_override 2>/dev/null)
CORRECT_KVER="$KERNEL_MAJOR.$KERNEL_MINOR.$KERNEL_PATCH"
if [ "$CURRENT_OVERRIDE" != "$CORRECT_KVER" ]; then
    resetprop ro.bpf.kver_override "$CORRECT_KVER" 2>/dev/null || \
    resetprop_phh ro.bpf.kver_override "$CORRECT_KVER" 2>/dev/null || \
    setprop ro.bpf.kver_override "$CORRECT_KVER" 2>/dev/null
    echo "$(date) [post-fs-data] Set ro.bpf.kver_override=$CORRECT_KVER" >> "$LOG"
fi

# Delete mainline_done marker so bpfloader reruns
BPF_DIR="/sys/fs/bpf/netd_shared"
[ -d "$BPF_DIR/mainline_done" ] && rm -rf "$BPF_DIR/mainline_done" 2>/dev/null && \
    echo "$(date) [post-fs-data] Deleted stale mainline_done" >> "$LOG"

# Enable BPF JIT if available
BPF_JIT_PATH="/proc/sys/net/core/bpf_jit_enable"
if [ -f "$BPF_JIT_PATH" ]; then
    echo 1 > "$BPF_JIT_PATH" 2>/dev/null && \
        echo "$(date) [post-fs-data] BPF JIT enabled" >> "$LOG"
else
    # Try sysfs alternative
    echo 1 > /sys/fs/bpf/jit_enable 2>/dev/null || \
        echo "$(date) [post-fs-data] BPF JIT not available (non-critical)" >> "$LOG"
fi

# For kernels >= 4.9, try to load required BPF modules
if [ "$KERNEL_MAJOR" -gt 4 ] || { [ "$KERNEL_MAJOR" -eq 4 ] && [ "$KERNEL_MINOR" -ge 9 ]; }; then
    # Try loading BPF-related kernel modules
    for MOD in netfilter_bpf bpf bpf_prog; do
        modprobe "$MOD" 2>/dev/null && \
            echo "$(date) [post-fs-data] Loaded kernel module: $MOD" >> "$LOG"
    done
fi

# Load xt_qtaguid for legacy kernels (< 5.0)
if [ "$KERNEL_MAJOR" -lt 5 ] 2>/dev/null; then
    for MP in /system/lib/modules/xt_qtaguid.ko /vendor/lib/modules/xt_qtaguid.ko \
              /vendor_dlkm/lib/modules/xt_qtaguid.ko /system_dlkm/lib/modules/xt_qtaguid.ko; do
        [ -f "$MP" ] && insmod "$MP" 2>/dev/null && \
            echo "$(date) [post-fs-data] Loaded $MP" >> "$LOG" && break
    done
    if [ ! -e /dev/xt_qtaguid ]; then
        mknod /dev/xt_qtaguid c 10 229 2>/dev/null
    fi
    chmod 0666 /dev/xt_qtaguid 2>/dev/null
    echo "$(date) [post-fs-data] xt_qtaguid fallback ready" >> "$LOG"
fi

# Try to restart bpfloader early to gain time
if [ -f /system/bin/bpfloader ] || [ -f /system_ext/bin/bpfloader ]; then
    setprop ctl.restart bpfloader 2>/dev/null
    echo "$(date) [post-fs-data] Early bpfloader restart triggered" >> "$LOG"
fi

echo "$(date) [post-fs-data] === complete ===" >> "$LOG"
exit 0
