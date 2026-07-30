#!/system/bin/sh
MODDIR=${0%/*}
LOG=/data/local/tmp/netproxy.log

_log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [post-fs-data] $*" >> "$LOG"; }

echo "" > "$LOG" 2>/dev/null || true
chmod 0666 "$LOG" 2>/dev/null

_log "=== post-fs-data.sh started ==="

KVER=$(uname -r 2>/dev/null)
KMAJOR=$(echo "$KVER" | cut -d. -f1)
KMINOR=$(echo "$KVER" | cut -d. -f2)
KPATCH=$(echo "$KVER" | cut -d. -f3 | grep -oE '^[0-9]+')
KMAJOR=${KMAJOR:-0}; KMINOR=${KMINOR:-0}; KPATCH=${KPATCH:-0}

_log "Kernel: $KVER"
_log "Android: $(getprop ro.build.version.sdk 2>/dev/null) (SDK $(getprop ro.build.version.sdk 2>/dev/null))"
_log "SELinux: $(getenforce 2>/dev/null || echo unknown)"

chmod 0644 /proc/net/dev 2>/dev/null
chmod 0644 /proc/self/net/dev 2>/dev/null

BPF_DIR="/sys/fs/bpf"
BPF_NETD="$BPF_DIR/netd_shared"
if ! mount | grep -q "bpf on $BPF_DIR"; then
    mount -t bpf bpf "$BPF_DIR" 2>/dev/null && _log "Mounted bpffs at $BPF_DIR" \
        || _log "bpffs mount failed (may already be mounted)"
fi

BPF_RESTORE=0
if   [ "$KMAJOR" -gt 5 ]; then BPF_RESTORE=1
elif [ "$KMAJOR" -eq 5 ]; then BPF_RESTORE=1
elif [ "$KMAJOR" -eq 4 ] && [ "$KMINOR" -ge 14 ]; then BPF_RESTORE=1
elif [ "$KMAJOR" -eq 4 ] && [ "$KMINOR" -ge 9  ]; then BPF_RESTORE=1
fi

_log "BPF restore eligible: $BPF_RESTORE (kernel $KMAJOR.$KMINOR)"

if [ "$BPF_RESTORE" -eq 1 ]; then
    if [ -d "$BPF_NETD/mainline_done" ]; then
        rm -rf "$BPF_NETD/mainline_done" 2>/dev/null \
            && _log "Deleted mainline_done marker" \
            || _log "WARNING: could not delete mainline_done"
    fi

    CORRECT_KVER="${KMAJOR}.${KMINOR}.${KPATCH}"
    CURRENT_OVERRIDE=$(getprop ro.bpf.kver_override 2>/dev/null)
    if [ "$CURRENT_OVERRIDE" != "$CORRECT_KVER" ]; then
        _log "ro.bpf.kver_override: $CURRENT_OVERRIDE -> $CORRECT_KVER"
        resetprop ro.bpf.kver_override "$CORRECT_KVER" 2>/dev/null \
        || resetprop_phh ro.bpf.kver_override "$CORRECT_KVER" 2>/dev/null \
        || setprop ro.bpf.kver_override "$CORRECT_KVER" 2>/dev/null
        _log "Set ro.bpf.kver_override=$CORRECT_KVER"
    fi

    resetprop ro.bpf.enabled 1 2>/dev/null || setprop ro.bpf.enabled 1 2>/dev/null
    resetprop persist.net.bpf.enable 1 2>/dev/null || true
    resetprop ro.kernel.ebpf.supported 1 2>/dev/null || true

    if [ -f /proc/sys/net/core/bpf_jit_enable ]; then
        echo 1 > /proc/sys/net/core/bpf_jit_enable 2>/dev/null \
            && _log "BPF JIT enabled" || _log "BPF JIT sysctl not writable"
    fi

    BPFL_STATUS=$(getprop init.svc.bpfloader 2>/dev/null)
    if [ "$BPFL_STATUS" = "stopped" ] || [ "$BPFL_STATUS" = "restarting" ]; then
        _log "Triggering early bpfloader restart (was: $BPFL_STATUS)"
        setprop ctl.restart bpfloader 2>/dev/null || start bpfloader 2>/dev/null || true
    else
        _log "bpfloader status: ${BPFL_STATUS:-not started} (deferring to service.sh)"
    fi

    if [ "$KMAJOR" -lt 5 ]; then
        for MP in \
            /vendor/lib/modules/xt_qtaguid.ko \
            /system/lib/modules/xt_qtaguid.ko \
            /vendor_dlkm/lib/modules/xt_qtaguid.ko \
            /system_dlkm/lib/modules/xt_qtaguid.ko; do
            [ -f "$MP" ] && insmod "$MP" 2>/dev/null \
                && _log "Loaded xt_qtaguid from $MP" && break
        done
        [ ! -e /dev/xt_qtaguid ] && mknod /dev/xt_qtaguid c 10 229 2>/dev/null
        chmod 0666 /dev/xt_qtaguid 2>/dev/null
    fi
else
    _log "Kernel $KMAJOR.$KMINOR < 4.9: skipping BPF ops"
fi

MAP_COUNT=0
for MAP_NAME in uid_owner_map app_uid_stats_map cookie_tag_map configuration_map stats_map_A stats_map_B; do
    MAP_PATH="$BPF_NETD/map_netd_${MAP_NAME}"
    if [ -e "$MAP_PATH" ]; then MAP_COUNT=$((MAP_COUNT + 1)); fi
done
_log "BPF maps found: $MAP_COUNT/6"
[ -f /proc/net/xt_qtaguid/stats ] && _log "xt_qtaguid: present" || _log "xt_qtaguid: not found"
[ -d /proc/uid_stat ]             && _log "uid_stat: present"   || _log "uid_stat: not found"
if [ -d /apex/com.android.tethering ] || [ -d /apex/com.android.networking ]; then
    _log "Tethering APEX: mounted"
else
    _log "Tethering APEX: not found"
fi

_log "=== post-fs-data.sh complete ==="
exit 0
