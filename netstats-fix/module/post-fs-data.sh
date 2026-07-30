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
_log "Build: $(getprop ro.build.display.id 2>/dev/null || getprop ro.build.description 2>/dev/null)"
_log "SELinux: $(getenforce 2>/dev/null || echo unknown)"

ARCH=$(getprop ro.product.cpu.abi 2>/dev/null)
_log "Arch: $ARCH"

SYSTEM_VARIANT="standard"
if [ -d "/system_axion" ]; then
    SYSTEM_VARIANT="axion"
    _log "ROM variant: Axion OS"
elif [ -d "/system_infinity" ]; then
    SYSTEM_VARIANT="infinity"
    _log "ROM variant: Infinity X"
fi

# Detect Tethering APEX bpfloader (real, not stub)
TETHERING_APEX=""
for APEX_DIR in /apex/com.android.tethering /apex/com.android.extservices; do
    if [ -d "$APEX_DIR" ]; then
        TETHERING_APEX="$APEX_DIR"
        _log "Tethering APEX: $APEX_DIR"
        break
    fi
done
[ -z "$TETHERING_APEX" ] && _log "Tethering APEX: not found"

# Ensure bpffs is mounted
BPF_DIR="/sys/fs/bpf"
BPF_NETD="$BPF_DIR/netd_shared"
if ! mount | grep -q "bpf on $BPF_DIR"; then
    mount -t bpf bpf "$BPF_DIR" 2>/dev/null && _log "Mounted bpffs at $BPF_DIR" \
        || _log "bpffs mount failed (may already be mounted)"
fi

# Determine BPF eligibility
BPF_RESTORE=0
if   [ "$KMAJOR" -gt 5 ]; then BPF_RESTORE=1
elif [ "$KMAJOR" -eq 5 ]; then BPF_RESTORE=1
elif [ "$KMAJOR" -eq 4 ] && [ "$KMINOR" -ge 14 ]; then BPF_RESTORE=1
elif [ "$KMAJOR" -eq 4 ] && [ "$KMINOR" -ge 9  ]; then BPF_RESTORE=1
fi
_log "BPF restore eligible: $BPF_RESTORE (kernel $KMAJOR.$KMINOR)"

# Load xt_qtaguid for legacy kernels
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

# ============================================================
# BPF Restoration Phase
# ============================================================
if [ "$BPF_RESTORE" -eq 1 ]; then
    _log "--- BPF Restoration ---"

    # Step 1: Remove stale mainline_done markers
    for MARKER_DIR in "$BPF_NETD/mainline_done" /dev/pmt/atomic/tebpf_mainline_done; do
        if [ -d "$MARKER_DIR" ]; then
            rm -rf "$MARKER_DIR" 2>/dev/null \
                && _log "Deleted stale marker: $MARKER_DIR" \
                || _log "WARNING: could not delete $MARKER_DIR"
        fi
    done

    # Step 2: Find bpfloader binary (prefer real over stub)
    BPFLOADER=""
    BPFLOADER_IS_STUB=0

    # Check system bpfloader first
    if [ -f /system/bin/bpfloader ]; then
        BPFLOADER="/system/bin/bpfloader"
        # Quick stub detection: check file size (stubs are tiny, real ones are >50KB)
        BSYS_SIZE=$(wc -c < /system/bin/bpfloader 2>/dev/null || echo 0)
        if [ "$BSYS_SIZE" -lt 50000 ] 2>/dev/null; then
            BPFLOADER_IS_STUB=1
            _log "System bpfloader appears to be a stub (${BSYS_SIZE} bytes)"
        fi
    fi

    # Find real bpfloader from APEX
    REAL_BPFLOADER=""
    if [ -n "$TETHERING_APEX" ]; then
        for BP in \
            "$TETHERING_APEX/bin/bpfloader" \
            "$TETHERING_APEX/bin/bpftest" \
            "$TETHERING_APEX/bin/bpfloader_real"; do
            if [ -f "$BP" ]; then
                REAL_BPFLOADER="$BP"
                _log "Found real bpfloader: $BP"
                break
            fi
        done
    fi

    # Search additional APEX paths
    if [ -z "$REAL_BPFLOADER" ]; then
        for APEX in /apex/*/bin/bpfloader; do
            if [ -f "$APEX" ]; then
                REAL_BPFLOADER="$APEX"
                _log "Found bpfloader in APEX: $APEX"
                break
            fi
        done
    fi

    # Search vendor/system DLKM paths
    if [ -z "$REAL_BPFLOADER" ]; then
        for BP in \
            /vendor_dlkm/bin/bpfloader \
            /system_dlkm/bin/bpfloader \
            /odm/bin/bpfloader; do
            if [ -f "$BP" ]; then
                REAL_BPFLOADER="$BP"
                _log "Found bpfloader: $BP"
                break
            fi
        done
    fi

    # Step 3: Set kernel version override
    CORRECT_KVER="${KMAJOR}.${KMINOR}.${KPATCH}"
    CURRENT_OVERRIDE=$(getprop ro.bpf.kver_override 2>/dev/null)
    if [ "$CURRENT_OVERRIDE" != "$CORRECT_KVER" ]; then
        _log "ro.bpf.kver_override: $CURRENT_OVERRIDE -> $CORRECT_KVER"
        resetprop ro.bpf.kver_override "$CORRECT_KVER" 2>/dev/null \
        || resetprop_phh ro.bpf.kver_override "$CORRECT_KVER" 2>/dev/null \
        || setprop ro.bpf.kver_override "$CORRECT_KVER" 2>/dev/null
    fi

    # Step 4: Set BPF-related properties
    resetprop ro.bpf.enabled 1 2>/dev/null || true
    resetprop persist.net.bpf.enable 1 2>/dev/null || true
    resetprop ro.kernel.ebpf.supported 1 2>/dev/null || true
    resetprop persist.sys.bpf.enable 1 2>/dev/null || true

    # Step 5: Enable BPF JIT
    if [ -f /proc/sys/net/core/bpf_jit_enable ]; then
        echo 1 > /proc/sys/net/core/bpf_jit_enable 2>/dev/null \
            && _log "BPF JIT enabled" || _log "BPF JIT sysctl not writable"
    fi

    # Step 6: If system bpfloader is stub and we have real one, try using it
    if [ "$BPFLOADER_IS_STUB" -eq 1 ] && [ -n "$REAL_BPFLOADER" ]; then
        _log "Attempting to use real bpfloader: $REAL_BPFLOADER"

        # Ensure bpffs is mounted
        mount -t bpf bpf "$BPF_DIR" 2>/dev/null || true

        # Try to execute real bpfloader directly
        chmod 755 "$REAL_BPFLOADER" 2>/dev/null

        # Try with different argument patterns
        for ARGS in "" "-d $BPF_DIR" "--dir $BPF_DIR" "-m"; do
            _log "  Trying: $REAL_BPFLOADER $ARGS"
            $REAL_BPFLOADER $ARGS >> "$LOG" 2>&1
            BPFLOADER_EXIT=$?
            _log "  Exit code: $BPFLOADER_EXIT"

            # Check if maps were created
            NEW_MAPS=0
            for MN in uid_owner_map app_uid_stats_map cookie_tag_map configuration_map stats_map_A stats_map_B; do
                [ -e "$BPF_NETD/map_netd_$MN" ] && NEW_MAPS=$((NEW_MAPS + 1))
            done
            if [ "$NEW_MAPS" -gt 0 ]; then
                _log "  SUCCESS: $NEW_MAPS BPF maps created via real bpfloader!"
                BPFLOADER_IS_STUB=0
                break
            fi
        done
    fi

    # Step 7: Try standard bpfloader restart (may work even if system one is stub,
    #          because init might pick up APEX version after properties are set)
    # Only if we still don't have maps
    MAP_COUNT=0
    for MN in uid_owner_map app_uid_stats_map cookie_tag_map configuration_map stats_map_A stats_map_B; do
        [ -e "$BPF_NETD/map_netd_$MN" ] && MAP_COUNT=$((MAP_COUNT + 1))
    done

    if [ "$MAP_COUNT" -eq 0 ]; then
        _log "No BPF maps yet, trying service restart..."

        # Delete any marker that reappeared
        [ -d "$BPF_NETD/mainline_done" ] && rm -rf "$BPF_NETD/mainline_done" 2>/dev/null

        # Apply SELinux rules before restart
        MP=$(command -v magiskpolicy 2>/dev/null || echo "")
        if [ -n "$MP" ]; then
            "$MP" --live "allow init bpfloader_exec:file { getattr open read execute execute_no_trans }" 2>/dev/null
            "$MP" --live "allow init bpfloader_platform_exec:file { getattr open read execute execute_no_trans }" 2>/dev/null
            "$MP" --live "allow init apex_file:file { getattr open read execute execute_no_trans }" 2>/dev/null
            "$MP" --live "allow init system_file:file { getattr open read execute execute_no_trans }" 2>/dev/null
            "$MP" --live "allow bpfloader bpffs:dir { search read write add_name remove_name create rmdir setattr }" 2>/dev/null
            "$MP" --live "allow bpfloader bpffs:file { create read write open map getattr setattr unlink }" 2>/dev/null
            "$MP" --live "allow bpfloader proc_net:file { read open getattr }" 2>/dev/null
            "$MP" --live "allow bpfloader proc_kallsyms:file { read open getattr }" 2>/dev/null
            "$MP" --live "allow bpfloader self:capability { sys_ptrace sys_admin net_admin }" 2>/dev/null
            "$MP" --live "allow bpfloader kernel:system module_request" 2>/dev/null
            "$MP" --live "allow bpfloader sysfs_btf:file { read open getattr }" 2>/dev/null
            "$MP" --live "allow bpfloader sysfs_btf:dir { search read }" 2>/dev/null
            "$MP" --live "allow bpfloader kmsg_device:chr_file { write }" 2>/dev/null
            _log "SELinux rules applied for bpfloader"
        fi

        stop bpfloader 2>/dev/null
        sleep 1
        start bpfloader 2>/dev/null

        BW=0
        while [ "$(getprop init.svc.bpfloader 2>/dev/null)" = "running" ] && [ "$BW" -lt 30 ]; do
            sleep 1; BW=$((BW+1))
        done
        _log "bpfloader completed after ${BW}s"
        sleep 2
    fi

    # Step 8: Final map count
    MAP_COUNT=0
    for MN in uid_owner_map app_uid_stats_map cookie_tag_map configuration_map stats_map_A stats_map_B; do
        [ -e "$BPF_NETD/map_netd_$MN" ] && MAP_COUNT=$((MAP_COUNT + 1))
    done
    _log "BPF maps found: $MAP_COUNT/6"
else
    _log "Skipping BPF restoration (not eligible: kernel $KMAJOR.$KMINOR)"
fi

# ============================================================
# Status reporting
# ============================================================
for MN in uid_owner_map app_uid_stats_map cookie_tag_map configuration_map stats_map_A stats_map_B; do
    p="$BPF_NETD/map_netd_$MN"
    [ -e "$p" ] && _log "  $MN: present" || _log "  $MN: absent"
done

[ -f /proc/net/xt_qtaguid/stats ] && _log "xt_qtaguid: present" || _log "xt_qtaguid: not found"
[ -d /proc/uid_stat ]             && _log "uid_stat: present"   || _log "uid_stat: not found"

if [ -d /apex/com.android.tethering ] || [ -d /apex/com.android.networking ]; then
    _log "Tethering APEX: mounted"
else
    _log "Tethering APEX: not found"
fi

[ -d /dev/cgroup ] && _log "Cgroup: mounted" || _log "Cgroup: not found"

# BPF capability summary
if [ "$KMAJOR" -ge 5 ]; then
    _log "BPF capable: full (kernel >= 5.0)"
elif [ "$KMAJOR" -eq 4 ] && [ "$KMINOR" -ge 14 ]; then
    _log "BPF capable: partial (kernel 4.14+, cgroup_skb may work with backports)"
elif [ "$KMAJOR" -eq 4 ] && [ "$KMINOR" -ge 9 ]; then
    _log "BPF capable: limited (kernel 4.9, cgroup_skb unlikely)"
else
    _log "BPF not capable (kernel < 4.9)"
fi

_log "=== post-fs-data.sh complete ==="
exit 0
