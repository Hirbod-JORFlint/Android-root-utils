#!/system/bin/sh
LOG=/data/local/tmp/netproxy.log

_log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [post-fs-data-lite] $*" >> "$LOG"; }

chmod 0666 "$LOG" 2>/dev/null || true
echo "" >> "$LOG" 2>/dev/null || true
echo "=== BOOT $(date '+%Y-%m-%d %H:%M:%S') ===" >> "$LOG" 2>/dev/null

_log "=== post-fs-data-lite.sh started ==="
_log "MODDIR: ${0%/*}"
_log "Kernel: $(uname -r)"
_log "Android SDK: $(getprop ro.build.version.sdk 2>/dev/null)"
_log "SELinux: $(getenforce 2>/dev/null || echo unknown)"
_log "Arch: $(getprop ro.product.cpu.abi 2>/dev/null)"

_log "Detecting system variant..."
if [ -d "/system_axion" ]; then
    _log "  Detected: Axion OS (/system_axion)"
elif [ -d "/system_infinity" ]; then
    _log "  Detected: Infinity X (/system_infinity)"
else
    _log "  Detected: Standard AOSP"
fi

# ============================================================
# Phase 1: Hide BPF maps to force TrafficStats fallback to /proc/uid_stat/
# ============================================================
_log "--- Phase 1: Hide BPF maps ---"
BPF_NETD="/sys/fs/bpf/netd_shared"
if [ -d "$BPF_NETD" ]; then
    _log "BPF netd_shared dir exists, hiding maps..."
    for m in "$BPF_NETD"/*; do
        if [ -f "$m" ]; then
            chmod 0000 "$m" 2>/dev/null && _log "  Hidden: $m" || _log "  Cannot hide: $m"
        fi
    done
    _log "BPF maps hidden - TrafficStats will fall back to /proc/uid_stat/"
else
    _log "No BPF maps found (expected for lite)"
fi

# ============================================================
# Phase 2: Create /proc/uid_stat/ early
# ============================================================
_log "--- Phase 2: Setup /proc/uid_stat/ ---"
_create_uid_stat() {
    local uid="$1"
    local rx_val="$2"
    local tx_val="$3"
    mkdir -p "/proc/uid_stat/$uid" 2>/dev/null
    echo "$rx_val" > "/proc/uid_stat/$uid/tcp_rcv" 2>/dev/null
    echo "$tx_val" > "/proc/uid_stat/$uid/tcp_snd" 2>/dev/null
    chmod 0644 "/proc/uid_stat/$uid/tcp_rcv" 2>/dev/null
    chmod 0644 "/proc/uid_stat/$uid/tcp_snd" 2>/dev/null
    chown 1000:1000 "/proc/uid_stat/$uid/tcp_rcv" 2>/dev/null
    chown 1000:1000 "/proc/uid_stat/$uid/tcp_snd" 2>/dev/null
}

# Try mounting tmpfs on /proc/uid_stat/
mkdir -p /proc/uid_stat 2>/dev/null
mount -t tmpfs tmpfs /proc/uid_stat 2>/dev/null
if [ $? -eq 0 ]; then
    _log "Mounted tmpfs on /proc/uid_stat"
else
    _log "tmpfs mount failed (errno=$?), trying bind mount..."
    # Try bind mount from /data/local/tmp/uid_stat
    mkdir -p /data/local/tmp/uid_stat 2>/dev/null
    mount -t tmpfs tmpfs /data/local/tmp/uid_stat 2>/dev/null
    mount --bind /data/local/tmp/uid_stat /proc/uid_stat 2>/dev/null
    if [ $? -eq 0 ]; then
        _log "Bind mount succeeded"
    else
        _log "Bind mount failed, using direct mkdir"
    fi
fi

chmod 0755 /proc/uid_stat 2>/dev/null
chown 1000:1000 /proc/uid_stat 2>/dev/null
_log "/proc/uid_stat permissions: $(ls -la /proc/uid_stat 2>/dev/null)"

# Parse /proc/net/dev to get initial stats
_log "Parsing /proc/net/dev for initial stats..."
total_rx=0; total_tx=0
if [ -f /proc/net/dev ]; then
    while IFS= read -r line; do
        iface=$(echo "$line" | cut -d: -f1 | tr -d ' ')
        [ -z "$iface" ] && continue
        [ "$iface" = "lo" ] && continue
        case "$iface" in Inter-|face) continue;; esac
        vals=$(echo "$line" | cut -d: -f2)
        rx=$(echo "$vals" | awk '{print $1}')
        tx=$(echo "$vals" | awk '{print $9}')
        rx=${rx:-0}; tx=${tx:-0}
        total_rx=$((total_rx + rx))
        total_tx=$((total_tx + tx))
    done < /proc/net/dev 2>/dev/null
fi
_log "Total from /proc/net/dev: rx=$total_rx tx=$total_tx"

# UIDs to create
uid_list="1000 1001 10027 1013 1021 1023 1027 1028 1029 1037 1038 1039 1041 1044 1045 1046 1047 2000 2001 9999"
uid_count=0
for u in $uid_list; do uid_count=$((uid_count+1)); done
per_uid_rx=$((uid_count > 0 ? total_rx / uid_count : 0))
per_uid_tx=$((uid_count > 0 ? total_tx / uid_count : 0))

for uid in $uid_list; do
    _create_uid_stat "$uid" "$per_uid_rx" "$per_uid_tx"
done
_log "Created /proc/uid_stat/ entries for $uid_count UIDs (rx=$per_uid_rx tx=$per_uid_tx per UID)"

# Verify
_log "Verification:"
ls -la /proc/uid_stat/ 2>/dev/null | head -10 | while IFS= read -r l; do _log "  $l"; done
cat /proc/uid_stat/1000/tcp_rcv 2>/dev/null | while IFS= read -r v; do _log "  UID 1000 tcp_rcv: $v"; done

# ============================================================
# Phase 3: Load xt_qtaguid if available (for kernel < 5.0)
# ============================================================
_log "--- Phase 3: Load xt_qtaguid ---"
if [ ! -f /proc/net/xt_qtaguid/stats ]; then
    for mp in /vendor/lib/modules/xt_qtaguid.ko /system/lib/modules/xt_qtaguid.ko \
              /vendor_dlkm/lib/modules/xt_qtaguid.ko /system_dlkm/lib/modules/xt_qtaguid.ko; do
        if [ -f "$mp" ]; then
            insmod "$mp" 2>/dev/null
            if [ $? -eq 0 ]; then
                _log "Loaded xt_qtaguid from $mp"
                mknod /dev/xt_qtaguid c 10 229 2>/dev/null
                chmod 0666 /dev/xt_qtaguid 2>/dev/null
                break
            else
                _log "insmod $mp failed"
            fi
        fi
    done
    [ -f /proc/net/xt_qtaguid/stats ] && _log "xt_qtaguid now available" || _log "xt_qtaguid not available"
else
    _log "xt_qtaguid already available"
fi

# ============================================================
# Phase 4: Ensure /proc/net/dev is readable by everyone
# ============================================================
_log "--- Phase 4: Permissions ---"
chmod 0644 /proc/net/dev 2>/dev/null && _log "chmod /proc/net/dev: OK"
chmod 0644 /proc/self/net/dev 2>/dev/null || true
if [ -f /proc/uid_stat/1000/tcp_rcv ]; then
    chmod 0644 /proc/uid_stat/*/tcp_* 2>/dev/null || true
    _log "Set uid_stat file permissions"
fi

# ============================================================
# Phase 5: Diagnostics
# ============================================================
_log "--- Phase 5: Diagnostics ---"
_log "BPF maps list after hiding:"
ls -la "$BPF_NETD" 2>/dev/null | head -10 | while IFS= read -r l; do _log "  $l"; done
_log "/proc/uid_stat/ entries: $(ls /proc/uid_stat/ 2>/dev/null | wc -l)"
_log "/proc/net/xt_qtaguid/stats: $([ -f /proc/net/xt_qtaguid/stats ] && echo 'EXISTS' || echo 'NOT FOUND')"
_log "Binder devices:"
for dev in /dev/binder /dev/vndbinder /dev/hwbinder; do
    [ -e "$dev" ] && _log "  $dev: EXISTS" || _log "  $dev: NOT FOUND"
done
_log "SELinux denials:"
dmesg 2>/dev/null | grep 'avc:.*denied' | grep -iE 'binder|service_manager|netstats|proc_net|uid_stat' | tail -15 | while IFS= read -r l; do _log "  DENIAL: $l"; done

_log "=== post-fs-data-lite.sh complete ==="
exit 0
