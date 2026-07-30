#!/system/bin/sh
MODDIR=${0%/*}
LOG=/data/local/tmp/netproxy.log

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [service-lite] $*" >> "$LOG"; }
logv() { echo "$(date '+%Y-%m-%d %H:%M:%S') [service-lite-verb] $*" >> "$LOG"; }

find_netproxy() {
    local probe
    for probe in \
        "$MODDIR/system/bin/netproxy" \
        "${0%/*}/system/bin/netproxy" \
        "/data/adb/modules/netstats-fix/system/bin/netproxy" \
        "/data/adb/modules/netstats-fix-lite/system/bin/netproxy" \
        "/system/bin/netproxy"; do
        [ -f "$probe" ] && { echo "$probe"; return 0; }
    done
    local found
    found=$(find /data/adb/modules -name "netproxy" -type f 2>/dev/null | head -1)
    [ -n "$found" ] && { echo "$found"; return 0; }
    return 1
}

select_arch_binary() {
    local base_bin="$1"
    local dir; dir=$(dirname "$base_bin")
    local arch; arch=$(getprop ro.product.cpu.abi 2>/dev/null)
    case "$arch" in
        arm64-v8a|arm64)
            [ -f "$base_bin" ] && { echo "$base_bin"; return 0; }
            [ -f "$dir/netproxy_arm" ] && { echo "$dir/netproxy_arm"; return 0; }
            ;;
        armeabi-v7a|armeabi)
            [ -f "$dir/netproxy_arm" ] && { echo "$dir/netproxy_arm"; return 0; }
            [ -f "$base_bin" ] && { echo "$base_bin"; return 0; }
            ;;
        *)
            [ -f "$base_bin" ] && { echo "$base_bin"; return 0; }
            [ -f "$dir/netproxy_arm" ] && { echo "$dir/netproxy_arm"; return 0; }
            ;;
    esac
    return 1
}

start_nproxy() {
    local bin="$1"
    chmod 755 "$bin"
    log "Starting netproxy: $bin"
    nohup "$bin" >> "$LOG" 2>&1 &
    local pid=$!
    log "Proxy launched (pid=$pid)"
    sleep 2
    if kill -0 "$pid" 2>/dev/null; then
        log "Proxy running (PID $pid)"
        echo "$pid"
        return 0
    fi
    log "Proxy exited, retrying..."
    sleep 2
    nohup "$bin" >> "$LOG" 2>&1 &
    pid=$!
    sleep 3
    if kill -0 "$pid" 2>/dev/null; then
        log "Proxy running after retry (PID $pid)"
        echo "$pid"
        return 0
    fi
    log "Proxy failed both attempts"
    return 1
}

check_registered() {
    grep -q "registered '" "$LOG" 2>/dev/null && return 0
    [ -f /data/local/tmp/netproxy_registered ] && return 0
    return 1
}

apply_sepolicy() {
    local MP; MP=$(command -v magiskpolicy 2>/dev/null || echo "")
    [ -z "$MP" ] && { log "magiskpolicy not found; relying on sepolicy.rule"; return 0; }
    logv "Applying live SELinux rules..."
    "$MP" --live "allow domain proc_net:file { read open getattr }" 2>/dev/null
    "$MP" --live "allow domain proc_net:dir { read search open }" 2>/dev/null
    "$MP" --live "allow domain binder_device:chr_file { read write open ioctl }" 2>/dev/null
    "$MP" --live "allow domain servicemanager:binder { call transfer }" 2>/dev/null
    "$MP" --live "allow domain servicemanager:service_manager { find add }" 2>/dev/null
    "$MP" --live "allow domain netstats_service:service_manager { add }" 2>/dev/null
    "$MP" --live "allow domain default_android_service:service_manager { add find }" 2>/dev/null
    "$MP" --live "allow domain netd:fd use" 2>/dev/null
    "$MP" --live "allow system_server proc_net:file { read open getattr }" 2>/dev/null
    "$MP" --live "allow system_server proc_net:dir { read search open }" 2>/dev/null
    "$MP" --live "allow system_app proc_net:file { read open getattr }" 2>/dev/null
    "$MP" --live "allow platform_app proc_net:file { read open getattr }" 2>/dev/null
    "$MP" --live "allow * * service_manager { add find }" 2>/dev/null
    logv "SELinux policies applied"
}

# ============================================================
# Write netstats XML files that NetworkStatsService reads
# This provides interface-level stats when BPF/netproxy fail
# ============================================================
write_netstats_files() {
    log "--- Writing netstats XML fallback files ---"
    local NETSTATS_DIR="/data/misc/netstats"
    mkdir -p "$NETSTATS_DIR" 2>/dev/null

    NOW=$(date +%s 2>/dev/null || echo 1700000000)
    START=$((NOW - 86400))

    # Read all interface stats
    local ifaces="" total_rx=0 total_tx=0 total_rxp=0 total_txp=0
    local iface_rx="" iface_tx="" iface_names=""

    if [ -f /proc/net/dev ]; then
        while IFS= read -r line; do
            local iface=$(echo "$line" | cut -d: -f1 | tr -d ' ')
            [ -z "$iface" ] && continue
            [ "$iface" = "lo" ] && continue

            local vals=$(echo "$line" | cut -d: -f2)
            local rxbytes=$(echo "$vals" | awk '{print $1}')
            local rxpackets=$(echo "$vals" | awk '{print $2}')
            local txbytes=$(echo "$vals" | awk '{print $9}')
            local txpackets=$(echo "$vals" | awk '{print $10}')

            rxbytes=${rxbytes:-0}; rxpackets=${rxpackets:-0}
            txbytes=${txbytes:-0}; txpackets=${txpackets:-0}

            total_rx=$((total_rx + rxbytes))
            total_tx=$((total_tx + txbytes))
            total_rxp=$((total_rxp + rxpackets))
            total_txp=$((total_txp + txpackets))

            ifaces="$ifaces $iface"
            logv "  iface=$iface rx=$rxbytes tx=$txbytes rxp=$rxpackets txp=$txpackets"
        done < /proc/net/dev
    fi

    log "Total: rx=$total_rx tx=$total_tx interfaces='$ifaces'"

    # Write dev stats (uid=-1 means total interface stats)
    local dev_xml="<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n"
    dev_xml="${dev_xml}<stats devDetail=\"true\">\n"
    for iface in $ifaces; do
        local vals=$(grep "^ *$iface:" /proc/net/dev 2>/dev/null | cut -d: -f2)
        local rb=$(echo "$vals" | awk '{print $1}')
        local rp=$(echo "$vals" | awk '{print $2}')
        local tb=$(echo "$vals" | awk '{print $9}')
        local tp=$(echo "$vals" | awk '{print $10}')
        rb=${rb:-0}; rp=${rp:-0}; tb=${tb:-0}; tp=${tp:-0}
        dev_xml="${dev_xml}<st if=\"$iface\" dev=\"$iface\" uid=\"-1\" tag=\"0x0\" set=\"default\" rb=\"$rb\" rp=\"$rp\" tb=\"$tb\" tp=\"$tp\" />\n"
    done
    # Also add total
    dev_xml="${dev_xml}<st if=\"wlan0\" dev=\"wlan0\" uid=\"-1\" tag=\"0x0\" set=\"default\" rb=\"$total_rx\" rp=\"$total_rxp\" tb=\"$total_tx\" tp=\"$total_txp\" />\n"
    dev_xml="${dev_xml}</stats>"

    echo -e "$dev_xml" > "$NETSTATS_DIR/netstats_dev.xml" 2>/dev/null
    chmod 0644 "$NETSTATS_DIR/netstats_dev.xml" 2>/dev/null
    log "Wrote $NETSTATS_DIR/netstats_dev.xml (rx=$total_rx tx=$total_tx)"

    # Write UID stats with per-app entries for running processes
    # Get all installed packages and their UIDs
    local uid_xml="<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n"
    uid_xml="${uid_xml}<stats uidStats=\"true\">\n"

    # Query package manager for UIDs
    local pkg_list=$(pm list packages -U 2>/dev/null | head -200)
    local uid_count=0
    if [ -n "$pkg_list" ]; then
        while IFS= read -r line; do
            local pkg=$(echo "$line" | sed 's/package:\([^ ]*\).*/\1/')
            local uid=$(echo "$line" | grep -oE 'uid:[0-9]+' | cut -d: -f2)
            [ -z "$uid" ] && continue
            [ "$uid" -lt 10000 ] && continue  # Skip system UIDs

            # Create placeholder entries with 0 bytes (SystemUI will show the interface total)
            uid_xml="${uid_xml}<st uid=\"$uid\" tag=\"0x0\" set=\"default\" rb=\"0\" rp=\"0\" tb=\"0\" tp=\"0\" />\n"
            uid_count=$((uid_count + 1))
            [ "$uid_count" -ge 200 ] && break
        done <<< "$pkg_list"
    fi

    uid_xml="${uid_xml}</stats>"
    echo -e "$uid_xml" > "$NETSTATS_DIR/netstats_uid.xml" 2>/dev/null
    chmod 0644 "$NETSTATS_DIR/netstats_uid.xml" 2>/dev/null
    log "Wrote $NETSTATS_DIR/netstats_uid.xml ($uid_count UIDs)"

    # Force NetworkStatsService to re-read the files
    cmd netstats force-refresh 2>/dev/null && log "netstats force-refresh: OK" \
        || log "netstats force-refresh: not available"
    settings put global network_stats_enabled 1 2>/dev/null
}

log "=== service-lite.sh started ==="
log "MODDIR: $MODDIR"
log "Kernel: $(uname -r)"
log "Android SDK: $(getprop ro.build.version.sdk 2>/dev/null)"
log "Arch: $(getprop ro.product.cpu.abi 2>/dev/null)"
log "SELinux: $(getenforce 2>/dev/null)"
log "Build: $(getprop ro.build.display.id 2>/dev/null)"

WAIT=0
while [ "$(getprop sys.boot_completed)" != "1" ] && [ "$WAIT" -lt 180 ]; do
    sleep 1; WAIT=$((WAIT + 1))
done
log "Boot completed after ${WAIT}s"
sleep 8

apply_sepolicy

chmod 0644 /proc/net/dev 2>/dev/null
chmod 0644 /proc/self/net/dev 2>/dev/null

# Phase 1: Start netproxy
log "--- Phase 1: Starting netproxy ---"
PROXY_BIN=$(find_netproxy)
if [ -z "$PROXY_BIN" ]; then
    log "FATAL: netproxy not found"
    log "MODDIR=$MODDIR"
    log "  Contents:"
    ls -la "$MODDIR/system/bin/" 2>/dev/null | while IFS= read -r l; do log "  $l"; done
    exit 1
fi

TARGET_BIN=$(select_arch_binary "$PROXY_BIN")
[ -z "$TARGET_BIN" ] && TARGET_BIN="$PROXY_BIN"
log "Binary: $TARGET_BIN"
log "File exists: $([ -f "$TARGET_BIN" ] && echo yes || echo no)"
log "File size: $(wc -c < "$TARGET_BIN" 2>/dev/null || echo unknown) bytes"

PROXY_PID=$(start_nproxy "$TARGET_BIN")
if [ -z "$PROXY_PID" ]; then
    log "Proxy failed to start"
fi

# Phase 2: Wait for registration with exponential backoff
log "--- Phase 2: Waiting for netproxy registration ---"
REG_OK=0
BACKOFF=2
TOTAL_WAIT=0
for RTRY in 1 2 3 4 5 6 7 8; do
    sleep $BACKOFF
    TOTAL_WAIT=$((TOTAL_WAIT + BACKOFF))
    log "Registration check attempt $RTRY (waited ${TOTAL_WAIT}s, backoff=${BACKOFF}s)"

    if check_registered; then
        REG_OK=1
        log "SUCCESS: Netproxy registered with ServiceManager (attempt $RTRY)"
        break
    fi

    # Check if proxy is still alive
    if [ -n "$PROXY_PID" ] && ! kill -0 "$PROXY_PID" 2>/dev/null; then
        log "WARNING: Proxy died (PID $PROXY_PID), restarting..."
        PROXY_PID=$(start_nproxy "$TARGET_BIN")
    fi

    # Re-apply sepolicy every other attempt
    [ "$((RTRY % 2))" -eq 0 ] && apply_sepolicy 2>/dev/null

    # Increase backoff
    BACKOFF=$((BACKOFF + 1))
    [ "$BACKOFF" -gt 5 ] && BACKOFF=5
done

if [ "$REG_OK" -eq 0 ]; then
    log "WARNING: Netproxy NOT registered after ${TOTAL_WAIT}s ($RTRY attempts)"
    log "  The traffic indicator may not show per-app stats."
fi

# Phase 3: Settings
log "--- Phase 3: Settings ---"
settings put global restricted_networking_mode 0 2>/dev/null

ATTEMPT=0
while [ "$ATTEMPT" -lt 12 ]; do
    ATTEMPT=$((ATTEMPT+1))
    settings put global network_stats_enabled 1 2>/dev/null
    sleep 2
    NSE=$(settings get global network_stats_enabled 2>/dev/null)
    if [ "$NSE" = "1" ]; then
        log "network_stats_enabled=1 (attempt $ATTEMPT)"
        break
    fi
    log "  attempt $ATTEMPT: got '$NSE'"
done

settings put global netstats_enabled 1 2>/dev/null
cmd netstats force-refresh 2>/dev/null && log "netstats force-refresh: OK" \
    || log "netstats force-refresh: not available"
cmd netstatscore force-refresh 2>/dev/null || true

# Phase 4: Write netstats files fallback (always, as backup)
log "--- Phase 4: Netstats file fallback ---"
write_netstats_files

# Phase 5: Restart SystemUI only if proxy registered
log "--- Phase 5: SystemUI restart ---"
if [ "$REG_OK" -eq 1 ]; then
    sleep 3
    am force-stop com.android.systemui 2>/dev/null
    log "SystemUI killed (will restart with proxy)"
    sleep 8
    SYSUI_PID=$(pidof com.android.systemui 2>/dev/null)
    log "SystemUI running as pid=$SYSUI_PID"
else
    log "Skipping aggressive SystemUI restart (proxy not registered)"
    log "  Trying gentle refresh..."
    # Try to just refresh the netstats service
    cmd netstats force-refresh 2>/dev/null || true
    cmd netstatscore force-refresh 2>/dev/null || true
fi

# Phase 6: Summary
log "============================================"
log "SUMMARY:"
log "  Proxy registered: $([ "$REG_OK" -eq 1 ] && echo YES || echo NO)"
log "  network_stats_enabled: $(settings get global network_stats_enabled 2>/dev/null)"
log "  netstats_enabled: $(settings get global netstats_enabled 2>/dev/null)"
if [ "$REG_OK" -eq 0 ]; then
    log "  Fallback: netstats XML files written to /data/misc/netstats/"
    log "  NOTE: Per-app stats require BPF or working netstats service."
    log "  The traffic indicator may show total traffic only."
fi
log "============================================"
log "=== service-lite.sh complete ==="

# Watchdog
WD=0
while true; do
    sleep 300
    WD=$((WD+1))

    NSE=$(settings get global network_stats_enabled 2>/dev/null)
    [ "$NSE" != "1" ] && settings put global network_stats_enabled 1 2>/dev/null \
        && log "[WD-$WD] Restored network_stats_enabled"

    if pidof netproxy > /dev/null 2>&1; then
        if ! check_registered; then
            log "[WD-$WD] Proxy running but not registered, waiting..."
            sleep 10
            if ! check_registered; then
                log "[WD-$WD] Still not registered, restarting proxy"
                killall -9 netproxy 2>/dev/null || true
                sleep 1
                PROXY_PID=$(start_nproxy "$TARGET_BIN")
                for RTRY in 1 2 3; do
                    sleep 3
                    if check_registered; then
                        log "[WD-$WD] Netproxy registered (attempt $RTRY)"
                        am force-stop com.android.systemui 2>/dev/null || true
                        break
                    fi
                done
            fi
        fi
    else
        log "[WD-$WD] Proxy died, restarting..."
        PROXY_PID=$(start_nproxy "$TARGET_BIN")
    fi

    # Refresh netstats files periodically
    if [ "$((WD % 6))" -eq 0 ]; then
        write_netstats_files 2>/dev/null
    fi
done
