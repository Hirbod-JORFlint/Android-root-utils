#!/system/bin/sh
# service.sh - Late boot initialization for netstats-fix v6
# Runs after system is fully booted

# Wait for boot completion
while [ "$(getprop sys.boot_completed)" != "1" ]; do
    sleep 5
done

# Small delay to ensure SystemUI has started
sleep 10

# === Step 1: Bypass restricted networking mode ===
# GSI compatibility: disable restricted networking (BPF-backed)
# This mirrors phh-on-boot.sh behavior
settings put global restricted_networking_mode 0 2>/dev/null

# === Step 2: Verify xt_qtaguid is accessible ===
if [ -e /dev/xt_qtaguid ]; then
    chmod 0666 /dev/xt_qtaguid
fi

# === Step 3: Trigger SystemUI to reload traffic stats ===
# Force restart SystemUI's traffic handler by toggling a setting
# The traffic indicator will auto-resume on next refresh cycle
am broadcast -a android.intent.action.SCREEN_ON 2>/dev/null

exit 0
