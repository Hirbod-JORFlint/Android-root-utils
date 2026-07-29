#!/system/bin/sh
LOG=/data/local/tmp/netproxy.log
echo "$(date) [post-fs-data-lite] started" > "$LOG"
chmod 0644 /proc/net/dev 2>/dev/null
exit 0
