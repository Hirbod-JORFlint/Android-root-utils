#!/system/bin/sh
LOG=/data/local/tmp/netproxy.log
echo "$(date '+%Y-%m-%d %H:%M:%S') [post-fs-data-lite] started" > "$LOG"
echo "$(date '+%Y-%m-%d %H:%M:%S') [post-fs-data-lite] Kernel: $(uname -r)" >> "$LOG"
echo "$(date '+%Y-%m-%d %H:%M:%S') [post-fs-data-lite] Android: $(getprop ro.build.version.sdk 2>/dev/null)" >> "$LOG"
echo "$(date '+%Y-%m-%d %H:%M:%S') [post-fs-data-lite] MODDIR: ${0%/*}" >> "$LOG"
chmod 0644 /proc/net/dev 2>/dev/null
chmod 0644 /proc/self/net/dev 2>/dev/null
echo "$(date '+%Y-%m-%d %H:%M:%S') [post-fs-data-lite] complete" >> "$LOG"
exit 0
