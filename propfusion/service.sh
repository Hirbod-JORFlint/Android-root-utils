#!/system/bin/sh

MODDIR=${0%/*}

# Wait until Android is mostly booted.
until [ "$(getprop sys.boot_completed)" = "1" ]; do
    sleep 2
done

sleep 5

########################################
# Built-in tweaks
########################################


#resetprop debug.stagefright.ccodec 1
resetprop media.stagefright.thumbnail.prefer_hw_codecs false
resetprop vendor.media.omx 0

resetprop media.stagefright.enable-player true
resetprop media.stagefright.enable-http true

resetprop media.stagefright.enable-aac true
resetprop media.stagefright.enable-fma2dp true
resetprop media.stagefright.enable-qcp true
resetprop media.stagefright.enable-scan true

########################################
# External property file
########################################

PROPFILE=""

for file in \
    /data/local/resetprop.conf \
    /data/resetprop.conf \
    /sdcard/resetprop.conf \
    /storage/emulated/0/resetprop.conf
do
    if [ -f "$file" ]; then
        PROPFILE="$file"
        break
    fi
done

if [ -n "$PROPFILE" ]; then
    while IFS= read -r line || [ -n "$line" ]; do

        # Remove whitespace
        line="$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"

        # Skip empty lines
        [ -z "$line" ] && continue

        # Skip comments
        case "$line" in
            \#*) continue ;;
        esac

        # Skip malformed lines
        case "$line" in
            *=*)
                prop="${line%%=*}"
                value="${line#*=}"

                [ -n "$prop" ] && resetprop "$prop" "$value"
                ;;
        esac

    done < "$PROPFILE"
fi