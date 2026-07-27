#!/system/bin/sh

# Verify that this script actually ran
resetprop persist.service.media_tweaks.loaded 1

########################################
# Built-in tweaks
########################################

resetprop media.stagefright.enable-player true
resetprop media.stagefright.enable-http true

resetprop media.stagefright.enable-aac true
resetprop media.stagefright.enable-fma2dp true
resetprop media.stagefright.enable-qcp true
resetprop media.stagefright.enable-scan true

########################################
# Find external config
########################################

for PROPFILE in \
    /data/adb/resetprop.conf \
    /data/resetprop.conf \
    /data/local/tmp/resetprop.conf \
    /storage/emulated/0/resetprop.conf
do
    [ -r "$PROPFILE" ] && break
    PROPFILE=""
done

########################################
# Apply external config
########################################

if [ -n "$PROPFILE" ]; then
    resetprop persist.service.media_tweaks.config "$PROPFILE"

    while IFS= read -r line || [ -n "$line" ]; do

        case "$line" in
            ""|\#*) continue ;;
        esac

        line="${line%$'\r'}"

        key="${line%%=*}"
        value="${line#*=}"

        [ "$key" = "$line" ] && continue

        resetprop "$key" "$value"

    done < "$PROPFILE"
fi

resetprop persist.service.media_tweaks.done 1