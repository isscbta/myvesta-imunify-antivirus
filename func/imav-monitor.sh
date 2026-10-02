#!/bin/bash
# myVesta ImunifyAV integration: registry of monitored domains.
#
# Domains that receive a scheduled security report are kept in
# /usr/local/vesta/data/imav/monitor.conf, one line per domain in the myVesta
# config format:
#   DOMAIN='example.com' USER='bob' EMAIL='a@x,b@y' HOUR='9' SUSPENDED='no' TIME='..' DATE='..'
# The per-domain state used for trends (file counts, administrators, plugins)
# is in /usr/local/vesta/data/imav/monitor/DOMAIN.conf.
#
# Requires func/imav.sh.

IMAV_MONITOR_CONF="$IMAV_DATA/monitor.conf"
IMAV_MONITOR_DIR="$IMAV_DATA/monitor"
IMAV_MONITOR_CRON='/etc/cron.d/myvesta-imav-monitor'

imav_monitor_init() {
    mkdir -p "$IMAV_MONITOR_DIR"
    chmod 700 "$IMAV_MONITOR_DIR"
    touch "$IMAV_MONITOR_CONF"
    chmod 600 "$IMAV_MONITOR_CONF"
}

# Registry line of a domain (empty if not monitored)
# $1 = domain
imav_monitor_get() {
    grep "^DOMAIN='$1' " "$IMAV_MONITOR_CONF" 2>/dev/null | head -n 1
}

# Is the domain monitored
# $1 = domain
imav_monitor_exists() {
    [ -n "$(imav_monitor_get "$1")" ]
}

# Add a domain to the registry
# $1 = domain, $2 = user, $3 = emails, $4 = hour
imav_monitor_add() {
    local now
    now=$(date +'%T %F')
    echo "DOMAIN='$1' USER='$2' EMAIL='$3' HOUR='$4' SUSPENDED='no' TIME='${now%% *}' DATE='${now##* }'" \
        >> "$IMAV_MONITOR_CONF"
}

# Remove a domain from the registry
# $1 = domain
imav_monitor_delete() {
    sed -i "/^DOMAIN='$1' /d" "$IMAV_MONITOR_CONF"
}

# Change one value of a monitored domain
# $1 = domain, $2 = key, $3 = value
imav_monitor_set() {
    local escaped=${3//|/\\|}
    sed -i "/^DOMAIN='$1' /s|$2='[^']*'|$2='$escaped'|" "$IMAV_MONITOR_CONF"
}

# Install the hourly cron job that runs the monitors, if missing
imav_monitor_ensure_cron() {
    if [ ! -f "$IMAV_MONITOR_CRON" ]; then
        cat > "$IMAV_MONITOR_CRON" <<'EOF'
# myvesta-imunify-antivirus: scheduled security reports for monitored domains.
# Installed by v-imav-add-monitor; v-imav-run-monitors reports the domains
# whose HOUR matches the current hour (see v-imav-list-monitors).

SHELL=/bin/bash
VESTA=/usr/local/vesta
PATH=/usr/local/vesta/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

5 * * * * root /usr/local/vesta/bin/v-imav-run-monitors >/dev/null 2>&1
EOF
        chmod 644 "$IMAV_MONITOR_CRON"
    fi
}


#----------------------------------------------------------#
#                    Per-domain state                      #
#----------------------------------------------------------#

# Read one key of the domain state
# $1 = domain, $2 = key
imav_state_get() {
    grep -m1 "^$2=" "$IMAV_MONITOR_DIR/$1.conf" 2>/dev/null | cut -d "'" -f 2
}

# Write one key of the domain state
# $1 = domain, $2 = key, $3 = value
imav_state_set() {
    local file="$IMAV_MONITOR_DIR/$1.conf" escaped=${3//\'/}
    mkdir -p "$IMAV_MONITOR_DIR"
    touch "$file"
    chmod 600 "$file"
    if grep -q "^$2=" "$file"; then
        escaped=${escaped//|/\\|}
        sed -i "s|^$2=.*|$2='$escaped'|" "$file"
    else
        echo "$2='$escaped'" >> "$file"
    fi
}
