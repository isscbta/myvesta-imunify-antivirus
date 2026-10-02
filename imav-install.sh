#!/bin/bash
# info: install myvesta-imunify-antivirus on a myVesta server
# options: [--key LICENSE_KEY] [--wf-key WORDFENCE_KEY] [--email ADDRESS] [--mail-transport sendmail|mailgun] [--mailgun-key KEY] [--mailgun-domain DOMAIN] [--no-hook] [--no-imunify] [--cron yes|no] [--update]
#
# Installs the v-imav-* commands and functions into /usr/local/vesta, writes
# the ImunifyAV stand-alone integration config, runs the official ImunifyAV
# installer, applies the ImunifyAV settings and registers the notification
# hook. At the end it asks for the mail transport and default recipient, an
# optional Wordfence Intelligence API key, and whether to install the nightly
# scan cron job. Safe to run again.
#
#   --key KEY       register an ImunifyAV+ license during installation
#   --email ADDR    default recipient of alerts and security reports
#                   (ALERT_EMAIL and REPORT_EMAIL in imav.conf)
#   --mail-transport sendmail|mailgun
#                   how mail is sent; mailgun needs MAILGUN_API_KEY and
#                   MAILGUN_DOMAIN in imav.conf (asked for, or given with
#                   --mailgun-key KEY and --mailgun-domain DOMAIN)
#   --wf-key KEY    Wordfence Intelligence v3 API key (free, from a
#                   wordfence.com account) for v-imav-vuln-scan; without this
#                   option the script asks, Enter skips it
#   --no-hook       do not register the notification hook
#   --no-imunify    do not run the ImunifyAV installer (only copy the files)
#   --cron yes|no   install the nightly cron job without asking
#                   (without this option the script asks; when there is no
#                   terminal, the cron job is not installed)
#   --update        only copy files, set permissions and re-register the hook
#                   (used by imav-update.sh); an existing cron job is refreshed

set -o pipefail

VESTA='/usr/local/vesta'
REPO_DIR=$(cd "$(dirname "$0")" && pwd)
IMAV_DEPLOY_URL='https://repo.imunify360.cloudlinux.com/defence360/imav-deploy.sh'
UI_PATH='/opt/imunifyav-ui'
HOOK="$VESTA/bin/v-imav-notify-hook"
CRON_TARGET='/etc/cron.d/myvesta-imav'

WF_FEED_URL='https://www.wordfence.com/api/intelligence/v3/vulnerabilities/scanner'

license_key=''
wf_key=''
opt_email=''
opt_transport=''
opt_mg_key=''
opt_mg_domain=''
with_hook=1
with_imunify=1
with_cron='ask'
update_only=0

while [ $# -gt 0 ]; do
    case $1 in
        --key)        license_key=$2; shift 2 ;;
        --wf-key)     wf_key=$2; shift 2 ;;
        --email)      opt_email=$2; shift 2 ;;
        --mail-transport) opt_transport=$2; shift 2 ;;
        --mailgun-key)    opt_mg_key=$2; shift 2 ;;
        --mailgun-domain) opt_mg_domain=$2; shift 2 ;;
        --no-hook)    with_hook=0; shift ;;
        --no-imunify) with_imunify=0; shift ;;
        --cron)       with_cron=$2; shift 2 ;;
        --update)     update_only=1; shift ;;
        -h|--help)    sed -n '2,28p' "$0"; exit 0 ;;
        *)            echo "Unknown option: $1"; exit 1 ;;
    esac
done
case $with_cron in
    ask|yes|no) ;;
    *) echo "Invalid value for --cron: $with_cron (use yes or no)"; exit 1 ;;
esac
case $opt_transport in
    ''|sendmail|mailgun) ;;
    *) echo "Invalid value for --mail-transport: $opt_transport (use sendmail or mailgun)"; exit 1 ;;
esac

say() { echo "= $1"; }
fail() { echo "- Error: $1" >&2; exit 1; }

# Check a Wordfence Intelligence key by downloading the feed into the cache
# that v-imav-vuln-scan uses (the feed is rate limited per IP, so one request
# must serve both the check and the first scan). Sets wf_code to the HTTP
# code. Returns 0 unless the key was rejected (401/403).
# $1 = key
wf_key_valid() {
    local cache='/var/cache/imav/wf-scanner.json'
    mkdir -p /var/cache/imav
    wf_code=$(curl -sS -f -L --max-time 900 -o "$cache.tmp" -w '%{http_code}' \
        -H "Authorization: Bearer $1" -H 'Accept: application/json' "$WF_FEED_URL" 2>/dev/null)
    if [ "$wf_code" = '200' ] && [ -s "$cache.tmp" ]; then
        mv -f "$cache.tmp" "$cache"
    else
        rm -f "$cache.tmp"
    fi
    [ "$wf_code" != '401' ] && [ "$wf_code" != '403' ]
}

# Message after a key check
wf_key_report() {
    case $wf_code in
        200) say "Wordfence Intelligence key stored in $VESTA/conf/imav.conf, feed downloaded to the cache" ;;
        429) say "Wordfence Intelligence key stored in $VESTA/conf/imav.conf (feed rate limited right now, v-imav-vuln-scan will download it later)" ;;
        *)   say "Wordfence Intelligence key stored in $VESTA/conf/imav.conf (feed download returned HTTP ${wf_code:-none}, v-imav-vuln-scan will retry)" ;;
    esac
}

# Store a value in imav.conf
# $1 = key, $2 = value
conf_set() {
    local escaped=${2//|/\\|}
    escaped=${escaped//&/\\&}
    if grep -q "^$1=" "$VESTA/conf/imav.conf"; then
        sed -i "s|^$1=.*|$1='$escaped'|" "$VESTA/conf/imav.conf"
    else
        echo "$1='$escaped'" >> "$VESTA/conf/imav.conf"
    fi
}

# Read a value from imav.conf
# $1 = key
conf_get() {
    grep "^$1=" "$VESTA/conf/imav.conf" | head -n 1 | cut -d "'" -f 2
}

# Store the Wordfence key in imav.conf
# $1 = key
wf_key_store() {
    conf_set 'WF_API_KEY' "$1"
}

# Files under files/ map to / on the server
FILES_DIR="$REPO_DIR/files"
DEFAULT_CONF="$FILES_DIR/usr/local/vesta/conf/imav.conf"
CRON_FILE="$FILES_DIR/etc/cron.d/myvesta-imav"
INTEGRATION_CONF="$FILES_DIR/etc/sysconfig/imunify360/integration.conf"
NOTIFY_PATH_UNIT="$FILES_DIR/etc/systemd/system/myvesta-imav-notify.path"
NOTIFY_SERVICE_UNIT="$FILES_DIR/etc/systemd/system/myvesta-imav-notify.service"
SPOOL='/var/spool/myvesta-imav'


#----------------------------------------------------------#
#                    Verifications                         #
#----------------------------------------------------------#

if [ "$(id -u)" -ne 0 ]; then
    fail "this script must be run as root"
fi
if [ ! -d "$VESTA/bin" ] || [ ! -f "$VESTA/func/main.sh" ]; then
    fail "myVesta was not found in $VESTA"
fi
if [ ! -f /etc/debian_version ]; then
    fail "only Debian is supported"
fi
debian_release=$(cut -d . -f 1 /etc/debian_version)
if [ "$debian_release" -lt 11 ] 2>/dev/null; then
    fail "Debian $debian_release is not supported by ImunifyAV stand-alone (11, 12 or 13 required)"
fi
for f in "$REPO_DIR/bin/v-imav-malware-scan" "$REPO_DIR/func/imav.sh" "$DEFAULT_CONF" "$CRON_FILE" "$INTEGRATION_CONF" "$NOTIFY_PATH_UNIT" "$NOTIFY_SERVICE_UNIT"; do
    [ -f "$f" ] || fail "${f#$REPO_DIR/} not found, run this script from the repository clone"
done


#----------------------------------------------------------#
#                    Files                                 #
#----------------------------------------------------------#

if [ $update_only -eq 0 ]; then
    say "Installing dependencies"
    missing=''
    for pkg in jq unzip curl; do
        command -v $pkg >/dev/null 2>&1 || missing="$missing $pkg"
    done
    if [ -n "$missing" ]; then
        apt_log=$(mktemp)
        apt-get update -qq > "$apt_log" 2>&1
        for pkg in $missing; do
            if DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$pkg" >> "$apt_log" 2>&1; then
                continue
            fi
            # The newest indexed version may be gone from the pool (a security
            # suite past its end of life): try the other available versions
            installed=0
            for ver in $(apt-cache madison "$pkg" 2>/dev/null | awk -F'|' '{ gsub(/ /, "", $2); print $2 }' | sort -uV -r); do
                # pin the dependencies that ship in the same version (jq needs libjq1 of the same version)
                pins="$pkg=$ver"
                for dep in $(apt-cache depends "$pkg=$ver" 2>/dev/null | awk '/^ *Depends:/ { print $2 }' | grep -v '^<'); do
                    if apt-cache madison "$dep" 2>/dev/null | awk -F'|' '{ gsub(/ /, "", $2); print $2 }' | grep -qx "$ver"; then
                        pins="$pins $dep=$ver"
                    fi
                done
                if DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --allow-downgrades $pins >> "$apt_log" 2>&1; then
                    say "$pkg installed as version $ver (the newest indexed version is not downloadable)"
                    installed=1
                    break
                fi
            done
            if [ $installed -eq 0 ]; then
                echo "- apt output:"
                tail -n 15 "$apt_log" | sed 's/^/    /'
                rm -f "$apt_log"
                fail "could not install $pkg (see the apt output above)"
            fi
        done
        rm -f "$apt_log"
    fi
fi

say "Installing commands into $VESTA/bin"
for f in "$REPO_DIR"/bin/v-imav-*; do
    cp -f "$f" "$VESTA/bin/"
    chmod 755 "$VESTA/bin/$(basename "$f")"
    chown root:root "$VESTA/bin/$(basename "$f")"
done

say "Installing functions into $VESTA/func"
for f in "$REPO_DIR"/func/imav*.sh; do
    cp -f "$f" "$VESTA/func/"
    chmod 644 "$VESTA/func/$(basename "$f")"
    chown root:root "$VESTA/func/$(basename "$f")"
done

if [ ! -f "$VESTA/conf/imav.conf" ]; then
    say "Installing default configuration $VESTA/conf/imav.conf"
    cp "$DEFAULT_CONF" "$VESTA/conf/imav.conf"
else
    say "Keeping existing $VESTA/conf/imav.conf"
    # Add options introduced by newer versions
    while IFS= read -r line; do
        key=${line%%=*}
        grep -q "^$key=" "$VESTA/conf/imav.conf" || echo "$line" >> "$VESTA/conf/imav.conf"
    done < "$DEFAULT_CONF"
fi
chown root:root "$VESTA/conf/imav.conf"
chmod 640 "$VESTA/conf/imav.conf"
# Earlier versions granted _imunify traversal of $VESTA/conf; not needed any more
if command -v setfacl >/dev/null 2>&1; then
    setfacl -x u:_imunify "$VESTA/conf" 2>/dev/null
fi

mkdir -p "$VESTA/data/imav" /var/cache/imav /var/log/myvesta-imav
chmod 700 "$VESTA/data/imav" /var/cache/imav /var/log/myvesta-imav
touch /var/log/myvesta-imav/imav.log
# Logs and report history moved from $VESTA to /var/log/myvesta-imav
if [ "$(conf_get 'REPORT_HISTORY_DIR')" = "$VESTA/data/imav/reports" ]; then
    conf_set 'REPORT_HISTORY_DIR' '/var/log/myvesta-imav/reports'
    if [ -d "$VESTA/data/imav/reports" ] && [ ! -d /var/log/myvesta-imav/reports ]; then
        mv "$VESTA/data/imav/reports" /var/log/myvesta-imav/reports
    fi
fi
if [ -f "$VESTA/log/imav.log" ] && [ ! -s /var/log/myvesta-imav/imav.log ]; then
    cat "$VESTA/log/imav.log" >> /var/log/myvesta-imav/imav.log
    rm -f "$VESTA/log/imav.log"
fi

say "Installing the notification service (systemd path unit)"
cp -f "$NOTIFY_PATH_UNIT" "$NOTIFY_SERVICE_UNIT" /etc/systemd/system/
chmod 644 /etc/systemd/system/myvesta-imav-notify.path /etc/systemd/system/myvesta-imav-notify.service
mkdir -p "$SPOOL"
systemctl daemon-reload
systemctl enable --now myvesta-imav-notify.path >/dev/null 2>&1 \
    || echo "- Warning: could not enable myvesta-imav-notify.path"


#----------------------------------------------------------#
#                    ImunifyAV                             #
#----------------------------------------------------------#

if [ $update_only -eq 0 ]; then
    say "Writing ImunifyAV integration config /etc/sysconfig/imunify360/integration.conf"
    mkdir -p /etc/sysconfig/imunify360 "$UI_PATH"
    if [ ! -f /etc/sysconfig/imunify360/integration.conf ]; then
        cp "$INTEGRATION_CONF" /etc/sysconfig/imunify360/integration.conf
    else
        say "integration.conf already exists, leaving it unchanged"
        # panel_info became mandatory later; add it to older files
        if ! grep -q '^panel_info' /etc/sysconfig/imunify360/integration.conf; then
            say "Adding panel_info to the existing integration.conf"
            printf 'panel_info = %s/bin/v-imav-panel-info-integration\n' "$VESTA" \
                >> /etc/sysconfig/imunify360/integration.conf
        fi
    fi

    if [ $with_imunify -eq 1 ]; then
        if command -v imunify-antivirus >/dev/null 2>&1; then
            say "ImunifyAV is already installed ($(imunify-antivirus version 2>/dev/null | head -n 1))"
            if [ -n "$license_key" ]; then
                say "Registering license"
                imunify-antivirus register "$license_key" || fail "license registration failed"
            fi
        else
            say "Downloading the ImunifyAV installer"
            cd /root || fail "cannot cd to /root"
            curl -sS -f -L -o imav-deploy.sh "$IMAV_DEPLOY_URL" || fail "could not download imav-deploy.sh"
            say "Running the ImunifyAV installer (this takes a few minutes)"
            if [ -n "$license_key" ]; then
                bash imav-deploy.sh --key "$license_key" || fail "ImunifyAV installation failed"
            else
                bash imav-deploy.sh || fail "ImunifyAV installation failed"
            fi
            cd "$REPO_DIR" || true
        fi
    fi
fi

if command -v imunify-antivirus >/dev/null 2>&1; then
    if getent group _imunify >/dev/null 2>&1; then
        # The hook runs as _imunify and only drops event files here: it can
        # create files but not list the directory or read other users' files.
        chown root:_imunify "$SPOOL"
        chmod 1730 "$SPOOL"
    fi

    if [ $update_only -eq 0 ]; then
        say "Applying ImunifyAV settings"
        source "$VESTA/conf/imav.conf"
        send_files='false'; [ "$IMUNIFY_SEND_FILES_FOR_ANALYSIS" = 'yes' ] && send_files='true'
        detect_elf='false'; [ "$IMUNIFY_DETECT_ELF" = 'yes' ] && detect_elf='true'
        # One update per section, so that a rejected value does not block the others
        for setting in \
            "{\"MALWARE_SCAN_SCHEDULE\": {\"interval\": \"none\"}}" \
            "{\"MALWARE_SCAN_INTENSITY\": {\"cpu\": ${SCAN_INTENSITY_CPU:-2}, \"io\": ${SCAN_INTENSITY_IO:-2}}}" \
            "{\"MALWARE_SCANNING\": {\"rapid_scan\": true, \"hyperscan\": true, \"sends_file_for_analysis\": $send_files, \"detect_elf\": $detect_elf}}" \
            "{\"MALWARE_CLEANUP\": {\"trim_file_instead_of_removal\": false, \"keep_original_files_days\": ${IMUNIFY_KEEP_ORIGINAL_DAYS:-30}}}"
        do
            output=$(imunify-antivirus config update "$setting" 2>&1) \
                || echo "- Warning: ImunifyAV rejected $setting: $(echo "$output" | head -n 1)"
        done
    fi

    if [ $with_hook -eq 1 ]; then
        say "Registering the notification hook"
        imunify-antivirus notifications-config update "{\"rules\": {
            \"CUSTOM_SCAN_MALWARE_FOUND\": {\"SCRIPT\": {\"scripts\": [\"$HOOK\"], \"enabled\": true}},
            \"USER_SCAN_MALWARE_FOUND\": {\"SCRIPT\": {\"scripts\": [\"$HOOK\"], \"enabled\": true}}
        }}" >/dev/null 2>&1 || echo "- Warning: could not register the notification hook"
    fi

    say "Sanity check"
    imunify-antivirus version || fail "imunify-antivirus does not respond"
else
    echo "- Warning: imunify-antivirus is not installed; the v-imav-* commands need it"
fi


#----------------------------------------------------------#
#                    Mail transport and recipient          #
#----------------------------------------------------------#

if [ -n "$opt_transport" ]; then
    conf_set 'MAIL_TRANSPORT' "$opt_transport"
elif [ $update_only -eq 0 ] && [ -t 0 ]; then
    current_transport=$(conf_get 'MAIL_TRANSPORT')
    echo
    echo "Alerts and security reports are sent by mail. Choose the transport:"
    echo "  1) sendmail  - the local Exim on this server (works out of the box)"
    echo "  2) mailgun   - the Mailgun HTTP API (better deliverability for client reports;"
    echo "                 needs a Mailgun API key and sending domain)"
    read -r -p "Mail transport [1/2, Enter keeps '${current_transport:-sendmail}']: " answer
    case $answer in
        2|mailgun)  conf_set 'MAIL_TRANSPORT' 'mailgun' ;;
        1|sendmail) conf_set 'MAIL_TRANSPORT' 'sendmail' ;;
        '')         [ -z "$current_transport" ] && conf_set 'MAIL_TRANSPORT' 'sendmail' ;;
        *)          echo "- Unknown answer, keeping '${current_transport:-sendmail}'"; [ -z "$current_transport" ] && conf_set 'MAIL_TRANSPORT' 'sendmail' ;;
    esac
fi
[ -n "$opt_mg_key" ]    && conf_set 'MAILGUN_API_KEY' "$opt_mg_key"
[ -n "$opt_mg_domain" ] && conf_set 'MAILGUN_DOMAIN' "$opt_mg_domain"
# Earlier versions kept the Mailgun settings in a separate mailgun.conf;
# values that are not yet in imav.conf are taken over from it
if [ -f "$VESTA/conf/mailgun.conf" ]; then
    old_mg_key=$(grep "^API_KEY=" "$VESTA/conf/mailgun.conf" | head -n 1 | cut -d "'" -f 2)
    old_mg_domain=$(grep "^DOMAIN=" "$VESTA/conf/mailgun.conf" | head -n 1 | cut -d "'" -f 2)
    old_mg_from=$(grep "^FROM=" "$VESTA/conf/mailgun.conf" | head -n 1 | cut -d "'" -f 2)
    old_mg_url=$(grep "^API_URL=" "$VESTA/conf/mailgun.conf" | head -n 1 | cut -d "'" -f 2)
    [ -n "$old_mg_key" ]    && [ -z "$(conf_get 'MAILGUN_API_KEY')" ] && conf_set 'MAILGUN_API_KEY' "$old_mg_key"
    [ -n "$old_mg_domain" ] && [ -z "$(conf_get 'MAILGUN_DOMAIN')" ]  && conf_set 'MAILGUN_DOMAIN' "$old_mg_domain"
    [ -n "$old_mg_from" ]   && [ -z "$(conf_get 'MAILGUN_FROM')" ]    && conf_set 'MAILGUN_FROM' "$old_mg_from"
    [ -n "$old_mg_url" ]    && conf_set 'MAILGUN_API_URL' "$old_mg_url"
    say "Mailgun settings moved from $VESTA/conf/mailgun.conf to imav.conf; the old file is no longer read and can be removed"
fi
if [ "$(conf_get 'MAIL_TRANSPORT')" = 'mailgun' ]; then
    mg_key=$(conf_get 'MAILGUN_API_KEY')
    mg_domain=$(conf_get 'MAILGUN_DOMAIN')
    if [ $update_only -eq 0 ] && [ -t 0 ]; then
        if [ -z "$mg_key" ]; then
            read -r -p "Mailgun API key (Enter to set MAILGUN_API_KEY in imav.conf later): " answer
            [ -n "$answer" ] && conf_set 'MAILGUN_API_KEY' "$answer" && mg_key=$answer
        fi
        if [ -z "$mg_domain" ]; then
            read -r -p "Mailgun sending domain (Enter to set MAILGUN_DOMAIN in imav.conf later): " answer
            [ -n "$answer" ] && conf_set 'MAILGUN_DOMAIN' "$answer" && mg_domain=$answer
        fi
    fi
    if [ -z "$mg_key" ] || [ -z "$mg_domain" ]; then
        echo "- Mailgun is selected but not configured yet. Before any mail can be sent, set in $VESTA/conf/imav.conf:"
        [ -z "$mg_key" ]    && echo "    MAILGUN_API_KEY='...'"
        [ -z "$mg_domain" ] && echo "    MAILGUN_DOMAIN='...' (and optionally MAILGUN_FROM, MAILGUN_API_URL)"
    fi
fi

if [ -n "$opt_email" ]; then
    conf_set 'ALERT_EMAIL' "$opt_email"
    conf_set 'REPORT_EMAIL' "$opt_email"
    say "Default recipient set to $opt_email"
elif [ $update_only -eq 0 ] && [ -t 0 ]; then
    current_email=$(conf_get 'REPORT_EMAIL')
    echo
    echo "Every security report and every malware alert is sent to a default address"
    echo "(REPORT_EMAIL and ALERT_EMAIL in $VESTA/conf/imav.conf); per-domain recipients"
    echo "are added to it with v-imav-add-monitor."
    if [ -n "$current_email" ]; then
        read -r -p "Default recipient [Enter keeps '$current_email']: " answer
    else
        read -r -p "Default recipient (Enter to skip): " answer
    fi
    if [ -n "$answer" ]; then
        conf_set 'ALERT_EMAIL' "$answer"
        conf_set 'REPORT_EMAIL' "$answer"
        say "Default recipient set to $answer"
    elif [ -n "$current_email" ]; then
        say "Default recipient kept: $current_email"
    else
        say "No default recipient; set ALERT_EMAIL and REPORT_EMAIL in $VESTA/conf/imav.conf later"
    fi
fi


#----------------------------------------------------------#
#                    Wordfence Intelligence key            #
#----------------------------------------------------------#

# v-imav-vuln-scan always uses the WPVulnerability API; with a Wordfence
# Intelligence key it also cross-checks the Wordfence feed.
current_wf_key=$(grep '^WF_API_KEY=' "$VESTA/conf/imav.conf" | cut -d "'" -f 2)
if [ -n "$wf_key" ]; then
    if wf_key_valid "$wf_key"; then
        wf_key_store "$wf_key"
        wf_key_report
    else
        echo "- Warning: the Wordfence Intelligence key was rejected by the feed (HTTP $wf_code), not stored"
    fi
elif [ $update_only -eq 0 ] && [ -z "$current_wf_key" ] && [ -t 0 ]; then
    echo
    echo "v-imav-vuln-scan checks WordPress core, plugins and themes against the"
    echo "WPVulnerability API (no key needed). With a Wordfence Intelligence API key"
    echo "it also cross-checks the Wordfence feed for a more thorough result. The key"
    echo "is free: wordfence.com account -> Integrations -> Vulnerability Data Feed."
    read -r -p "Wordfence Intelligence API key (Enter to skip): " answer
    if [ -n "$answer" ]; then
        say "Checking the key by downloading the feed (this can take a minute)"
        if wf_key_valid "$answer"; then
            wf_key_store "$answer"
            wf_key_report
        else
            echo "- Warning: the key was rejected by the feed (HTTP $wf_code), not stored"
            echo "  Add it later as WF_API_KEY='...' in $VESTA/conf/imav.conf"
        fi
    else
        say "No Wordfence key; add it later as WF_API_KEY='...' in $VESTA/conf/imav.conf"
    fi
elif [ -n "$current_wf_key" ]; then
    say "Wordfence Intelligence key present in $VESTA/conf/imav.conf"
fi


#----------------------------------------------------------#
#                    Cron                                  #
#----------------------------------------------------------#

if [ $update_only -eq 1 ]; then
    # Keep whatever the operator decided at installation time
    if [ -f "$CRON_TARGET" ]; then
        say "Refreshing the existing cron job $CRON_TARGET"
        cp -f "$CRON_FILE" "$CRON_TARGET"
        chmod 644 "$CRON_TARGET"
    fi
else
    if [ "$with_cron" = 'ask' ]; then
        with_cron='no'
        if [ -t 0 ]; then
            echo
            echo "The nightly cron job runs 'v-imav-scan-all' (an ImunifyAV scan of the whole"
            echo "/home) every day at 03:00 and writes a summary to $VESTA/data/imav/reports/."
            echo "Free ImunifyAV otherwise scans in the background only once a month."
            read -r -p "Install the nightly cron job $CRON_TARGET? [y/N]: " answer
            case $answer in
                y|Y|yes|YES|Yes) with_cron='yes' ;;
            esac
        fi
    fi
    if [ "$with_cron" = 'yes' ]; then
        say "Installing cron job $CRON_TARGET"
        cp -f "$CRON_FILE" "$CRON_TARGET"
        chmod 644 "$CRON_TARGET"
    else
        say "Cron job not installed (copy $CRON_FILE to $CRON_TARGET later if needed)"
    fi
fi


#----------------------------------------------------------#
#                    Done                                  #
#----------------------------------------------------------#

version=$(cat "$REPO_DIR/VERSION" 2>/dev/null || echo 'unknown')
echo
echo "==============================="
if [ $update_only -eq 1 ]; then
    echo "myvesta-imunify-antivirus $version files updated."
else
    echo "myvesta-imunify-antivirus $version is ready to use."
fi
echo "==============================="
echo
echo "Use:"
echo "v-imav-malware-scan DOMAIN                  ... malware scan of a domain"
echo "v-imav-scan-path /some/path [MINUTES]       ... malware scan of a path"
echo "v-imav-vuln-scan DOMAIN                     ... vulnerable plugins, themes and core"
echo "v-imav-malware-scan-with-remediate DOMAIN   ... scan and restore or quarantine"
echo "v-imav-remediate DOMAIN [dry-run]           ... restore or quarantine known findings"
echo "v-imav-db-scan DOMAIN                       ... WordPress database scan"
echo "v-imav-list-infected [DOMAIN]               ... findings without a new scan"
echo "v-imav-scan-all                             ... whole server (the nightly cron job runs this)"
echo "v-imav-report-domain DOMAIN [EMAIL]         ... full security report of a domain, by mail"
echo "v-imav-add-monitor DOMAIN [EMAIL] [HOUR]    ... daily security report for a domain"
echo "v-imav-list-monitors                        ... domains with scheduled reports"
echo
echo "Configuration: $VESTA/conf/imav.conf (REPORT_EMAIL, MAIL_TRANSPORT, WF_API_KEY, intensity)"
echo "Test: bash $REPO_DIR/test/smoke.sh DOMAIN"
echo
