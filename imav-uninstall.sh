#!/bin/bash
# info: uninstall myvesta-imunify-antivirus
# options: [--purge-imunify]
#
# Removes the v-imav-* commands, functions, cron job and the notification hook
# registration. Configuration, reports, backups and quarantine are kept.
# With --purge-imunify the ImunifyAV package itself is uninstalled as well.

VESTA='/usr/local/vesta'
purge=0
[ "$1" = '--purge-imunify' ] && purge=1

if [ "$(id -u)" -ne 0 ]; then
    echo "- Error: this script must be run as root" >&2
    exit 1
fi

if command -v imunify-antivirus >/dev/null 2>&1; then
    echo "= Removing the notification hook registration"
    imunify-antivirus notifications-config update '{"rules": {
        "CUSTOM_SCAN_MALWARE_FOUND": {"SCRIPT": {"scripts": [], "enabled": false}},
        "USER_SCAN_MALWARE_FOUND": {"SCRIPT": {"scripts": [], "enabled": false}}
    }}' >/dev/null 2>&1
fi

echo "= Removing the notification service"
systemctl disable --now myvesta-imav-notify.path >/dev/null 2>&1
rm -f /etc/systemd/system/myvesta-imav-notify.path /etc/systemd/system/myvesta-imav-notify.service
systemctl daemon-reload
rm -rf /var/spool/myvesta-imav

echo "= Removing commands and functions"
rm -f "$VESTA"/bin/v-imav-* "$VESTA"/func/imav*.sh
rm -f /etc/cron.d/myvesta-imav
if command -v setfacl >/dev/null 2>&1; then
    setfacl -x u:_imunify "$VESTA/conf" 2>/dev/null
fi

echo "= Kept: $VESTA/conf/imav.conf, $VESTA/data/imav, /var/cache/imav, /srv/wp-quarantine"

if [ $purge -eq 1 ]; then
    echo "= Uninstalling ImunifyAV"
    if [ -f /root/imav-deploy.sh ]; then
        bash /root/imav-deploy.sh --uninstall
    else
        curl -sS -f -L -o /root/imav-deploy.sh https://repo.imunify360.cloudlinux.com/defence360/imav-deploy.sh \
            && bash /root/imav-deploy.sh --uninstall
    fi
fi

echo "= Done."
