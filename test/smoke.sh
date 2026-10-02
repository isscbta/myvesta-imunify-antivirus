#!/bin/bash
# info: smoke test of the installed v-imav-* commands on a real domain
# options: DOMAIN
#
# Puts an EICAR test file into the document root of the domain, runs
# v-imav-malware-scan and checks that the file is reported, then removes the
# file and the finding. Also runs v-imav-vuln-scan, v-imav-list-infected and
# the integration scripts. Run on the server, as root, after imav-install.sh.

domain=$1
VESTA=${VESTA:-/usr/local/vesta}
export VESTA

if [ -z "$domain" ]; then
    echo "Usage: $0 DOMAIN"
    exit 1
fi
if [ "$(id -u)" -ne 0 ]; then
    echo "This test must be run as root"
    exit 1
fi

source "$VESTA/func/main.sh"
source "$VESTA/func/imav.sh"
source "$VESTA/conf/imav.conf"

pass=0
failures=0
ok()   { echo "PASS: $1"; ((pass++)); }
bad()  { echo "FAIL: $1"; ((failures++)); }

imav_domain_owner "$domain"
imav_domain_docroot "$user" "$domain"
test_file="$docroot/imav-eicar-test-$$.php"

echo "== Integration scripts"
if $VESTA/bin/v-imav-list-users-integration | jq -e '.metadata.result == "ok" and (.data | length) > 0' >/dev/null; then
    ok "v-imav-list-users-integration returns users"
else
    bad "v-imav-list-users-integration"
fi
if $VESTA/bin/v-imav-list-domains-integration | jq -e --arg d "$domain" '.data[$d].owner != null' >/dev/null; then
    ok "v-imav-list-domains-integration knows $domain"
else
    bad "v-imav-list-domains-integration"
fi

echo "== EICAR scan of $domain"
# The EICAR string is split so that this test file is not itself detected
printf '%s%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS' '-TEST-FILE!$H+H*' > "$test_file"
chown "$user:$user" "$test_file"

output=$($VESTA/bin/v-imav-malware-scan "$domain" 2>&1)
rc=$?
echo "$output" | tail -n 5
if [ $rc -eq 0 ] && echo "$output" | grep -q "$test_file"; then
    ok "v-imav-malware-scan reported the EICAR file"
else
    bad "v-imav-malware-scan did not report the EICAR file (exit $rc)"
fi

report="/home/$user/web/$domain/private/imav-scan.csv"
if [ -f "$report" ] && grep -q "$test_file" "$report"; then
    ok "report written to $report"
else
    bad "report $report missing or without the EICAR file"
fi

if $VESTA/bin/v-imav-list-infected "$domain" json | jq -e --arg f "$test_file" '.[] | select(.file == $f)' >/dev/null; then
    ok "v-imav-list-infected shows the EICAR file"
else
    bad "v-imav-list-infected does not show the EICAR file"
fi

echo "== Remediate dry run"
output=$($VESTA/bin/v-imav-remediate "$domain" dry-run 2>&1)
if echo "$output" | grep -q "$test_file"; then
    ok "v-imav-remediate dry-run lists the EICAR file"
else
    bad "v-imav-remediate dry-run"
fi

echo "== Cleanup"
rm -f "$test_file"
$VESTA/bin/v-imav-malware-scan "$domain" >/dev/null 2>&1
if $VESTA/bin/v-imav-list-infected "$domain" json | jq -e --arg f "$test_file" '.[] | select(.file == $f)' >/dev/null; then
    echo "NOTE: the removed EICAR file is still listed by ImunifyAV; remove it with:"
    echo "      imunify-antivirus malware malicious remove-from-list ..."
fi

if imav_is_wordpress "$docroot"; then
    echo "== Vulnerability scan"
    if $VESTA/bin/v-imav-vuln-scan "$domain" json | jq -e 'type == "array"' >/dev/null; then
        ok "v-imav-vuln-scan returns JSON"
    else
        bad "v-imav-vuln-scan"
    fi
else
    echo "== $domain is not WordPress, skipping the vulnerability scan"
fi

echo
echo "$pass passed, $failures failed"
[ $failures -eq 0 ]
