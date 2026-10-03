#!/bin/bash
# info: unit test of the security report collection and rendering
# options: NONE
#
# Builds a report from synthetic sections (no ImunifyAV, no myVesta) and
# checks the text and HTML output: overall level, summary table, tables,
# preformatted blocks and HTML escaping.

REPO_DIR=$(cd "$(dirname "$0")/.." && pwd)
VESTA=$(mktemp -d)
export VESTA
mkdir -p "$VESTA/log" "$VESTA/data/imav"
check_result() { [ "$1" -ne 0 ] && { echo "check_result: $2"; exit "$1"; }; }
parse_object_kv_list_non_eval() { :; }
E_INVALID=2; E_NOTEXIST=3; E_DISABLED=11; E_UPDATE=19; E_DISK=13
BIN="$VESTA/bin"
domain='example.com'

source "$REPO_DIR/func/imav.sh"
source "$REPO_DIR/func/imav-monitor.sh"
source "$REPO_DIR/func/imav-report.sh"

pass=0; failures=0
ok()  { pass=$((pass + 1)); }
bad() { echo "FAIL: $1"; failures=$((failures + 1)); }

imav_report_begin

report_section 'malware' 'Malware scan (ImunifyAV)'
report_summary 'clean, 1234 files scanned'
report_line 'No infected files were found.'

report_section 'vuln' 'Known vulnerabilities'
report_level WARNING
report_summary '1 vulnerability, highest CVSS 7.5'
report_line 'One vulnerability matches.'
report_line ''
report_table_header 'Type' 'Component' 'Installed' 'Vulnerability' 'CVSS'
report_table_row 'plugin' 'wp-rocket' '3.21.3' 'WP Rocket <3.23.3.3 & "quotes"' '7.5'
report_table_row 'theme' 'x' '' 'empty column kept' ''

report_section 'core' 'Core integrity'
report_level CRITICAL
report_summary '2 modified files'
report_line 'Modified core files:'
printf '  wp-includes/a.php\n  wp-admin/b.php\n' | report_block

report_section 'php' 'PHP version'
report_level INFO
report_summary 'PHP 8.2'
report_line 'Fine.'

overall=$(imav_report_overall_level)
[ "$overall" = 'CRITICAL' ] && ok || bad "overall level expected CRITICAL, got $overall"

text=$(imav_report_render_text "$overall")
html=$(imav_report_render_html "$overall")
imav_report_end
rm -rf "$VESTA"

echo "$text" | grep -q 'Status: CRITICAL' && ok || bad 'text: status line'
echo "$text" | grep -q '\[WARNING\] Known vulnerabilities: 1 vulnerability' && ok || bad 'text: summary row'
echo "$text" | grep -q 'plugin  |  wp-rocket  |  3.21.3' && ok || bad 'text: table row'
echo "$text" | grep -q '^  wp-includes/a.php$' && ok || bad 'text: preformatted block'
echo "$text" | grep -q 'ImunifyAV' && ok || bad 'text: scanner note'

echo "$html" | grep -q '<title>Security report: example.com</title>' && ok || bad 'html: title'
echo "$html" | grep -q 'Status: <b>CRITICAL</b>' && ok || bad 'html: status'
echo "$html" | grep -q '#c62828' && ok || bad 'html: critical colour'
echo "$html" | grep -q '<th style="[^"]*">Component</th>' && ok || bad 'html: table header'
echo "$html" | grep -q 'WP Rocket &lt;3.23.3.3 &amp; &quot\|WP Rocket &lt;3.23.3.3 &amp; "quotes"' && ok || bad 'html: escaping'
[ "$(echo "$html" | grep -c '<td style="[^"]*">-</td>')" -ge 2 ] && ok || bad 'html: empty cells kept as -'
echo "$text" | grep -q 'theme  |  x  |  -  |  empty column kept  |  -' && ok || bad 'text: empty cells kept as -'
echo "$html" | grep -q '<pre style' && ok || bad 'html: preformatted block'
[ "$(echo "$html" | grep -c '<pre style')" -eq 1 ] && ok || bad "html: two block lines must form one <pre>, got $(echo "$html" | grep -c '<pre style')"
echo "$html" | grep -q '^  wp-includes/a.php$' && ok || bad 'html: block lines separated by newlines inside the <pre>'
[ "$(echo "$html" | grep -c '<table')" -eq 2 ] && ok || bad "html: expected 2 tables (summary + vuln), got $(echo "$html" | grep -c '<table')"
echo "$html" | grep -q 'id="02-vuln"' && ok || bad 'html: section anchor'

echo "$pass passed, $failures failed"
[ $failures -eq 0 ]
