#!/bin/bash
# info: unit test of the file-based report checks on a synthetic document root
# options: NONE
#
# Builds a fake WordPress document root (no ImunifyAV, no myVesta, no network)
# and runs the checks that look at files only: PHP files in unexpected places,
# .htaccess directives, backups and logs, hidden files and symbolic links.
# Verifies the level each check assigns, so that legitimate plugin data and
# hardening recipes stay below CRITICAL.

REPO_DIR=$(cd "$(dirname "$0")/.." && pwd)
VESTA=$(mktemp -d)
export VESTA
mkdir -p "$VESTA/log" "$VESTA/data/imav"
check_result() { [ "$1" -ne 0 ] && { echo "check_result: $2"; exit "$1"; }; }
parse_object_kv_list_non_eval() { :; }
E_INVALID=2; E_NOTEXIST=3; E_DISABLED=11; E_UPDATE=19; E_DISK=13
BIN="$VESTA/bin"
# GNU stat -c is used by the checks; macOS has BSD stat
if ! stat -c %Y / >/dev/null 2>&1; then
    stat() { if [ "$1" = '-c' ]; then command stat -f '%m' "$3"; else command stat "$@"; fi; }
fi

source "$REPO_DIR/func/imav.sh"
source "$REPO_DIR/func/imav-monitor.sh"
source "$REPO_DIR/func/imav-report.sh"

pass=0; failures=0
ok()  { pass=$((pass + 1)); }
bad() { echo "FAIL: $1"; failures=$((failures + 1)); }

# Level of the current section
level_of() { cat "$REPORT_TMP/$REPORT_CURRENT.level"; }
summary_of() { cat "$REPORT_TMP/$REPORT_CURRENT.summary"; }
expect_level() {
    local got; got=$(level_of)
    [ "$got" = "$2" ] && ok || bad "$1: level expected $2, got $got ($(summary_of))"
}

user='example'
domain='example.com'
home=$(cd "$(mktemp -d)" && pwd -P)
docroot="$home/web/example.com/public_html"
mkdir -p "$docroot/wp-content/uploads" "$docroot/wp-includes" "$docroot/wp-admin"

#----------------------------------------------------------#
#        PHP files in unexpected places                    #
#----------------------------------------------------------#

imav_report_begin

# 1. clean uploads
imav_report_check_php_files
expect_level 'php_files clean' 'OK'

# 2. known plugin data only -> INFO
mkdir -p "$docroot/wp-content/uploads/sucuri" "$docroot/wp-content/uploads/wpallimport"
echo '<?php exit; ?> data' > "$docroot/wp-content/uploads/sucuri/sucuri-settings.php"
echo '<?php function x() {}' > "$docroot/wp-content/uploads/wpallimport/functions.php"
imav_report_check_php_files
expect_level 'php_files known plugin dirs' 'INFO'
summary_of | grep -q 'plugin data' && ok || bad "php_files known summary: $(summary_of)"

# 3. unknown PHP in uploads -> WARNING
mkdir -p "$docroot/wp-content/uploads/2026/01"
echo '<?php echo 1;' > "$docroot/wp-content/uploads/2026/01/shell.php"
imav_report_check_php_files
expect_level 'php_files unknown php' 'WARNING'

# 4. PHP code in an image -> CRITICAL
printf '<?php eval($_POST["x"]); ?>' > "$docroot/wp-content/uploads/2026/01/logo.png"
imav_report_check_php_files
expect_level 'php_files disguised image' 'CRITICAL'
rm -f "$docroot/wp-content/uploads/2026/01/logo.png" "$docroot/wp-content/uploads/2026/01/shell.php"

#----------------------------------------------------------#
#        .htaccess                                         #
#----------------------------------------------------------#

# .htaccess files written by the test must not look freshly modified
age_file() { touch -d '3 days ago' "$1" 2>/dev/null || touch -t "$(date -v-3d +%Y%m%d%H%M 2>/dev/null)" "$1"; }
printf 'RewriteEngine On\n' > "$docroot/.htaccess"; age_file "$docroot/.htaccess"

# 5. hardening recipe: cgi-script handler with -ExecCGI -> OK
printf 'AddHandler cgi-script .php .phtml .php3 .pl .py .jsp .asp .htm .shtml .sh .cgi\nOptions -ExecCGI\n' > "$docroot/wp-content/uploads/.htaccess"; age_file "$docroot/wp-content/uploads/.htaccess"
imav_report_check_htaccess
expect_level 'htaccess hardening recipe' 'OK'

# 6. PHP handler for PHP extensions (panel leftover) -> INFO
printf 'AddHandler application/x-httpd-ea-php83 .php .php8 .phtml\n' > "$docroot/wp-content/.htaccess"; age_file "$docroot/wp-content/.htaccess"
imav_report_check_htaccess
expect_level 'htaccess php handler on php' 'INFO'

# 7. cgi-script without -ExecCGI -> WARNING
printf 'AddHandler cgi-script .php\n' > "$docroot/wp-content/uploads/.htaccess"; age_file "$docroot/wp-content/uploads/.htaccess"
imav_report_check_htaccess
expect_level 'htaccess cgi without ExecCGI' 'WARNING'

# 8. PHP handler for an image extension -> CRITICAL
printf 'AddType application/x-httpd-php .jpg\n' > "$docroot/wp-content/uploads/.htaccess"; age_file "$docroot/wp-content/uploads/.htaccess"
imav_report_check_htaccess
expect_level 'htaccess php on jpg' 'CRITICAL'

# 9. auto_prepend_file -> CRITICAL
printf 'php_value auto_prepend_file /tmp/x.php\n' > "$docroot/wp-content/uploads/.htaccess"; age_file "$docroot/wp-content/uploads/.htaccess"
imav_report_check_htaccess
expect_level 'htaccess auto_prepend_file' 'CRITICAL'
rm -f "$docroot/wp-content/uploads/.htaccess" "$docroot/wp-content/.htaccess"

#----------------------------------------------------------#
#        Backups, dumps and logs                           #
#----------------------------------------------------------#

# 10. content archives deeper in the tree are not reported
mkdir -p "$docroot/flipbooks/materials"
echo x > "$docroot/flipbooks/materials/BOOK 1.zip"
imav_report_check_backups
expect_level 'backups content archive' 'OK'

# 11. error logs -> INFO
echo x > "$docroot/wp-admin/error_log"
imav_report_check_backups
expect_level 'backups error_log' 'INFO'

# 12. archive in the root -> WARNING
echo x > "$docroot/public_html_bk.tar.gz"
imav_report_check_backups
expect_level 'backups root archive' 'WARNING'

# 13. database dump anywhere -> CRITICAL
echo x > "$docroot/flipbooks/db.sql"
imav_report_check_backups
expect_level 'backups sql dump' 'CRITICAL'
rm -f "$docroot/flipbooks/db.sql" "$docroot/public_html_bk.tar.gz" "$docroot/wp-admin/error_log"

#----------------------------------------------------------#
#        Hidden files and symbolic links                   #
#----------------------------------------------------------#

# 14. CloudLinux leftovers are ignored
mkdir -p "$docroot/.cagefs/opt/alt/php83/link"
ln -s /opt/alt/php83/etc "$docroot/.cagefs/opt/alt/php83/link/conf"
touch "$docroot/.cl.selector" "$docroot/wp-admin/.rnd" "$docroot/.maintenance1"
imav_report_check_hidden
expect_level 'hidden cloudlinux leftovers' 'OK'

# 15. a link inside the home directory -> INFO
mkdir -p "$home/private"
ln -s "$home/private" "$docroot/private-link"
imav_report_check_hidden
expect_level 'hidden link inside home' 'INFO'

# 16. a link outside the home directory -> WARNING
ln -s /etc "$docroot/etc-link"
imav_report_check_hidden
expect_level 'hidden link outside home' 'WARNING'
rm -f "$docroot/etc-link" "$docroot/private-link"

# 17. a .git directory -> WARNING
mkdir -p "$docroot/.git"
imav_report_check_hidden
expect_level 'hidden .git' 'WARNING'

imav_report_end
rm -rf "$VESTA" "$home"

echo "$pass passed, $failures failed"
[ "$failures" -eq 0 ]
