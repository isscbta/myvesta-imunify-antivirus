#!/bin/bash
# info: unit test of the version comparison and WordPress header parsing
# options: NONE
#
# Runs without ImunifyAV or myVesta: func/imav.sh is sourced with stubs for
# the main.sh functions it needs. Can be run on any machine with bash 4+.

REPO_DIR=$(cd "$(dirname "$0")/.." && pwd)
VESTA=$(mktemp -d)
export VESTA
mkdir -p "$VESTA/log"
check_result() { [ "$1" -ne 0 ] && { echo "check_result: $2"; exit "$1"; }; }
E_INVALID=2; E_NOTEXIST=3; E_DISABLED=11; E_UPDATE=19; E_DISK=13
parse_object_kv_list_non_eval() { :; }
BIN="$VESTA/bin"

source "$REPO_DIR/func/imav.sh"

pass=0
failures=0

expect_cmp() {
    local got
    got=$(imav_version_cmp "$1" "$2")
    if [ "$got" = "$3" ]; then
        ((pass++))
    else
        echo "FAIL: cmp $1 $2 expected $3 got $got"
        ((failures++))
    fi
}

expect_true() {
    if imav_version_compare "$1" "$2" "$3"; then ((pass++)); else echo "FAIL: $1 $2 $3 expected true"; ((failures++)); fi
}
expect_false() {
    if imav_version_compare "$1" "$2" "$3"; then echo "FAIL: $1 $2 $3 expected false"; ((failures++)); else ((pass++)); fi
}

# PHP version_compare semantics
expect_cmp '1.0' '1.0' 0
expect_cmp '1.0' '1.0.0' -1
expect_cmp '1.0.1' '1.0' 1
expect_cmp '1.10' '1.9' 1
expect_cmp '5.3.2' '5.3.10' -1
expect_cmp '1.0rc1' '1.0' -1
expect_cmp '1.0-beta' '1.0-alpha' 1
expect_cmp '1.0' '1.0rc1' 1
expect_cmp '1.0.0-dev' '1.0.0' -1
expect_cmp '2.0' '10.0' -1
expect_cmp '6.4.2' '6.4.2' 0
expect_cmp '1.2.3.4' '1.2.3' 1
expect_cmp '1.0pl1' '1.0' 1
expect_cmp '01.2' '1.2' 0

expect_true  '5.3.1' 'lt' '5.3.2'
expect_false '5.3.2' 'lt' '5.3.2'
expect_true  '5.3.2' 'le' '5.3.2'
expect_true  '5.3.2' 'eq' '5.3.2'
expect_true  '5.3.2' 'ne' '5.3.3'
expect_true  '5.3.3' 'gt' '5.3.2'
expect_true  '5.3.2' 'ge' '5.3.2'
expect_false '4.9' 'ge' '4.9.0'

# WordPress header parsing
tmp=$(mktemp -d)
mkdir -p "$tmp/wp-includes" "$tmp/wp-content/plugins/example" "$tmp/wp-content/themes/mytheme"
cat > "$tmp/wp-includes/version.php" <<'EOF'
<?php
$wp_version = '6.5.2';
$wp_db_version = 57155;
EOF
cat > "$tmp/wp-content/plugins/example/example.php" <<'EOF'
<?php
/**
 * Plugin Name: Example Plugin
 * Description: test
 * Version: 1.2.3
 */
EOF
cat > "$tmp/wp-content/plugins/example/helper.php" <<'EOF'
<?php
// helper without header
EOF
cat > "$tmp/wp-content/themes/mytheme/style.css" <<'EOF'
/*
Theme Name: My Theme
Version: 2.0
*/
EOF
touch "$tmp/wp-config.php"

[ "$(imav_wp_version "$tmp")" = '6.5.2' ] && ((pass++)) || { echo "FAIL: wp version"; ((failures++)); }
[ "$(imav_wp_plugin_version "$tmp" 'example')" = '1.2.3' ] && ((pass++)) || { echo "FAIL: plugin version"; ((failures++)); }
[ "$(imav_wp_theme_version "$tmp" 'mytheme')" = '2.0' ] && ((pass++)) || { echo "FAIL: theme version"; ((failures++)); }
[ "$(imav_wp_header "$tmp/wp-content/plugins/example/example.php" 'Plugin Name')" = 'Example Plugin' ] && ((pass++)) || { echo "FAIL: plugin name"; ((failures++)); }
imav_is_wordpress "$tmp" && ((pass++)) || { echo "FAIL: is_wordpress"; ((failures++)); }
# A damaged core (no version.php) is still recognised, a directory without wp-config.php is not
damaged=$(mktemp -d)
mkdir -p "$damaged/wp-content/plugins"
touch "$damaged/wp-config.php"
imav_is_wordpress "$damaged" && ((pass++)) || { echo "FAIL: is_wordpress damaged core"; ((failures++)); }
[ -z "$(imav_wp_version "$damaged")" ] && ((pass++)) || { echo "FAIL: wp version of damaged core"; ((failures++)); }
rm -f "$damaged/wp-config.php"
imav_is_wordpress "$damaged" && { echo "FAIL: is_wordpress without wp-config.php"; ((failures++)); } || ((pass++))
rm -rf "$damaged"

source "$REPO_DIR/func/imav-vuln.sh"
inventory=$(imav_vuln_inventory "$tmp")
[ "$(echo "$inventory" | grep -c .)" -eq 3 ] && ((pass++)) || { echo "FAIL: inventory count"; echo "$inventory"; ((failures++)); }
echo "$inventory" | grep -q $'^plugin\texample\t1.2.3\tExample Plugin$' && ((pass++)) || { echo "FAIL: inventory plugin line"; ((failures++)); }

source "$REPO_DIR/func/imav-remediate.sh"
expect_class() {
    local class slug rel
    IFS="$IMAV_FS" read -r class slug rel < <(imav_remediate_classify "$tmp" "$tmp/$1")
    if [ "$class" = "$2" ] && [ "$slug" = "$3" ] && [ "$rel" = "$1" ]; then
        ((pass++))
    else
        echo "FAIL: classify $1 expected $2/$3 got $class/$slug/$rel"
        ((failures++))
    fi
}
expect_class 'wp-includes/x.php' 'core' ''
expect_class 'wp-content/plugins/example/a/b.php' 'plugin' 'example'
expect_class 'wp-content/themes/mytheme/functions.php' 'theme' 'mytheme'
expect_class 'wp-content/uploads/2024/x.php' 'other' ''
expect_class 'wp-load.php' 'core' ''
expect_class 'wp-content/plugins/hello.php' 'plugin' 'hello-dolly'
expect_class 'wp-content/plugins/single-file.php' 'other' ''
expect_class 'evil.php' 'other' ''
expect_class 'wp-content/mu-plugins/x.php' 'other' ''

# WPVulnerability matching against a saved API response, when available
source "$REPO_DIR/func/imav-vuln.sh"
sample="$REPO_DIR/test/fixtures/wpv-contact-form-7.json"
if [ -f "$sample" ]; then
    n_old=$(imav_wpv_match "$sample" '5.3.1' | grep -c .)
    n_new=$(imav_wpv_match "$sample" '99.0' | grep -c .)
    [ "$n_old" -ge 1 ] && ((pass++)) || { echo "FAIL: wpv match 5.3.1 found $n_old"; ((failures++)); }
    [ "$n_new" -eq 0 ] && ((pass++)) || { echo "FAIL: wpv match 99.0 found $n_new"; ((failures++)); }
    imav_wpv_match "$sample" '5.3.1' | grep -q $'^Contact Form 7 \[contact-form-7\] < 5.3.2\x1f10.0\x1f5.3.2\x1fwpvulnerability' \
        && ((pass++)) || { echo "FAIL: wpv match fields"; ((failures++)); }
fi

# Domain and user from path
[ "$(imav_domain_from_path '/home/bob/web/example.com/public_html/x.php')" = 'example.com' ] && ((pass++)) || { echo "FAIL: domain from path"; ((failures++)); }
[ "$(imav_user_from_path '/home/bob/web/example.com/public_html/x.php')" = 'bob' ] && ((pass++)) || { echo "FAIL: user from path"; ((failures++)); }

rm -rf "$tmp" "$VESTA"
echo "$pass passed, $failures failed"
[ $failures -eq 0 ]
