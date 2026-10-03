#!/bin/bash
# myVesta ImunifyAV integration: location checks for the security report.
#
# What a file contains is judged by the ImunifyAV signatures. These checks
# only look at where PHP files are, which no signature can:
#   unknown-dir     PHP files in a wp-content directory that WordPress,
#                   plugins or themes do not create
#   random-suffix   plugin or theme directory whose name ends in a random
#                   hexadecimal string
# The result is TSV: KIND<FS>PATH<FS>DETAIL (separator $IMAV_FS).
#
# Requires func/imav.sh.

# wp-content directories that legitimately contain PHP files
IMAV_HEURISTIC_KNOWN_DIRS='plugins themes uploads mu-plugins upgrade languages cache upgrade-temp-backup w3tc-config wp-rocket-config et-cache litespeed wflogs imunify-security aiowps_backups ai1wm-backups updraft backups-dup-lite backup-guard wpvividbackups advanced-cache.php object-cache.php db.php index.php'

# Run the checks on a document root. Prints TSV records.
# $1 = docroot
imav_heuristic_scan() {
    local docroot="$1" hit dir name known php_files

    [ -d "$docroot/wp-content" ] || return 0

    # 1. PHP files in wp-content directories that nothing legitimate creates
    for dir in "$docroot"/wp-content/*/; do
        [ -d "$dir" ] || continue
        name=$(basename "$dir")
        known=0
        for k in $IMAV_HEURISTIC_KNOWN_DIRS; do [ "$name" = "$k" ] && known=1; done
        [ $known -eq 1 ] && continue
        # index.php guard files ("Silence is golden", "exit;") do not count as PHP content
        php_files=$(find "$dir" -maxdepth 3 -type f -name '*.php' 2>/dev/null | while IFS= read -r f; do
            imav_is_guard_index "$f" && continue
            echo "$f"
        done)
        hit=$(echo "$php_files" | head -n 1)
        if [ -n "$hit" ]; then
            printf 'unknown-dir\x1f%s\x1f%s PHP file(s), e.g. %s\n' "${dir%/}" "$(echo "$php_files" | grep -c .)" "${hit#$dir}"
        fi
    done

    # 2. plugin and theme directories with a random hexadecimal suffix
    for dir in "$docroot"/wp-content/plugins/*/ "$docroot"/wp-content/themes/*/; do
        [ -d "$dir" ] || continue
        name=$(basename "$dir")
        if [[ "$name" =~ -[0-9a-f]{6,}$ ]]; then
            local main pname
            main=$(imav_wp_plugin_main_file "$dir" 2>/dev/null)
            [ -z "$main" ] && [ -f "$dir/style.css" ] && main="$dir/style.css"
            pname=''
            [ -n "$main" ] && pname=$(imav_wp_header "$main" 'Plugin Name' 2>/dev/null | sed 's/\*\/.*//; s/[[:space:]]*$//')
            [ -z "$pname" ] && [ -n "$main" ] && pname=$(imav_wp_header "$main" 'Theme Name' 2>/dev/null)
            printf 'random-suffix\x1f%s\x1f%s\n' "${dir%/}" "${pname:-no Plugin Name header}"
        fi
    done
}

# Human readable table of heuristic findings (TSV on stdin)
imav_heuristic_print_shell() {
    {
        echo "KIND|FILE|DETAIL"
        echo "----|----|------"
        tr "$IMAV_FS" '|'
    } | column -t -s '|'
}

# CSV of heuristic findings (TSV on stdin)
imav_heuristic_print_csv() {
    echo 'kind,path,detail'
    while IFS="$IMAV_FS" read -r k p d; do
        [ -z "$k" ] && continue
        printf '"%s","%s","%s"\n' "$k" "${p//\"/\"\"}" "${d//\"/\"\"}"
    done
}
