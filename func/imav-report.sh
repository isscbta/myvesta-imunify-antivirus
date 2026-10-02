#!/bin/bash
# myVesta ImunifyAV integration: security report of one domain.
#
# Every check is a function that opens a section, sets the section level
# (OK, INFO, WARNING, CRITICAL) and writes lines or table rows into it. The
# renderers turn the collected sections into a plain-text and an HTML report
# with a summary on top. Used by v-imav-report-domain.
#
# Requires func/imav.sh, func/imav-vuln.sh, func/imav-db.sh, func/imav-monitor.sh,
# func/imav-heuristic.sh.

: "${REPORT_FILE_GROWTH_WARN:=500}"
: "${REPORT_MAIL_WARN:=500}"
: "${REPORT_SSL_WARN_DAYS:=14}"
: "${REPORT_NEW_ADMIN_DAYS:=30}"

WPORG_API='https://api.wordpress.org'
WPORG_CACHE_TTL=86400

IMAV_REPORT_NOTE='Malware scanning is performed by ImunifyAV (CloudLinux signature database with Hyperscan and cloud-assisted detection). Vulnerability detection uses the WPVulnerability database and, when configured, the Wordfence Intelligence feed. These methods are reliable and used on millions of hosting accounts, but no scanner can guarantee 100% detection; the report should be read together with the other checks below.'


#----------------------------------------------------------#
#                    Section collection                    #
#----------------------------------------------------------#

# Start collecting sections into a temporary directory
imav_report_begin() {
    REPORT_TMP=$(mktemp -d)
    REPORT_SECTION_LIST="$REPORT_TMP/sections.list"
    : > "$REPORT_SECTION_LIST"
    REPORT_CURRENT=''
    REPORT_SEQ=0
}

imav_report_end() {
    rm -rf "$REPORT_TMP"
}

# Numeric value of a level
imav_report_level_num() {
    case $1 in
        CRITICAL) echo 3 ;;
        WARNING)  echo 2 ;;
        INFO)     echo 1 ;;
        *)        echo 0 ;;
    esac
}

# Open a section
# $1 = id, $2 = title
report_section() {
    REPORT_SEQ=$((REPORT_SEQ + 1))
    REPORT_CURRENT=$(printf '%02d-%s' "$REPORT_SEQ" "$1")
    echo "$REPORT_CURRENT" >> "$REPORT_SECTION_LIST"
    echo "$2" > "$REPORT_TMP/$REPORT_CURRENT.title"
    echo 'OK' > "$REPORT_TMP/$REPORT_CURRENT.level"
    : > "$REPORT_TMP/$REPORT_CURRENT.body"
    : > "$REPORT_TMP/$REPORT_CURRENT.summary"
}

# Raise the level of the current section (never lowers it)
# $1 = level
report_level() {
    local current
    current=$(cat "$REPORT_TMP/$REPORT_CURRENT.level")
    if [ "$(imav_report_level_num "$1")" -gt "$(imav_report_level_num "$current")" ]; then
        echo "$1" > "$REPORT_TMP/$REPORT_CURRENT.level"
    fi
}

# One-line summary of the current section, shown in the summary table
# $1 = text
report_summary() {
    echo "$1" > "$REPORT_TMP/$REPORT_CURRENT.summary"
}

# Add a text line to the current section
# $1 = text (may be empty)
report_line() {
    printf 'L\t%s\n' "$1" >> "$REPORT_TMP/$REPORT_CURRENT.body"
}

# Add a preformatted block (multi-line text) to the current section, from stdin
report_block() {
    sed 's/^/P\t/' >> "$REPORT_TMP/$REPORT_CURRENT.body"
}

# Add a table header / row to the current section (columns as arguments)
report_table_header() {
    printf 'H'; printf '\t%s' "$@"; printf '\n'
} >> "$REPORT_TMP/$REPORT_CURRENT.body"

# Empty cells are stored as "-": a trailing empty column would otherwise be
# lost when the line is read back with a tab IFS.
report_table_row() {
    local cell
    printf 'R'
    for cell in "$@"; do
        printf '\t%s' "${cell:--}"
    done
    printf '\n'
} >> "$REPORT_TMP/$REPORT_CURRENT.body"

# Highest level over all sections
imav_report_overall_level() {
    local id level max='OK'
    while read -r id; do
        level=$(cat "$REPORT_TMP/$id.level")
        if [ "$(imav_report_level_num "$level")" -gt "$(imav_report_level_num "$max")" ]; then
            max=$level
        fi
    done < "$REPORT_SECTION_LIST"
    echo "$max"
}


#----------------------------------------------------------#
#                    Helpers                               #
#----------------------------------------------------------#

# Registrable part of a host name (last two labels), lowercase, without www.
# $1 = host
imav_report_base_host() {
    local h
    h=$(echo "$1" | tr 'A-Z' 'a-z' | sed -e 's/^www\.//' -e 's/:.*//')
    echo "$h" | awk -F. '{ if (NF >= 2) print $(NF-1)"."$NF; else print $0 }'
}

# Run a wp-cli command for the domain through myVesta; empty output on failure
# $@ = wp-cli arguments
imav_report_wp() {
    [ -x "$BIN/v-run-wp-cli" ] || return 1
    timeout 120 "$BIN/v-run-wp-cli" "$domain" "$@" --skip-plugins --skip-themes 2>/dev/null
}

# Cached JSON from the wordpress.org API; prints the file path
# $1 = url, $2 = cache name
imav_report_wporg() {
    local file="$CACHE_DIR/wporg/$2.json"
    if imav_cached_download "$1" "$file" "$WPORG_CACHE_TTL" -H 'Accept: application/json'; then
        echo "$file"
        return 0
    fi
    return 1
}


#----------------------------------------------------------#
#                    Checks                                #
#----------------------------------------------------------#

imav_report_check_malware() {
    report_section 'malware' 'Malware scan (ImunifyAV)'
    local results count total
    imav_start_scan "$docroot" --intensity-cpu "$SCAN_INTENSITY_CPU" --intensity-io "$SCAN_INTENSITY_IO"
    imav_wait_scan "$scan_id"
    results=$(imav_scan_results "$scan_id")
    imav_results_check "$results"
    results=$(imav_results_filter_path "$results" "$docroot")
    count=$(imav_results_count "$results")
    total=$(imav_ondemand_list_json | jq -r --arg id "$scan_id" '.[] | select(.scanid == $id) | .total_resources // ""' | head -n 1)
    imav_write_report "$user" "$domain" 'imav-scan' "$(imav_results_to_csv "$results")" >/dev/null

    if [ "$count" -gt 0 ]; then
        report_level CRITICAL
        report_summary "$count infected file(s) found"
        report_line "ImunifyAV found $count infected file(s) under $docroot (scan $scan_id${total:+, $total files scanned})."
        report_line ''
        if [ "$count" -gt 50 ]; then
            # A mass infection: the breakdown says more than a list of hundreds of rows
            report_line 'Infected files by directory and file type:'
            report_table_header 'Directory' 'Files' 'File types'
            echo "$results" | jq -r --arg d "$docroot/" '.[] | (.file // "") | ltrimstr($d)' \
                | awk -F/ '{ dir = (NF > 2) ? $1 "/" $2 : (NF > 1 ? $1 : "(root)"); n = split($NF, p, "."); ext = (n > 1) ? p[n] : "(none)"; c[dir]++; e[dir SUBSEP ext]++ }
                       END { for (d in c) { s = ""; for (k in e) { split(k, a, SUBSEP); if (a[1] == d) s = s (s == "" ? "" : ", ") a[2] " (" e[k] ")" } printf "%s\t%d\t%s\n", d, c[d], s } }' \
                | sort -t $'\t' -k2,2nr | while IFS=$'\t' read -r d n s; do report_table_row "$d" "$n" "$s"; done
            report_line ''
            report_line "The first 50 files are listed below; all $count are in private/imav-scan.csv."
            report_line ''
        fi
        report_table_header 'File' 'Signature' 'Size'
        echo "$results" | jq -r '.[] | [(.file // ""), (.type // ""), ((.size // "") | tostring)] | join("\u001f")' | head -n 50 \
            | while IFS="$IMAV_FS" read -r f t s; do report_table_row "${f#$docroot/}" "$t" "$s"; done
        report_line ''
        report_line "Run: v-imav-remediate $domain dry-run   (then without dry-run to restore originals or quarantine)"
    else
        report_summary "clean${total:+, $total files scanned}"
        report_line "No infected files were found under $docroot (scan $scan_id${total:+, $total files scanned})."
    fi

}

imav_report_check_heuristics() {
    report_section 'locations' 'Unexpected locations in wp-content'
    local findings kind path detail
    if [ $is_wp -eq 0 ]; then
        report_summary 'not a WordPress site'
        report_line 'Not a WordPress installation.'
        return
    fi
    findings=$(imav_heuristic_scan "$docroot")
    if [ -z "$findings" ]; then
        report_summary 'none'
        report_line 'No PHP files in wp-content directories that nothing legitimate creates, no plugin or theme directory with a random suffix.'
        return
    fi
    report_level WARNING
    report_summary "$(echo "$findings" | grep -c .) unexpected location(s)"
    report_line 'PHP files in a wp-content directory that neither WordPress nor plugins or themes create, and plugin or theme directories whose name ends in a random string, are how planted files are usually placed. Review each entry; the content itself is judged by the ImunifyAV scan above.'
    report_line ''
    report_table_header 'Kind' 'Path' 'Detail'
    echo "$findings" | while IFS="$IMAV_FS" read -r kind path detail; do
        report_table_row "$kind" "${path#$docroot/}" "$detail"
    done
}

imav_report_check_vuln() {
    report_section 'vuln' 'Known vulnerabilities (core, plugins, themes)'
    if [ $is_wp -eq 0 ]; then
        report_summary 'not a WordPress site'
        report_line 'Not a WordPress installation, no vulnerability check.'
        return
    fi
    local findings vulnerable notes count max_cvss unfixed sources
    IMAV_VULN_STALE=0
    # imav_vuln_scan runs in a subshell below, so the feed state is determined here
    imav_wf_index >/dev/null 2>&1
    findings=$(imav_vuln_scan "$docroot")
    vulnerable=$(echo "$findings" | awk -F'\t' '$4 != "" && $4 !~ /^-/')
    notes=$(echo "$findings" | awk -F'\t' '$4 ~ /^-/')
    count=$(echo "$vulnerable" | grep -c .)
    imav_write_report "$user" "$domain" 'imav-vuln' "$(echo "$vulnerable" | grep -v '^$' | imav_vuln_print csv)" >/dev/null

    case $IMAV_WF_STATE in
        ok|stale) sources='WPVulnerability and Wordfence Intelligence' ;;
        *)        sources='WPVulnerability' ;;
    esac

    if [ "$count" -gt 0 ]; then
        max_cvss=$(echo "$vulnerable" | awk -F'\t' '$5 != "" { if ($5+0 > m) m = $5+0 } END { print m+0 }')
        unfixed=$(echo "$vulnerable" | awk -F'\t' '$6 == "no fix"' | grep -c .)
        if [ "$unfixed" -gt 0 ] || awk -v m="$max_cvss" 'BEGIN { exit !(m + 0 >= 9) }'; then
            report_level CRITICAL
        elif awk -v m="$max_cvss" 'BEGIN { exit !(m + 0 >= 7) }'; then
            report_level WARNING
        else
            report_level INFO
        fi
        report_summary "$count vulnerability(ies)$(awk -v m="$max_cvss" 'BEGIN { if (m + 0 > 0) printf ", highest CVSS %s", m; else printf ", CVSS not published" }')$([ "$unfixed" -gt 0 ] && echo ", $unfixed without a fix")"
        report_line "$count known vulnerability(ies) match the installed versions (sources: $sources)."
        report_line 'Update the affected components to the fixed version as soon as possible.'
        report_line ''
        report_table_header 'Type' 'Component' 'Installed' 'Vulnerability' 'CVSS' 'Fixed in' 'Source'
        # Highest CVSS first, at most 40 rows in the mail; the CSV has all of them
        # empty CVSS cells would collapse with a tab IFS: convert to the unit separator first
        echo "$vulnerable" | sort -t $'\t' -k5,5gr | head -n 40 | awk -F'\t' -v OFS=$'\x1f' '{ $1 = $1; print }' \
            | while IFS="$IMAV_FS" read -r t s v title cvss fixed src link; do
            report_table_row "$t" "$s" "$v" "$title" "$cvss" "$fixed" "$src"
        done
        if [ "$count" -gt 40 ]; then
            report_line "Showing the 40 with the highest CVSS; all $count are in private/imav-vuln.csv."
        fi
    else
        report_summary "none known (sources: $sources)"
        report_line "No known vulnerabilities match the installed core, plugin and theme versions (sources: $sources)."
    fi
    if [ -n "$notes" ]; then
        report_line ''
        report_line 'Not checked (no wordpress.org entry, custom or premium component):'
        echo "$notes" | awk -F'\t' '{ printf "  %s %s %s\n", $1, $2, $3 }' | report_block
    fi
    if [ "$IMAV_VULN_STALE" = '1' ]; then
        report_line 'Note: the vulnerability API was not reachable, cached data was used.'
    fi
}

imav_report_check_db() {
    report_section 'database' 'Database scan'
    if [ $is_wp -eq 0 ]; then
        report_summary 'not a WordPress site'
        report_line 'Not a WordPress installation, no database check.'
        return
    fi
    if ! imav_db_credentials "$domain" || ! imav_db_query 'SELECT 1' >/dev/null 2>&1; then
        report_level INFO
        report_summary 'could not connect'
        report_line 'The database could not be opened with the credentials from wp-config.php; the database scan was skipped.'
        return
    fi
    local export_dir="$IMAV_DATA/dbscan/$domain" exported findings heuristics count icount oversized
    exported=$(imav_db_export "$export_dir")
    oversized=$(imav_db_oversized "$export_dir")
    findings=''
    if [ "$exported" -gt 0 ]; then
        local db_results
        imav_start_scan "$export_dir" --intensity-cpu "$SCAN_INTENSITY_CPU" --intensity-io "$SCAN_INTENSITY_IO"
        imav_wait_scan "$scan_id"
        db_results=$(imav_scan_results "$scan_id")
        imav_results_check "$db_results"
        findings=$(imav_db_map_findings "$export_dir" "$db_results")
        imav_db_forget_findings "$export_dir" "$db_results"
    fi
    heuristics=$(imav_db_heuristics "$domain" "$docroot" "$export_dir")
    rm -rf "$export_dir" "$export_dir.oversized"
    findings=$(printf '%s\n%s\n' "$findings" "$heuristics" | grep -v '^$')
    count=$(echo "$findings" | grep -c .)
    icount=$(echo "$findings" | awk -F'\t' '$5 == "imunify"' | grep -c .)
    imav_write_report "$user" "$domain" 'imav-db-scan' "$(echo "$findings" | imav_db_print csv)" >/dev/null

    if [ "$count" -gt 0 ]; then
        if [ "$icount" -gt 0 ]; then report_level CRITICAL; else report_level WARNING; fi
        report_summary "$count finding(s)"
        report_line "Database $IMAV_DB_NAME: $exported row(s) with text content (posts, meta, options, comments) were scanned by ImunifyAV, and the heuristic checks found the following."
        report_line ''
        report_table_header 'Table' 'Row' 'Column' 'Finding' 'Source'
        echo "$findings" | while IFS=$'\t' read -r t r c f s; do report_table_row "$t" "$r" "$c" "$f" "$s"; done
        report_line ''
        report_line 'Rows are identified by table and primary key; review them before changing the database.'
    else
        report_summary "clean, $exported row(s) checked"
        report_line "Database $IMAV_DB_NAME was scanned: $exported row(s) with text content (posts, meta, options, comments) checked by ImunifyAV; site URL, active plugins, administrators and cron entries verified. Clean."
    fi
    if [ -n "$oversized" ]; then
        report_level INFO
        report_line ''
        report_line "$(echo "$oversized" | grep -c .) row(s) are larger than 1 MB and cannot be checked by signatures (table-column-id):"
        echo "$oversized" | head -n 20 | sed 's/^/  /' | report_block
    fi
}

imav_report_check_core_integrity() {
    report_section 'core' 'WordPress core integrity'
    if [ $is_wp -eq 0 ]; then
        report_summary 'not a WordPress site'
        report_line 'Not a WordPress installation.'
        return
    fi
    local version file expected computed modified missing extra
    version=$(imav_wp_version "$docroot")
    if [ -z "$version" ]; then
        report_level CRITICAL
        report_summary 'core version unknown, wp-includes/version.php is missing'
        report_line 'wp-includes/version.php does not exist, so the WordPress version is unknown and the core cannot be verified. WordPress cannot load without this file (the site answers with an error), which usually means an attacker or an incomplete cleanup deleted core files.'
        report_line ''
        report_line 'Present core directories and their file count:'
        local d
        for d in wp-admin wp-includes; do
            if [ -d "$docroot/$d" ]; then
                report_line "  $d: $(find "$docroot/$d" -type f 2>/dev/null | wc -l) file(s)"
            else
                report_line "  $d: missing"
            fi
        done
        report_line ''
        report_line 'Restore wp-admin, wp-includes and the root files from the official archive of the version the site was running (wordpress.org/download/releases/), then run the report again.'
        local hint
        hint=$(grep -m1 -o 'Version [0-9][0-9.]*' "$docroot/readme.html" 2>/dev/null)
        if [ -n "$hint" ]; then
            report_line "readme.html in the root says: $hint (the release the site was last updated to, unless the file is stale)."
        fi
        return
    fi
    if ! file=$(imav_report_wporg "$WPORG_API/core/checksums/1.0/?version=$version&locale=en_US" "core-checksums-$version"); then
        report_level INFO
        report_summary "checksums for $version not available"
        report_line "The official checksums for WordPress $version could not be downloaded; core integrity was not verified."
        return
    fi
    expected=$(mktemp); computed=$(mktemp)
    # Only core directories and root files: wp-content is site-specific.
    # sort and join must agree on the collation, hence LC_ALL=C everywhere.
    jq -r '(.checksums // {}) | to_entries[] | select(.key | test("^(wp-admin/|wp-includes/|[^/]+$)")) | "\(.key)\t\(.value)"' "$file" \
        | LC_ALL=C sort > "$expected"
    (cd "$docroot" && cut -f1 "$expected" | xargs -d '\n' -r md5sum 2>/dev/null | awk '{ h=$1; $1=""; sub(/^ +/, ""); print $0 "\t" h }' | LC_ALL=C sort) > "$computed"
    missing=$(LC_ALL=C join -t $'\t' -v 1 "$expected" "$computed" | cut -f1 | grep -v 'wp-config-sample.php\|readme.html\|license.txt')
    modified=$(LC_ALL=C join -t $'\t' "$expected" "$computed" | awk -F'\t' '$2 != $3 { print $1 }')
    extra=$(cd "$docroot" && find wp-admin wp-includes -type f -name '*.php' 2>/dev/null | LC_ALL=C sort | LC_ALL=C join -t $'\t' -v 1 - "$expected")
    rm -f "$expected" "$computed"

    if [ -n "$modified" ] || [ -n "$extra" ]; then
        report_level CRITICAL
        report_summary "$(echo "$modified" | grep -c .) modified, $(echo "$extra" | grep -c .) unknown file(s)"
        report_line "WordPress $version core files differ from the official release. Modified or unknown files in wp-admin, wp-includes or the root are a strong sign of a compromise (or of manual edits that should not be there)."
        if [ -n "$modified" ]; then
            report_line ''
            report_line 'Modified core files (checksum mismatch):'
            echo "$modified" | head -n 50 | sed 's/^/  /' | report_block
        fi
        if [ -n "$extra" ]; then
            report_line ''
            report_line 'PHP files not part of the release:'
            echo "$extra" | head -n 50 | sed 's/^/  /' | report_block
        fi
        report_line ''
        report_line "Run: v-imav-remediate $domain dry-run   (restores core files from the official archive)"
    else
        report_summary "WordPress $version verified"
        report_line "All WordPress $version core files match the official checksums."
    fi
    if [ -n "$missing" ]; then
        report_level WARNING
        report_line ''
        report_line 'Core files missing from the installation:'
        echo "$missing" | head -n 30 | sed 's/^/  /' | report_block
    fi
}

imav_report_check_plugin_integrity() {
    report_section 'plugins-integrity' 'Plugin integrity (wordpress.org checksums)'
    if [ $is_wp -eq 0 ]; then
        report_summary 'not a WordPress site'
        report_line 'Not a WordPress installation.'
        return
    fi
    local output count
    if ! imav_report_wp core version >/dev/null 2>&1; then
        report_level INFO
        report_summary 'wp-cli did not run'
        report_line "wp-cli did not run for this site (check: v-run-wp-cli $domain core version); plugin checksums were not verified."
        return
    fi
    output=$(imav_report_wp plugin verify-checksums --all --format=csv 2>/dev/null | tail -n +2 | grep -v '^$')
    count=$(echo "$output" | grep -c .)
    if [ "$count" -gt 0 ]; then
        report_level WARNING
        report_summary "$count file(s) differ from wordpress.org"
        report_line 'Files of wordpress.org plugins that do not match the published release. Premium plugins are not covered by this check.'
        report_line ''
        report_table_header 'Plugin' 'File' 'Problem'
        echo "$output" | while IFS=',' read -r p f m; do report_table_row "$p" "$f" "$m"; done
    else
        report_summary 'verified'
        report_line 'All files of wordpress.org plugins match the published checksums (premium plugins cannot be verified this way).'
    fi
}

imav_report_check_updates() {
    report_section 'updates' 'Available updates'
    if [ $is_wp -eq 0 ]; then
        report_summary 'not a WordPress site'
        report_line 'Not a WordPress installation.'
        return
    fi
    local type slug version name latest file core_latest rows='' count=0 core_old=0
    if file=$(imav_report_wporg "$WPORG_API/core/version-check/1.7/" 'core-version-check'); then
        core_latest=$(jq -r '.offers[0].current // ""' "$file")
    fi
    while IFS=$'\t' read -r type slug version name; do
        [ -z "$type" ] && continue
        latest=''
        case $type in
            core)   latest=$core_latest ;;
            plugin) file=$(imav_report_wporg "$WPORG_API/plugins/info/1.0/$slug.json" "plugin-$slug") && latest=$(jq -r '.version // ""' "$file" 2>/dev/null) ;;
            theme)  file=$(imav_report_wporg "$WPORG_API/themes/info/1.1/?action=theme_information&request%5Bslug%5D=$slug" "theme-$slug") && latest=$(jq -r '.version // ""' "$file" 2>/dev/null) ;;
        esac
        [ -z "$latest" ] || [ "$latest" = 'null' ] && continue
        if imav_version_compare "$version" 'lt' "$latest"; then
            rows="$rows$type"$'\x1f'"$slug"$'\x1f'"$version"$'\x1f'"$latest"$'\n'
            count=$((count + 1))
            [ "$type" = 'core' ] && core_old=1
        fi
    done < <(imav_vuln_inventory "$docroot")

    if [ "$count" -gt 0 ]; then
        if [ $core_old -eq 1 ]; then report_level WARNING; else report_level INFO; fi
        report_summary "$count update(s) available$([ $core_old -eq 1 ] && echo ', including WordPress core')"
        report_line "$count component(s) have a newer version on wordpress.org. Outdated software is the most common entry point even without a published vulnerability."
        report_line ''
        report_table_header 'Type' 'Component' 'Installed' 'Latest'
        printf '%s' "$rows" | while IFS="$IMAV_FS" read -r t s v l; do [ -n "$t" ] && report_table_row "$t" "$s" "$v" "$l"; done
    else
        report_summary 'everything up to date'
        report_line 'WordPress core and all wordpress.org plugins and themes are at their latest version.'
    fi
}

imav_report_check_php_files() {
    report_section 'php-files' 'PHP files in unexpected places'
    local uploads_php disguised double
    # index.php guard files that plugins put into their upload folders do not count
    uploads_php=$(find "$docroot/wp-content/uploads" -type f \( -iname '*.php' -o -iname '*.php[0-9]' -o -iname '*.phtml' -o -iname '*.phar' -o -iname '*.php.*' \) 2>/dev/null \
        | while IFS= read -r f; do
            imav_is_guard_index "$f" && continue
            echo "$f"
        done | head -n 50)
    disguised=$(find "$docroot" -type f \( -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.png' -o -iname '*.gif' -o -iname '*.ico' -o -iname '*.svg' -o -iname '*.webp' -o -iname '*.txt' \) -size -4M -mtime -30 -print0 2>/dev/null \
        | xargs -0 -r -n 100 sh -c 'for f; do head -c 256 "$f" 2>/dev/null | grep -q "<?php" && echo "$f"; done' _ | head -n 50)
    # a second extension that a web server may serve or an image handler may accept; vendor .default/.dist/.sample files are not that
    double=$(find "$docroot" -type f \( -iname '*.php.jpg' -o -iname '*.php.jpeg' -o -iname '*.php.png' -o -iname '*.php.gif' -o -iname '*.php.ico' -o -iname '*.php.svg' -o -iname '*.php.webp' -o -iname '*.php.txt' -o -iname '*.php.html' -o -iname '*.php.htm' -o -iname '*.php.suspected' \) ! -path "$docroot/wp-content/uploads/*" 2>/dev/null | head -n 50)

    if [ -n "$uploads_php" ] || [ -n "$disguised" ]; then
        report_level CRITICAL
    elif [ -n "$double" ]; then
        report_level WARNING
    fi
    if [ -z "$uploads_php$disguised$double" ]; then
        report_summary 'none'
        report_line 'No PHP files in wp-content/uploads, no image or text files containing PHP code, no double extensions.'
        return
    fi
    report_summary "$(printf '%s\n%s\n%s\n' "$uploads_php" "$disguised" "$double" | grep -c .) file(s)"
    if [ -n "$uploads_php" ]; then
        report_line 'PHP files inside wp-content/uploads (uploads must never contain executable code):'
        echo "$uploads_php" | sed "s|^$docroot/|  |" | report_block
        report_line ''
    fi
    if [ -n "$disguised" ]; then
        report_line 'Files with an image or text extension that contain PHP code (modified in the last 30 days):'
        echo "$disguised" | sed "s|^$docroot/|  |" | report_block
        report_line ''
    fi
    if [ -n "$double" ]; then
        report_line 'Files with a double extension after .php:'
        echo "$double" | sed "s|^$docroot/|  |" | report_block
    fi
}

imav_report_check_backups() {
    report_section 'backups' 'Backups, dumps and logs reachable over the web'
    local found dumps
    # Database dumps anywhere in the document root, other leftovers in the top three levels
    dumps=$(find "$docroot" -type f \( -iname '*.sql' -o -iname '*.sql.gz' -o -iname '*.sql.zip' -o -iname '*.sql.bz2' -o -iname '*.mysql' -o -iname '*.dump' \) 2>/dev/null | head -n 40)
    found=$(find "$docroot" -maxdepth 3 -type f \( -iname '*.zip' -o -iname '*.tar' -o -iname '*.tar.gz' -o -iname '*.tgz' -o -iname '*.bak' -o -iname '*.old' -o -iname 'wp-config*.php.*' -o -iname 'wp-config.php~' -o -iname 'debug.log' -o -iname 'error_log' -o -iname 'php_errorlog' \) \
        ! -path "$docroot/wp-content/uploads/*/*" 2>/dev/null | head -n 40)
    found=$(printf '%s\n%s\n' "$dumps" "$found" | grep -v '^$' | awk '!seen[$0]++')
    if [ -n "$found" ]; then
        report_level WARNING
        [ -n "$dumps" ] && report_level CRITICAL
        report_summary "$(echo "$found" | grep -c .) file(s)$([ -n "$dumps" ] && echo ", including $(echo "$dumps" | grep -c .) database dump(s)")"
        report_line 'Archives, database dumps, configuration copies or log files inside the document root can be downloaded by anyone who guesses the name. A database dump exposes every user, password hash and setting of the site. Move them outside public_html or delete them.'
        report_line ''
        report_table_header 'File' 'Size' 'Modified'
        echo "$found" | while IFS= read -r f; do
            report_table_row "${f#$docroot/}" "$(du -h "$f" 2>/dev/null | cut -f1)" "$(date -r "$f" +'%F %T' 2>/dev/null)"
        done
    else
        report_summary 'none'
        report_line 'No database dumps anywhere in the document root, and no archives, configuration copies or log files in its top three levels.'
    fi
}

imav_report_check_htaccess() {
    report_section 'htaccess' '.htaccess files'
    local main="$docroot/.htaccess" files recent dangerous rewrite count f age line host
    if [ -f "$main" ]; then
        age=$(( ($(date +%s) - $(stat -c %Y "$main")) / 3600 ))
        if [ "$age" -le 24 ]; then
            report_level INFO
            report_line "Main .htaccess was modified in the last 24 hours ($(date -r "$main" +'%F %T')). Current content:"
            head -n 80 "$main" | report_block
        else
            report_line "Main .htaccess last modified $(date -r "$main" +'%F %T')."
        fi
    else
        report_line 'No main .htaccess file.'
    fi

    files=$(find "$docroot" -type f -name '.htaccess' 2>/dev/null | head -n 500)
    count=$(echo "$files" | grep -c .)
    recent=''; dangerous=''; rewrite=''
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        age=$(( ($(date +%s) - $(stat -c %Y "$f")) / 3600 ))
        [ "$age" -le 24 ] && [ "$f" != "$main" ] && recent="$recent${f#$docroot/} ($(date -r "$f" +'%F %T'))"$'\n'
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            case $line in
                *auto_prepend_file*|*auto_append_file*|*AddHandler*php*|*AddType*php*|*SetHandler*php*)
                    dangerous="$dangerous${f#$docroot/}: $line"$'\n' ;;
                *RewriteRule*http://*|*RewriteRule*https://*|*Redirect*http://*|*Redirect*https://*)
                    host=$(echo "$line" | grep -oE 'https?://[^/ "]+' | head -n 1 | sed 's|https\?://||')
                    if [ -n "$host" ] && [ "$(imav_report_base_host "$host")" != "$(imav_report_base_host "$domain")" ]; then
                        rewrite="$rewrite${f#$docroot/}: $line"$'\n'
                    fi ;;
            esac
        done < <(grep -iE 'auto_prepend_file|auto_append_file|AddHandler|AddType|SetHandler|RewriteRule|Redirect' "$f" 2>/dev/null | grep -v '^\s*#')
    done <<< "$files"

    if [ -n "$dangerous" ]; then
        report_level CRITICAL
        report_line ''
        report_line 'Directives that make other files executable or prepend code to every request (typical of backdoors):'
        printf '%s' "$dangerous" | sed 's/^/  /' | report_block
    fi
    if [ -n "$rewrite" ]; then
        report_level WARNING
        report_line ''
        report_line 'Redirects or rewrites to external hosts:'
        printf '%s' "$rewrite" | sed 's/^/  /' | report_block
    fi
    if [ -n "$recent" ]; then
        report_level INFO
        report_line ''
        report_line 'Other .htaccess files modified in the last 24 hours:'
        printf '%s' "$recent" | sed 's/^/  /' | report_block
    fi
    if [ -n "$dangerous" ]; then
        report_summary 'dangerous directives found'
    elif [ -n "$rewrite" ]; then
        report_summary 'external redirects found'
    else
        report_summary "$count file(s), no dangerous directives"
    fi
    report_line ''
    report_line "$count .htaccess file(s) in total under the document root."
}

imav_report_check_external() {
    report_section 'external' 'Site seen from outside'
    local body meta code final_url final_host expected scripts ext_hosts enddate days redirect_note=''
    body=$(mktemp)
    meta=$(curl -s -o "$body" -w '%{http_code}\t%{url_effective}' -L --max-redirs 5 -m 30 \
        -A 'Mozilla/5.0 (compatible; myVesta security report)' "https://$domain/" 2>/dev/null)
    code=${meta%%$'\t'*}
    if [ -z "$code" ] || [ "$code" = '000' ]; then
        meta=$(curl -s -o "$body" -w '%{http_code}\t%{url_effective}' -L --max-redirs 5 -m 30 \
            -A 'Mozilla/5.0 (compatible; myVesta security report)' "http://$domain/" 2>/dev/null)
        code=${meta%%$'\t'*}
    fi
    final_url=${meta#*$'\t'}
    final_host=$(echo "$final_url" | sed -e 's|^[a-z]*://||' -e 's|[/:].*||')
    expected=$(imav_report_base_host "$domain")

    local suspended
    suspended=$(grep "DOMAIN='$domain'" "$VESTA/data/users/$user/web.conf" 2>/dev/null | grep -o "SUSPENDED='[^']*'" | cut -d "'" -f 2)
    if [ "$suspended" = 'yes' ]; then
        report_level INFO
        report_line 'The web domain is suspended in myVesta: visitors see the suspension page, and wp-cli based checks are skipped.'
    fi
    if [ -z "$code" ] || [ "$code" = '000' ]; then
        report_level WARNING
        report_summary 'site not reachable'
        report_line "The site did not answer over HTTPS or HTTP from this server (curl could not connect)."
    else
        report_line "Home page: HTTP $code, final URL $final_url"
        if [ -n "$final_host" ] && [ "$(imav_report_base_host "$final_host")" != "$expected" ]; then
            report_level CRITICAL
            redirect_note="redirects to $final_host"
            report_line "The home page redirects to another domain ($final_host). Unless this is intentional, it is the classic symptom of a hacked site."
        elif [ "$code" -ge 500 ]; then
            report_level WARNING
            redirect_note="HTTP $code"
        fi
        if grep -qi '<meta[^>]*http-equiv=["'"'"']*refresh' "$body"; then
            report_level WARNING
            report_line "The home page contains a meta refresh redirect: $(grep -oi '<meta[^>]*http-equiv=["'"'"']*refresh[^>]*>' "$body" | head -n 1)"
        fi
        ext_hosts=$(grep -oiE '<script[^>]+src=["'"'"']?(https?:)?//[^/"'"'"' >]+' "$body" \
            | sed -E 's|.*//||' | tr 'A-Z' 'a-z' | sort -u \
            | while read -r h; do [ "$(imav_report_base_host "$h")" != "$expected" ] && echo "$h"; done | head -n 20)
        if [ -n "$ext_hosts" ]; then
            report_line ''
            report_line 'External hosts the home page loads scripts from (verify that each one is expected):'
            echo "$ext_hosts" | sed 's/^/  /' | report_block
        fi
    fi
    rm -f "$body"

    enddate=$(echo | timeout 20 openssl s_client -servername "$domain" -connect "$domain:443" 2>/dev/null \
        | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
    if [ -n "$enddate" ]; then
        days=$(( ($(date -d "$enddate" +%s) - $(date +%s)) / 86400 ))
        if [ "$days" -lt 0 ]; then
            report_level CRITICAL
            report_line "SSL certificate EXPIRED on $enddate."
        elif [ "$days" -lt "$REPORT_SSL_WARN_DAYS" ]; then
            report_level WARNING
            report_line "SSL certificate expires in $days day(s) ($enddate)."
        else
            report_line "SSL certificate valid until $enddate ($days days)."
        fi
    else
        report_line 'SSL certificate could not be read (no HTTPS on port 443?).'
    fi
    [ -z "$redirect_note" ] && redirect_note="HTTP ${code:-none}${enddate:+, SSL $days days}"
    [ "$suspended" = 'yes' ] && redirect_note="suspended in myVesta, $redirect_note"
    report_summary "$redirect_note"
}

imav_report_check_admins() {
    report_section 'admins' 'WordPress administrators'
    if [ $is_wp -eq 0 ]; then
        report_summary 'not a WordPress site'
        report_line 'Not a WordPress installation.'
        return
    fi
    local rows previous current new recent login email registered id cutoff
    rows=$(imav_report_wp user list --role=administrator --fields=ID,user_login,user_email,user_registered --format=csv 2>/dev/null | tail -n +2)
    if [ -z "$rows" ] && imav_db_credentials "$domain" 2>/dev/null; then
        rows=$(imav_db_query "SELECT u.ID, u.user_login, u.user_email, u.user_registered FROM ${IMAV_DB_PREFIX}users u JOIN ${IMAV_DB_PREFIX}usermeta m ON m.user_id=u.ID WHERE m.meta_key='${IMAV_DB_PREFIX}capabilities' AND m.meta_value LIKE '%administrator%'" | tr '\t' ',')
    fi
    if [ -z "$rows" ]; then
        report_level INFO
        report_summary 'could not list'
        report_line 'The administrator list could not be read (wp-cli and database both unavailable).'
        return
    fi
    current=$(echo "$rows" | cut -d, -f2 | sort | tr '\n' ',' | sed 's/,$//')
    previous=$(imav_state_get "$domain" 'ADMINS')
    new=''
    if [ -n "$previous" ]; then
        new=$(comm -13 <(echo "$previous" | tr ',' '\n' | sort) <(echo "$current" | tr ',' '\n' | sort))
    fi
    cutoff=$(date -d "$REPORT_NEW_ADMIN_DAYS days ago" +'%F')
    recent=$(echo "$rows" | awk -F, -v c="$cutoff" '$4 >= c { print $2 }')
    # Accounts typical of a compromise: a reserved or unresolvable email domain,
    # a login that ends in a long random hexadecimal string, a login built from
    # words planted accounts use (backup, seo, support, wpadmin, test, dev,
    # temp), or an email on the site's own domain, which attackers choose
    # because it looks plausible and never bounces.
    local odd
    odd=$(echo "$rows" | awk -F, -v site="$(echo "$domain" | tr 'A-Z' 'a-z')" '
        BEGIN { gsub(/\./, "\\.", site) }
        {
            login = tolower($2); email = tolower($3); note = ""
            if (email ~ /@([^.]+\.)*(invalid|internal|local|localhost|test|example)$/ || email ~ /@example\.(com|net|org)$/) note = "reserved email domain " $3
            else if (login ~ /[0-9a-f]{12,}$/) note = "random login"
            else {
                if (login ~ /backup|seo|support|wp[-_]?admin/ || login ~ /(^|[^a-z])(test|dev|temp|tmp)([^a-z]|$)/) note = "login typical of planted accounts"
                if (email ~ ("@(www\\.)?" site "$")) note = note (note == "" ? "" : "; ") "email on the domain of the site itself"
            }
            if (note != "") print $2 " (" note ")"
        }')

    report_table_header 'ID' 'Login' 'Email' 'Registered'
    echo "$rows" | while IFS=',' read -r id login email registered; do report_table_row "$id" "$login" "$email" "$registered"; done
    if [ -n "$new" ]; then
        report_level WARNING
        report_line ''
        report_line "New administrator(s) since the previous report: $(echo "$new" | tr '\n' ' ')"
    fi
    if [ -n "$recent" ]; then
        report_level WARNING
        report_line ''
        report_line "Administrator(s) registered in the last $REPORT_NEW_ADMIN_DAYS days: $(echo "$recent" | tr '\n' ' ')"
    fi
    if [ -n "$odd" ]; then
        report_level WARNING
        report_line ''
        report_line 'Administrator account(s) to review, with the traits of accounts planted by an attacker (reserved email domain, random login, login built from words such as backup, seo, support, wpadmin, test, or an email on the domain of the site itself):'
        echo "$odd" | sed 's/^/  /' | report_block
    fi
    report_summary "$(echo "$rows" | grep -c .) administrator(s)${new:+, NEW: $(echo "$new" | tr '\n' ' ')}${odd:+, suspicious: $(echo "$odd" | grep -c .)}"
    imav_state_set "$domain" 'ADMINS' "$current"
}

imav_report_check_plugins() {
    report_section 'plugins' 'Plugins'
    if [ $is_wp -eq 0 ]; then
        report_summary 'not a WordPress site'
        report_line 'Not a WordPress installation.'
        return
    fi
    local dir total recent current previous new inactive list name
    dir="$docroot/wp-content/plugins"
    total=$(find "$dir" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | wc -l)
    recent=$(find "$dir" -maxdepth 1 -mindepth 1 -type d -mtime -7 2>/dev/null | sort)
    current=$(find "$dir" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | xargs -r -n1 basename | sort | tr '\n' ',' | sed 's/,$//')
    previous=$(imav_state_get "$domain" 'PLUGINS')
    new=''
    [ -n "$previous" ] && new=$(comm -13 <(echo "$previous" | tr ',' '\n' | sort) <(echo "$current" | tr ',' '\n' | sort))
    list=$(imav_report_wp plugin list --fields=name,status,version --format=csv 2>/dev/null | tail -n +2)
    inactive=$(echo "$list" | awk -F, '$2 == "inactive"' | grep -c .)

    report_line "$total plugin directories, $(echo "$recent" | grep -c .) modified in the last 7 days${list:+, $inactive inactive}."
    if [ -n "$new" ]; then
        report_level INFO
        report_line "New since the previous report: $(echo "$new" | tr '\n' ' ')"
    fi
    if [ -n "$recent" ]; then
        report_line ''
        report_table_header 'Plugin' 'Modified' 'Files changed (7 days)'
        echo "$recent" | while IFS= read -r p; do
            report_table_row "$(basename "$p")" "$(date -r "$p" +'%F %T')" "$(find "$p" -type f -mtime -7 2>/dev/null | wc -l)"
        done
    fi
    if [ "$inactive" -gt 0 ]; then
        report_line ''
        report_line "Inactive plugins are still reachable over the web and should be deleted if not needed: $(echo "$list" | awk -F, '$2 == "inactive" { print $1 }' | tr '\n' ' ')"
    fi
    report_summary "$total total, $(echo "$recent" | grep -c .) changed in 7 days${new:+, new: $(echo "$new" | tr '\n' ' ')}"
    imav_state_set "$domain" 'PLUGINS' "$current"
}

imav_report_check_cron() {
    report_section 'cron' 'WordPress cron tasks'
    if [ $is_wp -eq 0 ]; then
        report_summary 'not a WordPress site'
        report_line 'Not a WordPress installation.'
        return
    fi
    local core='wp_version_check|wp_update_plugins|wp_update_themes|wp_scheduled_delete|wp_scheduled_auto_draft_delete|wp_privacy_delete_old_export_files|wp_site_health_scheduled_check|wp_update_user_counts|wp_delete_temp_updater_backups|delete_expired_transients|recovery_mode_clean_expired_keys|wp_split_shared_term_batch|wp_https_detection|wp_maybe_auto_update'
    local rows custom hook next rec
    rows=$(imav_report_wp cron event list --fields=hook,next_run_relative,recurrence --format=csv 2>/dev/null | tail -n +2)
    if [ -z "$rows" ]; then
        report_level INFO
        report_summary 'wp-cli did not run'
        report_line "Cron events could not be listed (check: v-run-wp-cli $domain cron event list)."
        return
    fi
    custom=$(echo "$rows" | grep -vE "^($core),")
    report_summary "$(echo "$rows" | grep -c .) event(s), $(echo "$custom" | grep -c .) from plugins or custom"
    if [ -n "$custom" ]; then
        report_line 'Plugin and custom cron events (unknown hooks that call external URLs deserve a look):'
        report_table_header 'Hook' 'Next run' 'Recurrence'
        echo "$custom" | while IFS=',' read -r hook next rec; do report_table_row "$hook" "$next" "$rec"; done
    else
        report_line 'Only WordPress core cron events are scheduled.'
    fi
}

imav_report_check_mail() {
    report_section 'mail' 'Outgoing mail from this account'
    local cutoff count logs
    cutoff=$(date -d '24 hours ago' +'%F %T')
    logs='/var/log/exim4/mainlog'
    [ -f /var/log/exim4/mainlog.1 ] && logs="/var/log/exim4/mainlog.1 $logs"
    count=$(cat $logs 2>/dev/null | awk -v c="$cutoff" -v u="$user" '$1" "$2 >= c && / <= / && index($0, " U=" u " ") { n++ } END { print n+0 }')
    if [ "$count" -gt "$REPORT_MAIL_WARN" ]; then
        report_level WARNING
        report_summary "$count messages in 24 h (above $REPORT_MAIL_WARN)"
        report_line "$count messages were submitted to the mail server by the system user $user in the last 24 hours, which is above the threshold of $REPORT_MAIL_WARN. A spike usually means a compromised contact form or a mailer script."
    else
        report_summary "$count messages in 24 h"
        report_line "$count messages were submitted by the system user $user in the last 24 hours (threshold $REPORT_MAIL_WARN)."
    fi
}

imav_report_check_php_version() {
    report_section 'php' 'PHP version'
    local version eol today
    version=$("$BIN/v-get-php-version-of-domain" "$domain" 2>/dev/null)
    if [ -z "$version" ]; then
        report_summary 'unknown'
        report_line 'The PHP version of the domain could not be determined (no PHP-FPM template).'
        return
    fi
    case $version in
        5.*|7.0) eol='2018-12-31' ;; 7.1) eol='2019-12-01' ;; 7.2) eol='2020-11-30' ;; 7.3) eol='2021-12-06' ;;
        7.4) eol='2022-11-28' ;; 8.0) eol='2023-11-26' ;; 8.1) eol='2025-12-31' ;; 8.2) eol='2026-12-31' ;;
        8.3) eol='2027-12-31' ;; 8.4) eol='2028-12-31' ;; 8.5) eol='2029-12-31' ;; *) eol='' ;;
    esac
    today=$(date +%F)
    if [ -n "$eol" ] && [[ "$eol" < "$today" ]]; then
        report_level WARNING
        report_summary "PHP $version, end of life since $eol"
        report_line "The site runs on PHP $version, which stopped receiving security fixes on $eol. Switch the domain to a supported PHP version."
    else
        report_summary "PHP $version"
        report_line "The site runs on PHP $version${eol:+ (security support until $eol)}."
    fi
}

imav_report_check_hidden() {
    report_section 'hidden' 'Hidden files and symbolic links'
    local hidden links target l
    hidden=$(find "$docroot" -maxdepth 2 -name '.*' ! -name '.htaccess' ! -name '.htpasswd' ! -name '.well-known' ! -name '.user.ini' ! -name '.maintenance' ! -name '.' 2>/dev/null | head -n 40)
    links=''
    while IFS= read -r l; do
        [ -z "$l" ] && continue
        target=$(readlink -f "$l" 2>/dev/null)
        case "$target" in
            "$docroot"/*) ;;
            *) links="$links${l#$docroot/} -> $target"$'\n' ;;
        esac
    done < <(find "$docroot" -type l 2>/dev/null | head -n 200)

    if echo "$hidden" | grep -q '/\.git$\|/\.svn$\|/\.env$'; then
        report_level WARNING
    elif [ -n "$hidden" ]; then
        report_level INFO
    fi
    [ -n "$links" ] && report_level WARNING
    if [ -z "$hidden$links" ]; then
        report_summary 'none'
        report_line 'No unexpected hidden files in the top two levels and no symbolic links pointing outside the document root.'
        return
    fi
    report_summary "$(printf '%s\n%s' "$hidden" "$links" | grep -c .) item(s)"
    if [ -n "$hidden" ]; then
        report_line 'Hidden files and directories (a .git, .svn or .env directory exposes source code or credentials):'
        echo "$hidden" | sed "s|^$docroot/|  |" | report_block
    fi
    if [ -n "$links" ]; then
        report_line ''
        report_line 'Symbolic links pointing outside the document root:'
        printf '%s' "$links" | sed 's/^/  /' | report_block
    fi
}

imav_report_check_sizes() {
    report_section 'sizes' 'Directory sizes and file count trend'
    local total_size total_files prev delta uploads_size uploads_files uprev udelta note=''
    total_size=$(du -sh "$docroot" 2>/dev/null | cut -f1)
    total_files=$(find "$docroot" -type f 2>/dev/null | wc -l)
    prev=$(imav_state_get "$domain" 'TOTAL_FILES')
    if [ -n "$prev" ]; then
        delta=$((total_files - prev))
        if [ "$delta" -gt "$REPORT_FILE_GROWTH_WARN" ]; then
            report_level WARNING
            note=" (+$delta since the previous report, above the threshold of $REPORT_FILE_GROWTH_WARN)"
        elif [ "$delta" -ne 0 ]; then
            note=" ($([ $delta -gt 0 ] && echo +)$delta since the previous report)"
        else
            note=' (no change since the previous report)'
        fi
    fi
    report_line "Document root: $total_size, $total_files files$note"
    if [ -d "$docroot/wp-content/uploads" ]; then
        uploads_size=$(du -sh "$docroot/wp-content/uploads" 2>/dev/null | cut -f1)
        uploads_files=$(find "$docroot/wp-content/uploads" -type f 2>/dev/null | wc -l)
        uprev=$(imav_state_get "$domain" 'UPLOADS_FILES')
        udelta=''
        [ -n "$uprev" ] && udelta=" ($([ $((uploads_files - uprev)) -gt 0 ] && echo +)$((uploads_files - uprev)) since the previous report)"
        report_line "wp-content/uploads: $uploads_size, $uploads_files files$udelta"
        imav_state_set "$domain" 'UPLOADS_FILES' "$uploads_files"
    fi
    report_summary "$total_size, $total_files files$note"
    imav_state_set "$domain" 'TOTAL_FILES' "$total_files"
}

imav_report_check_root_php() {
    report_section 'root-php' 'PHP files in the root directory'
    local standard='index.php|wp-activate.php|wp-blog-header.php|wp-comments-post.php|wp-config.php|wp-config-sample.php|wp-cron.php|wp-links-opml.php|wp-load.php|wp-login.php|wp-mail.php|wp-settings.php|wp-signup.php|wp-trackback.php|xmlrpc.php'
    local found f
    found=$(find "$docroot" -maxdepth 1 -name '*.php' -type f 2>/dev/null | xargs -r -n1 basename | grep -vE "^($standard)$" | sort)
    if [ $is_wp -eq 0 ]; then
        report_summary "$(echo "$found" | grep -c .) PHP file(s) in root"
        report_line 'Not a WordPress installation; PHP files in the root are listed for information.'
    elif [ -n "$found" ]; then
        report_level WARNING
        report_summary "$(echo "$found" | grep -c .) non-standard file(s)"
        report_line 'PHP files in the root that are not part of WordPress (security plugins put some there, backdoors too):'
    else
        report_summary 'only WordPress files'
        report_line 'Only the standard WordPress PHP files are in the root directory.'
        return
    fi
    [ -z "$found" ] && return
    report_table_header 'File' 'Size' 'Modified' 'Owner'
    echo "$found" | while IFS= read -r f; do
        report_table_row "$f" "$(stat -c %s "$docroot/$f")" "$(date -r "$docroot/$f" +'%F %T')" "$(stat -c %U "$docroot/$f")"
    done
}

imav_report_check_modified() {
    report_section 'modified' 'Recently modified PHP files'
    report_summary 'for reference'
    report_line 'The 30 most recently modified PHP files (modification time, size, owner, path):'
    (cd "$docroot" && find . -name '*.php' -type f -printf '%TY-%Tm-%Td %TH:%TM  %8s  %-12u  %p\n' 2>/dev/null | sort -r | head -n 30) | report_block
    report_line ''
    report_line 'The 30 most recently changed PHP files (status change time, catches permission and ownership changes):'
    (cd "$docroot" && find . -name '*.php' -type f -printf '%CY-%Cm-%Cd %CH:%CM  %8s  %-12u  %p\n' 2>/dev/null | sort -r | head -n 30) | report_block
}


#----------------------------------------------------------#
#                    Run all checks                        #
#----------------------------------------------------------#

# Run every check for the current domain. Needs $domain, $user, $docroot.
imav_report_run_checks() {
    is_wp=0
    imav_is_wordpress "$docroot" && is_wp=1
    imav_report_check_malware
    imav_report_check_heuristics
    imav_report_check_vuln
    imav_report_check_db
    imav_report_check_core_integrity
    imav_report_check_plugin_integrity
    imav_report_check_updates
    imav_report_check_php_files
    imav_report_check_backups
    imav_report_check_htaccess
    imav_report_check_external
    imav_report_check_admins
    imav_report_check_plugins
    imav_report_check_cron
    imav_report_check_mail
    imav_report_check_php_version
    imav_report_check_hidden
    imav_report_check_sizes
    imav_report_check_root_php
    imav_report_check_modified
    imav_state_set "$domain" 'LAST_REPORT' "$(date +'%F %T')"
}


#----------------------------------------------------------#
#                    Rendering                             #
#----------------------------------------------------------#

# Plain-text report to stdout
# $1 = overall level
imav_report_render_text() {
    local overall="$1" id title level summary kind rest
    echo "SECURITY REPORT: $domain"
    echo "Server: $(hostname -f 2>/dev/null || hostname)   Date: $(date +'%F %T')   Status: $overall"
    echo
    echo "$IMAV_REPORT_NOTE" | fold -s -w 78
    echo
    echo "SUMMARY"
    echo "-------"
    while read -r id; do
        title=$(cat "$REPORT_TMP/$id.title")
        level=$(cat "$REPORT_TMP/$id.level")
        summary=$(cat "$REPORT_TMP/$id.summary")
        printf '  %-9s %s: %s\n' "[$level]" "$title" "$summary"
    done < "$REPORT_SECTION_LIST"
    while read -r id; do
        title=$(cat "$REPORT_TMP/$id.title")
        level=$(cat "$REPORT_TMP/$id.level")
        echo
        echo "==============================================================================="
        echo " [$level] $title"
        echo "==============================================================================="
        while IFS=$'\t' read -r kind rest; do
            case $kind in
                L) echo "$rest" | fold -s -w 78 ;;
                P) echo "$rest" ;;
                H) echo "$rest" | tr '\t' '|' | sed 's/|/  |  /g' ;;
                R) echo "$rest" | tr '\t' '|' | sed 's/|/  |  /g' ;;
            esac
        done < <(sed 's/\t/\t/' "$REPORT_TMP/$id.body")
    done < "$REPORT_SECTION_LIST"
    echo
    echo "Generated by myVesta ImunifyAV integration on $(hostname -f 2>/dev/null || hostname). Report history on the server: $REPORT_HISTORY_DIR/$domain/"
}

# HTML escape stdin
imav_report_html_escape() {
    sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
}

# Colour of a level
imav_report_level_color() {
    case $1 in
        CRITICAL) echo '#c62828' ;;
        WARNING)  echo '#ef6c00' ;;
        INFO)     echo '#1565c0' ;;
        *)        echo '#2e7d32' ;;
    esac
}

# HTML report to stdout
# $1 = overall level
imav_report_render_html() {
    local overall="$1" id title level summary kind rest color in_table=0
    cat <<EOF
<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Security report: $domain</title></head>
<body style="margin:0;padding:0;background:#f4f5f7;font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#222;">
<div style="max-width:900px;margin:0 auto;padding:20px;">
<div style="background:$(imav_report_level_color "$overall");color:#ffffff;padding:18px 22px;border-radius:6px 6px 0 0;">
  <div style="font-size:20px;font-weight:bold;color:#ffffff;">Security report: <a href="https://$domain/" style="color:#ffffff;text-decoration:none;">$domain</a></div>
  <div style="margin-top:6px;color:#ffffff;">Status: <b>$overall</b> &nbsp;|&nbsp; Server: <a href="https://$(hostname -f 2>/dev/null || hostname)/" style="color:#ffffff;text-decoration:none;">$(hostname -f 2>/dev/null || hostname)</a> &nbsp;|&nbsp; $(date +'%F %T')</div>
</div>
<div style="background:#fff;padding:18px 22px;border:1px solid #ddd;border-top:0;">
<p style="margin:0 0 16px 0;color:#555;font-size:13px;">$(echo "$IMAV_REPORT_NOTE" | imav_report_html_escape)</p>
<table style="border-collapse:collapse;width:100%;margin-bottom:8px;">
<tr><th style="text-align:left;padding:6px 8px;border-bottom:2px solid #ddd;">Check</th><th style="text-align:left;padding:6px 8px;border-bottom:2px solid #ddd;">Status</th><th style="text-align:left;padding:6px 8px;border-bottom:2px solid #ddd;">Result</th></tr>
EOF
    while read -r id; do
        title=$(cat "$REPORT_TMP/$id.title" | imav_report_html_escape)
        level=$(cat "$REPORT_TMP/$id.level")
        summary=$(cat "$REPORT_TMP/$id.summary" | imav_report_html_escape)
        color=$(imav_report_level_color "$level")
        echo "<tr><td style=\"padding:5px 8px;border-bottom:1px solid #eee;\"><a href=\"#$id\" style=\"color:#222;text-decoration:none;\">$title</a></td><td style=\"padding:5px 8px;border-bottom:1px solid #eee;\"><span style=\"background:$color;color:#fff;padding:2px 8px;border-radius:3px;font-size:12px;font-weight:bold;\">$level</span></td><td style=\"padding:5px 8px;border-bottom:1px solid #eee;\">$summary</td></tr>"
    done < "$REPORT_SECTION_LIST"
    echo '</table></div>'

    while read -r id; do
        title=$(cat "$REPORT_TMP/$id.title" | imav_report_html_escape)
        level=$(cat "$REPORT_TMP/$id.level")
        color=$(imav_report_level_color "$level")
        echo "<div id=\"$id\" style=\"background:#fff;border:1px solid #ddd;border-top:0;padding:14px 22px;\">"
        echo "<h3 style=\"margin:0 0 10px 0;font-size:16px;border-left:5px solid $color;padding-left:10px;\">$title <span style=\"background:$color;color:#fff;padding:1px 7px;border-radius:3px;font-size:11px;vertical-align:middle;\">$level</span></h3>"
        in_table=0
        while IFS=$'\t' read -r kind rest; do
            case $kind in
                H)
                    [ $in_table -eq 1 ] && echo '</table>'
                    echo '<table style="border-collapse:collapse;width:100%;margin:6px 0;font-size:13px;"><tr>'
                    echo "$rest" | tr '\t' '\n' | imav_report_html_escape | sed 's|.*|<th style="text-align:left;padding:4px 6px;background:#f0f0f0;border:1px solid #ddd;">&</th>|'
                    echo '</tr>'
                    in_table=1 ;;
                R)
                    [ $in_table -eq 0 ] && { echo '<table style="border-collapse:collapse;width:100%;margin:6px 0;font-size:13px;">'; in_table=1; }
                    echo '<tr>'
                    echo "$rest" | tr '\t' '\n' | imav_report_html_escape | sed 's|.*|<td style="padding:4px 6px;border:1px solid #ddd;word-break:break-all;">&</td>|'
                    echo '</tr>' ;;
                P)
                    [ $in_table -eq 1 ] && { echo '</table>'; in_table=0; }
                    echo "<pre style=\"margin:4px 0;padding:8px;background:#f7f7f7;border:1px solid #e5e5e5;font-size:12px;white-space:pre-wrap;word-break:break-all;\">$(echo "$rest" | imav_report_html_escape)</pre>" ;;
                L)
                    [ $in_table -eq 1 ] && { echo '</table>'; in_table=0; }
                    if [ -z "$rest" ]; then echo '<div style="height:6px;"></div>'; else echo "<p style=\"margin:4px 0;\">$(echo "$rest" | imav_report_html_escape)</p>"; fi ;;
            esac
        done < "$REPORT_TMP/$id.body"
        [ $in_table -eq 1 ] && echo '</table>'
        echo '</div>'
    done < "$REPORT_SECTION_LIST"
    # Consecutive <pre> blocks are merged visually by the browser margins; fine for email.
    cat <<EOF
<div style="background:#fff;border:1px solid #ddd;border-top:0;border-radius:0 0 6px 6px;padding:12px 22px;color:#777;font-size:12px;">
Generated by myVesta ImunifyAV integration on <a href="https://$(hostname -f 2>/dev/null || hostname)/" style="color:#777777;text-decoration:none;">$(hostname -f 2>/dev/null || hostname)</a>. Report history on the server: $REPORT_HISTORY_DIR/$domain/
</div></div></body></html>
EOF
}
