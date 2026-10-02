#!/bin/bash
# myVesta ImunifyAV integration: vulnerability scanner engine.
#
# Reads the installed WordPress core, plugin and theme versions from the files
# of a document root (no wp-cli, no database), queries the WPVulnerability API
# (no key) and optionally the Wordfence Intelligence v3 scanner feed (free key
# in WF_API_KEY), and prints the matching vulnerabilities.
#
# Requires func/imav.sh.

WPV_API='https://www.wpvulnerability.net'
WF_FEED='https://www.wordfence.com/api/intelligence/v3/vulnerabilities/scanner'


#----------------------------------------------------------#
#                    Inventory from disk                   #
#----------------------------------------------------------#

# Prints one line per component: TYPE<TAB>SLUG<TAB>VERSION<TAB>NAME
# $1 = docroot
imav_vuln_inventory() {
    local docroot="$1" dir slug version name main

    version=$(imav_wp_version "$docroot")
    if [ -n "$version" ]; then
        printf 'core\twordpress\t%s\tWordPress\n' "$version"
    fi

    for dir in "$docroot"/wp-content/plugins/*/; do
        [ -d "$dir" ] || continue
        slug=$(basename "$dir")
        main=$(imav_wp_plugin_main_file "$dir") || continue
        version=$(imav_wp_header "$main" 'Version')
        name=$(imav_wp_header "$main" 'Plugin Name')
        printf 'plugin\t%s\t%s\t%s\n' "$slug" "${version:-unknown}" "${name:-$slug}"
    done
    for main in "$docroot"/wp-content/plugins/*.php; do
        [ -f "$main" ] || continue
        head -c 8192 "$main" | grep -qi 'Plugin Name:' || continue
        slug=$(basename "$main" .php)
        # Single-file plugins whose wordpress.org slug differs from the file name
        case $slug in
            hello) slug='hello-dolly' ;;
        esac
        version=$(imav_wp_header "$main" 'Version')
        name=$(imav_wp_header "$main" 'Plugin Name')
        printf 'plugin\t%s\t%s\t%s\n' "$slug" "${version:-unknown}" "${name:-$slug}"
    done

    for dir in "$docroot"/wp-content/themes/*/; do
        [ -f "$dir/style.css" ] || continue
        slug=$(basename "$dir")
        version=$(imav_wp_header "$dir/style.css" 'Version')
        name=$(imav_wp_header "$dir/style.css" 'Theme Name')
        printf 'theme\t%s\t%s\t%s\n' "$slug" "${version:-unknown}" "${name:-$slug}"
    done
}


#----------------------------------------------------------#
#                    WPVulnerability                       #
#----------------------------------------------------------#

# Fetch (cached) the WPVulnerability record for a component; prints the file path
# $1 = type (core, plugin, theme), $2 = slug, $3 = version (core only)
imav_wpv_fetch() {
    local type="$1" slug="$2" version="$3" url file
    case $type in
        core)   url="$WPV_API/core/$version";   file="$CACHE_DIR/wpv/core/$version.json" ;;
        plugin) url="$WPV_API/plugin/$slug";    file="$CACHE_DIR/wpv/plugin/$slug.json" ;;
        theme)  url="$WPV_API/theme/$slug";     file="$CACHE_DIR/wpv/theme/$slug.json" ;;
        *)      return 1 ;;
    esac
    if imav_cached_download "$url" "$file" "$VULN_CACHE_TTL" -H 'Accept: application/json'; then
        if jq -e '.error == 0' "$file" >/dev/null 2>&1; then
            echo "$file"
            return 0
        fi
    fi
    return 1
}

# Match WPVulnerability records against an installed version.
# Prints one line per match: TITLE<TAB>CVSS<TAB>FIXED_IN<TAB>SOURCE<TAB>LINK<TAB>INFORMATIONAL
# $1 = record file, $2 = installed version
imav_wpv_match() {
    local file="$1" version="$2"
    local line name minv minop maxv maxop unfixed cvss link fixed

    while IFS="$IMAV_FS" read -r name minv minop maxv maxop unfixed cvss link; do
        [ -z "$name" ] && continue
        name=$(echo "$name" | sed -e 's/&#8211;/-/g' -e 's/&#8212;/-/g' -e 's/&amp;/\&/g' -e 's/&#039;/'"'"'/g' -e 's/&quot;/"/g' -e 's/&lt;/</g' -e 's/&gt;/>/g')
        if [ -n "$minv" ] && [ "$minv" != 'null' ]; then
            imav_version_compare "$version" "$minop" "$minv" || continue
        fi
        if [ -n "$maxv" ] && [ "$maxv" != 'null' ]; then
            imav_version_compare "$version" "$maxop" "$maxv" || continue
        fi
        fixed='unknown'
        if [ "$unfixed" = '1' ]; then
            fixed='no fix'
        elif [ -n "$maxv" ] && [ "$maxv" != 'null' ]; then
            case $maxop in
                lt) fixed="$maxv" ;;
                le) fixed="> $maxv" ;;
                eq) fixed="!= $maxv" ;;
            esac
        fi
        printf '%s\x1f%s\x1f%s\x1fwpvulnerability\x1f%s\x1fno\n' "$name" "${cvss:-}" "$fixed" "${link:-}"
    done < <(jq -r --arg v "$version" '
        (.data.vulnerability // [])[] |
        [
            # core records carry only the version as name: use the CVE and its description
            (if (.name // "") == "" or (.name == $v) then
                (((.source // [])[0].name // "unnamed") + " " + ((((.source // [])[0].description // "") | sub("^\\[..\\] "; "")) | .[0:90]))
             else .name end),
            (.operator.min_version // ""), (.operator.min_operator // "ge"),
            (.operator.max_version // ""), (.operator.max_operator // "lt"),
            ((.operator.unfixed // "0") | tostring),
            ((.impact // {}) | if type == "object" then (.cvss3.score // .cvss.score // "") else "" end),
            ((.source // []) | if type == "array" then (.[0].link // "") else (.link // "") end)
        ] | map(if . == null then "" else tostring end) | join("\u001f")' "$file" 2>/dev/null)
}


#----------------------------------------------------------#
#                    Wordfence Intelligence                #
#----------------------------------------------------------#

# Download the Wordfence scanner feed (once a day) and split it into one
# JSON-lines file per component in $CACHE_DIR/wf-index/TYPE/SLUG.jsonl.
# Sets IMAV_WF_STATE to "no-key", "unavailable", "stale" or "ok" and
# IMAV_WF_FEED_DATE to the download time of the feed in use.
# Returns 1 when the feed is not available and no index exists.
imav_wf_index() {
    local feed="$CACHE_DIR/wf-scanner.json" index="$CACHE_DIR/wf-index" stamp="$CACHE_DIR/wf-index/.built"
    IMAV_WF_STATE='no-key'
    IMAV_WF_FEED_DATE=''
    [ -z "$WF_API_KEY" ] && return 1

    # The feed is tens of megabytes: allow a long download
    if ! imav_cached_download "$WF_FEED" "$feed" "$VULN_CACHE_TTL" \
        -H "Authorization: Bearer $WF_API_KEY" -H 'Accept: application/json' -m 900; then
        IMAV_WF_STATE='unavailable'
        IMAV_WF_ERROR=$IMAV_DOWNLOAD_ERROR
        return 1
    fi
    IMAV_WF_STATE='ok'
    [ "$IMAV_CACHE_STALE" = '1' ] && IMAV_WF_STATE='stale'
    IMAV_WF_FEED_DATE=$(date -r "$feed" +'%F %T' 2>/dev/null)

    if [ -f "$stamp" ] && [ ! "$feed" -nt "$stamp" ]; then
        return 0
    fi

    rm -rf "$index"
    mkdir -p "$index/core" "$index/plugin" "$index/theme"
    jq -r '
        to_entries[] | .value as $v | ($v.software // [])[] |
        [ .type, .slug,
          ({title: $v.title, id: $v.id, cve: $v.cve, informational: ($v.informational // false),
            cvss: ($v.cvss.score // null),
            affected_versions: (.affected_versions // {}),
            patched_versions: (.patched_versions // []),
            references: ($v.references // [])} | tojson)
        ] | @tsv' "$feed" 2>/dev/null \
    | awk -F'\t' -v dir="$index" '
        # some feed records carry a URL or path as slug; those cannot match a directory name
        $1 ~ /^(core|plugin|theme)$/ && $2 != "" && $2 !~ /[\/ ]/ {
            f = dir "/" $1 "/" $2 ".jsonl"; print $3 >> f; close(f)
        }'
    touch "$stamp"
    return 0
}

# The patched version that applies to the installed branch: the lowest
# patched version above the installed one within the same major.minor,
# otherwise the highest patched version overall.
# $1 = installed version, $2 = patched versions separated by spaces
imav_wf_fixed_in() {
    local installed="$1" p best='' branch
    [ -z "$2" ] && { echo 'unknown'; return; }
    branch=$(echo "$installed" | cut -d. -f1-2)
    for p in $2; do
        if [ "$(echo "$p" | cut -d. -f1-2)" = "$branch" ] && imav_version_compare "$installed" 'lt' "$p"; then
            if [ -z "$best" ] || imav_version_compare "$p" 'lt' "$best"; then best=$p; fi
        fi
    done
    if [ -z "$best" ]; then
        for p in $2; do
            if [ -z "$best" ] || imav_version_compare "$p" 'gt' "$best"; then best=$p; fi
        done
    fi
    echo "$best"
}

# Match Wordfence records against an installed version.
# Prints the same record format as imav_wpv_match with SOURCE = wordfence.
# One jq pass emits one line per (record, version range); the loop in bash
# compares versions without subprocesses and reports each record once.
# $1 = type, $2 = slug, $3 = installed version
imav_wf_match() {
    local file="$CACHE_DIR/wf-index/$1/$2.jsonl"
    [ -f "$file" ] || return 0
    local version="$3"
    local id title cvss cve info patched refs from finc to tinc last_id=''

    while IFS="$IMAV_FS" read -r id title cvss cve info patched refs from finc to tinc; do
        [ -z "$id" ] && continue
        [ "$id" = "$last_id" ] && continue
        if [ "$from" != '*' ] && [ -n "$from" ]; then
            if [ "$finc" = 'true' ]; then
                imav_version_compare "$version" 'ge' "$from" || continue
            else
                imav_version_compare "$version" 'gt' "$from" || continue
            fi
        fi
        if [ "$to" != '*' ] && [ -n "$to" ]; then
            if [ "$tinc" = 'true' ]; then
                imav_version_compare "$version" 'le' "$to" || continue
            else
                imav_version_compare "$version" 'lt' "$to" || continue
            fi
        fi
        last_id=$id
        [ -n "$cve" ] && [ "$cve" != 'null' ] && title="$title ($cve)"
        printf '%s\x1f%s\x1f%s\x1fwordfence\x1f%s\x1f%s\n' "$title" "${cvss/null/}" "$(imav_wf_fixed_in "$version" "$patched")" "${refs:-}" "${info/false/no}"
    done < <(jq -r '
        . as $r | ((.affected_versions // {}) | to_entries[]) as $e |
        [ ($r.id // $r.title), $r.title, ($r.cvss // ""), ($r.cve // ""), (($r.informational // false)|tostring),
          (($r.patched_versions // []) | join(" ")),
          (($r.references // [])[0] // ""),
          ($e.value.from_version // "*"), (($e.value.from_inclusive // true)|tostring),
          ($e.value.to_version // "*"), (($e.value.to_inclusive // true)|tostring)
        ] | map(if . == null then "" else tostring end) | join("\u001f")' "$file" 2>/dev/null)
}


#----------------------------------------------------------#
#                    Scan of one document root             #
#----------------------------------------------------------#

# Prints one line per finding:
# TYPE<TAB>SLUG<TAB>VERSION<TAB>TITLE<TAB>CVSS<TAB>FIXED_IN<TAB>SOURCE<TAB>LINK
# Components that could not be checked are reported with TITLE starting with "-".
# $1 = docroot
imav_vuln_scan() {
    local docroot="$1"
    local type slug version name file matches line
    local have_wf=0

    if imav_wf_index; then
        have_wf=1
    fi

    while IFS=$'\t' read -r type slug version name; do
        [ -z "$type" ] && continue
        if [ "$version" = 'unknown' ]; then
            printf '%s\t%s\t%s\t- version not found in files\t\t\t\t\n' "$type" "$slug" "$version"
            continue
        fi

        matches=''
        if file=$(imav_wpv_fetch "$type" "$slug" "$version"); then
            if [ "$type" != 'core' ] && jq -e '.data.name == null' "$file" >/dev/null 2>&1; then
                printf '%s\t%s\t%s\t- not on wordpress.org (custom or premium), not checked\t\t\t\t\n' "$type" "$slug" "$version"
            else
                matches=$(imav_wpv_match "$file" "$version")
                if [ "$IMAV_CACHE_STALE" = '1' ]; then
                    IMAV_VULN_STALE=1
                fi
            fi
        else
            printf '%s\t%s\t%s\t- WPVulnerability API not available\t\t\t\t\n' "$type" "$slug" "$version"
        fi
        if [ $have_wf -eq 1 ]; then
            matches="$matches"$'\n'"$(imav_wf_match "$type" "$slug" "$version")"
        fi

        echo "$matches" | grep -v '^$' | sort -u -t "$IMAV_FS" -k1,1 | while IFS="$IMAV_FS" read -r title cvss fixed source link info; do
            if [ "$info" = 'true' ] && [ "$VULN_SHOW_INFORMATIONAL" != 'yes' ]; then
                continue
            fi
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$type" "$slug" "$version" "$title" "$cvss" "$fixed" "$source" "$link"
        done
    done < <(imav_vuln_inventory "$docroot")
}

# Print vulnerability findings (TSV from imav_vuln_scan on stdin) in a format
# $1 = format
imav_vuln_print() {
    case $1 in
        json)
            jq -R -s -c '
                split("\n") | map(select(length > 0) | split("\t")) |
                map({type: .[0], slug: .[1], version: .[2], title: .[3],
                     cvss: .[4], fixed_in: .[5], source: .[6], link: .[7]})' | jq '.'
            ;;
        csv)
            echo 'type,slug,version,title,cvss,fixed_in,source,link'
            jq -R -r 'split("\t") | @csv'
            ;;
        plain)
            cat
            ;;
        shell)
            {
                echo "TYPE|SLUG|VERSION|VULNERABILITY|CVSS|FIXED IN|SOURCE"
                echo "----|----|-------|-------------|----|--------|------"
                awk -F'\t' '{ t=$4; if (length(t) > 70) t=substr(t,1,67) "..."; print $1"|"$2"|"$3"|"t"|"$5"|"$6"|"$7 }'
            } | column -t -s '|'
            ;;
    esac
}
