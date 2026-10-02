#!/bin/bash
# myVesta ImunifyAV integration: shared functions.
#
# Sourced by /usr/local/vesta/bin/v-imav-* after $VESTA/func/main.sh,
# $VESTA/conf/vesta.conf and $VESTA/conf/imav.conf.
#
# All knowledge about the shape of ImunifyAV JSON output is kept in the
# functions marked "JSON SHAPE" below, so that adjustments after verification
# against a real agent are made in one place only.

IMAV_BIN='/usr/bin/imunify-antivirus'
IMAV_LOG_DIR='/var/log/myvesta-imav'
IMAV_LOG="$IMAV_LOG_DIR/imav.log"
IMAV_DATA="$VESTA/data/imav"
IMAV_SCAN_EXTENSIONS='php js htm html phtml php5 php7 php8 inc'

# Field separator for internal multi-column records read with "read".
# A tab is an IFS whitespace character and would collapse empty fields;
# the ASCII unit separator does not. In jq: join("\u001f").
IMAV_FS=$'\x1f'

# Defaults for options that may be missing from imav.conf
: "${SCAN_INTENSITY_CPU:=2}"
: "${SCAN_INTENSITY_IO:=2}"
: "${SCAN_TIMEOUT:=21600}"
: "${SCAN_PROGRESS_INTERVAL:=15}"
: "${REPORT_IN_DOMAIN_DIR:=private}"
: "${REPORT_HISTORY_DIR:=$IMAV_LOG_DIR/reports}"
: "${REPORT_KEEP_DAYS:=90}"
: "${QUARANTINE_DIR:=/srv/wp-quarantine}"
: "${BACKUP_DIR:=$IMAV_DATA/backups}"
: "${CACHE_DIR:=/var/cache/imav}"
: "${VULN_CACHE_TTL:=86400}"
: "${VULN_SHOW_INFORMATIONAL:=no}"
: "${REMEDIATE_USE_IMUNIFY_CLEANUP:=yes}"


#----------------------------------------------------------#
#                    Logging and checks                    #
#----------------------------------------------------------#

# Append a line to the project log
# $1 = level (INFO, WARN, ERROR), $2 = message
imav_log() {
    echo "$(date +'%F %T') $(basename $0) [$1] $2" >> "$IMAV_LOG"
}

# Create the working directories if missing
imav_ensure_dirs() {
    mkdir -p "$IMAV_DATA" "$IMAV_LOG_DIR" "$REPORT_HISTORY_DIR" "$BACKUP_DIR" "$CACHE_DIR"
    chmod 700 "$IMAV_LOG_DIR"
    touch "$IMAV_LOG"
}

# Check that the ImunifyAV agent is installed and answers
imav_require_agent() {
    if [ ! -x "$IMAV_BIN" ]; then
        check_result $E_DISABLED "ImunifyAV is not installed ($IMAV_BIN not found)"
    fi
    if ! command -v jq >/dev/null 2>&1; then
        check_result $E_DISABLED "jq is not installed"
    fi
    if ! $IMAV_BIN version >/dev/null 2>&1; then
        check_result $E_DISABLED "ImunifyAV agent is not responding"
    fi
}

# Validate the FORMAT parameter of list-style commands
# $1 = format
imav_format_valid() {
    case $1 in
        shell|json|plain|csv) ;;
        *) check_result $E_INVALID "invalid format :: $1 (use shell, json, plain or csv)" ;;
    esac
}

# Validate that a path is absolute and exists
# $1 = path, $2 = name for the error message
imav_path_valid() {
    if [[ "$1" != /* ]]; then
        check_result $E_INVALID "invalid $2 format :: $1 (absolute path required)"
    fi
    if [[ "$1" =~ [\'\"\`\;\$] ]]; then
        check_result $E_INVALID "invalid $2 format :: $1"
    fi
}


#----------------------------------------------------------#
#                    Domains and users                     #
#----------------------------------------------------------#

# Find the owner of a web domain. Sets $user and $USER_DATA in the caller
# (call it directly, not in a subshell).
# $1 = domain
imav_domain_owner() {
    user=$($BIN/v-search-domain-owner "$1" 'web' 2>/dev/null)
    if [ -z "$user" ]; then
        check_result $E_NOTEXIST "domain $1 doesn't exist"
    fi
    USER_DATA="$VESTA/data/users/$user"
}

# Domain name from a path under /home/USER/web/DOMAIN/..., empty otherwise
# $1 = path
imav_domain_from_path() {
    echo "$1" | sed -n 's|^/home/[^/]*/web/\([^/]*\)/.*|\1|p'
}

# User name from a path under /home/USER/..., empty otherwise
# $1 = path
imav_user_from_path() {
    echo "$1" | sed -n 's|^/home/\([^/]*\)/.*|\1|p'
}

# Document root of a web domain (public_html, or public_shtml for single SSL
# home). Sets $docroot in the caller (call it directly, not in a subshell, so
# that a failed check stops the command).
# $1 = user, $2 = domain
imav_domain_docroot() {
    local web_line
    web_line=$(grep "DOMAIN='$2'" "$VESTA/data/users/$1/web.conf" 2>/dev/null | head -n 1)
    local dir='public_html'
    if [ -n "$web_line" ]; then
        SSL_HOME=''
        parse_object_kv_list_non_eval "$web_line"
        if [ "$SSL_HOME" = 'single' ]; then
            dir='public_shtml'
        fi
    fi
    docroot="/home/$1/web/$2/$dir"
    if [ ! -d "$docroot" ]; then
        check_result $E_NOTEXIST "document root $docroot doesn't exist"
    fi
}

# Domain directory that is not web-accessible (report location)
# $1 = user, $2 = domain
imav_domain_private_dir() {
    echo "/home/$1/web/$2/private"
}


#----------------------------------------------------------#
#            ImunifyAV on-demand scan handling             #
#----------------------------------------------------------#

# JSON SHAPE (measured on 8.8.6): "on-demand list --json" returns
# {"max_count": N, "items": [{"scanid": "...", "path": "...",
#   "scan_status": "running"|"stopped", "scan_type": "on-demand",
#   "started": 1790433760.86, "created": 1790433760, "completed": 1790433770|null,
#   "error": null, "total_resources": 0, "total_malicious": 0, "duration": 10,
#   "total": 0, "resource_type": "file"}], ...}
# A finished scan has scan_status "stopped" and a non-null "completed".
# Prints the items as a JSON array.
imav_ondemand_list_json() {
    $IMAV_BIN malware on-demand list --limit 1000 --json 2>/dev/null \
        | jq -c 'if type == "array" then . else (.items // []) end' 2>/dev/null
    return ${PIPESTATUS[0]}
}

# JSON SHAPE: scan ids present in an on-demand list JSON (stdin)
imav_ondemand_list_ids() {
    jq -r '.[] | (.scanid // .scan_id // .id // empty)' 2>/dev/null
}

# JSON SHAPE: normalised state of one scan from the on-demand list JSON (stdin).
# $1 = scan id. Prints finished, failed, stopped, running or queued; nothing
# if the scan is not listed.
imav_ondemand_scan_status() {
    jq -r --arg id "$1" '
        .[] | select((.scanid // .scan_id // .id) == $id)
        | if (.error != null and .error != "") then "failed"
          elif (.scan_status // .status) == "stopped" and .completed != null then "finished"
          elif (.scan_status // .status) == "stopped" then "stopped"
          else (.scan_status // .status // "queued") end' 2>/dev/null | head -n 1
}

# JSON SHAPE (measured): "on-demand status --json" returns
# {"items": {"status": "running", "scanid": "...", "path": "...",
#   "phase": "preparing file list"|..., "progress": 0..100, "queued": 0, ...}}
# while a scan runs and {"items": {"queued": 0, "status": "stopped"}} when idle.
# Prints "phase, N%" for the scan given as $1, nothing otherwise.
imav_ondemand_progress() {
    local status
    status=$($IMAV_BIN malware on-demand status --json 2>/dev/null)
    [ -z "$status" ] && return
    echo "$status" | jq -r --arg id "$1" '
        .items | select(type == "object" and (.scanid // "") == $id)
        | "\(.phase // "running"), \(.progress // 0)%"' 2>/dev/null | head -n 1
}

# Start an on-demand scan. Sets $scan_id in the caller (call it directly, not
# in a subshell, so that a failed start stops the command).
# $1 = path (may be a glob), remaining arguments are passed to ImunifyAV
imav_start_scan() {
    local path="$1"
    shift
    local before after new_ids output try
    scan_id=''

    before=$(imav_ondemand_list_json | imav_ondemand_list_ids | sort -u)

    output=$($IMAV_BIN malware on-demand start --path "$path" "$@" --json 2>&1)
    if [ $? -ne 0 ]; then
        imav_log ERROR "on-demand start failed for $path: $output"
        check_result $E_UPDATE "ImunifyAV could not start the scan: $output"
    fi

    # JSON SHAPE (measured): "on-demand start --json" returns {"items": null, ...},
    # so the id comes from the list; kept in case a future version returns it.
    scan_id=$(echo "$output" | jq -r '.items.scanid // .scanid // .scan_id // empty' 2>/dev/null)

    # The new entry in the on-demand list (appears within a second or two)
    try=0
    while [ -z "$scan_id" ] && [ $try -lt 15 ]; do
        sleep 1
        after=$(imav_ondemand_list_json | imav_ondemand_list_ids | sort -u)
        new_ids=$(comm -13 <(echo "$before") <(echo "$after"))
        if [ "$(echo "$new_ids" | grep -c .)" -ge 1 ]; then
            scan_id=$(echo "$new_ids" | tail -n 1)
        fi
        ((try++))
    done

    if [ -z "$scan_id" ]; then
        imav_log ERROR "scan started for $path but no scan id could be determined"
        check_result $E_UPDATE "scan started but the scan id could not be determined"
    fi

    imav_log INFO "scan $scan_id started for $path"
}

# Queue several paths (files or directories) for scanning.
# Prints nothing; the resulting scan ids are collected by the caller from the list.
# $1.. = paths, plus IMAV_QUEUE_ARGS for extra options
imav_queue_paths() {
    $IMAV_BIN malware on-demand queue put "$@" $IMAV_QUEUE_ARGS >/dev/null 2>&1
    return $?
}

# Wait until a scan is finished. Prints progress to stderr.
# $1 = scan id, $2 = timeout in seconds (0 = unlimited, default $SCAN_TIMEOUT)
imav_wait_scan() {
    local scan_id="$1"
    local timeout="${2-$SCAN_TIMEOUT}"
    local started=$(date +%s)
    local state progress elapsed last_line=''

    while true; do
        state=$(imav_ondemand_list_json | imav_ondemand_scan_status "$scan_id")
        case "$state" in
            finished)
                imav_log INFO "scan $scan_id finished"
                [ -n "$last_line" ] && echo >&2
                return 0
                ;;
            failed)
                [ -n "$last_line" ] && echo >&2
                imav_log ERROR "scan $scan_id failed: $(imav_ondemand_list_json | jq -r --arg id "$scan_id" '.[] | select(.scanid == $id) | .error // ""')"
                check_result $E_UPDATE "scan $scan_id failed (see imunify-antivirus malware on-demand list)"
                ;;
            stopped)
                [ -n "$last_line" ] && echo >&2
                imav_log ERROR "scan $scan_id was stopped before completion"
                check_result $E_UPDATE "scan $scan_id was stopped before completion"
                ;;
        esac

        elapsed=$(( $(date +%s) - started ))
        if [ "$timeout" -gt 0 ] && [ "$elapsed" -gt "$timeout" ]; then
            [ -n "$last_line" ] && echo >&2
            imav_log ERROR "scan $scan_id timed out after ${elapsed}s (status: ${state:-unknown})"
            check_result $E_UPDATE "scan $scan_id did not finish within ${timeout}s"
        fi

        progress=$(imav_ondemand_progress "$scan_id")
        last_line="scan $scan_id: ${state:-queued}${progress:+ ($progress)}, ${elapsed}s elapsed"
        if [ -t 2 ]; then
            printf '\r%-70s' "$last_line" >&2
        fi
        sleep "$SCAN_PROGRESS_INTERVAL"
    done
}

# JSON SHAPE: paginated "malware malicious list" as one JSON array of objects
# with the fields file, type (signature), status, size, hash, scan_id,
# username, created.
# $@ = extra arguments for the list command (--by-scan-id ID, --user USER, ...)
imav_malicious_list() {
    local offset=0 limit=1000 count pages page_file
    # Pages are merged through files: a large list passed as a command-line
    # argument fails with "Argument list too long"
    pages=$(mktemp -d)

    while true; do
        page_file="$pages/$(printf '%08d' "$offset").json"
        if ! $IMAV_BIN malware malicious list "$@" --limit $limit --offset $offset --json 2>/dev/null \
            | jq -c 'if type == "array" then . else (.items // []) end' > "$page_file" 2>/dev/null \
            || ! [ -s "$page_file" ]; then
            rm -rf "$pages"
            echo 'ERROR'
            return 1
        fi
        count=$(jq 'length' "$page_file")
        if [ "$count" -lt "$limit" ]; then
            break
        fi
        offset=$((offset + limit))
    done
    jq -c -s 'add // []' "$pages"/*.json
    rm -rf "$pages"
}

# Stop the command when a findings JSON is not a valid array (for example
# after a failed listing). Call it directly, not in a subshell.
# $1 = results JSON
imav_results_check() {
    if ! echo "$1" | jq -e 'type == "array"' >/dev/null 2>&1; then
        imav_log ERROR "could not read the ImunifyAV findings list"
        check_result $E_UPDATE "could not read the ImunifyAV findings list (see $IMAV_LOG)"
    fi
}

# Concatenate several findings JSON files into one array
# $@ = files
imav_results_concat() {
    jq -c -s 'add // []' "$@"
}

# Findings of one scan
# $1 = scan id
imav_scan_results() {
    imav_malicious_list --by-scan-id "$1"
}

# All current findings of a user
# $1 = user
imav_user_results() {
    imav_malicious_list --user "$1"
}

# All current findings on the server
imav_all_results() {
    imav_malicious_list
}

# Keep only findings whose file is under a path
# $1 = results JSON, $2 = path prefix
imav_results_filter_path() {
    echo "$1" | jq -c --arg p "$2/" '[.[] | select((.file // "") | startswith($p))]'
}

# Keep only findings that are still infected (not cleaned, not ignored)
# $1 = results JSON
imav_results_filter_active() {
    echo "$1" | jq -c '[.[] | select(((.status // "found") | test("cleanup_done|cleanup_removed|ignored|restored|deleted")) | not)]'
}

# Number of findings
# $1 = results JSON
imav_results_count() {
    echo "$1" | jq 'length'
}

# File paths of findings, one per line
# $1 = results JSON
imav_results_files() {
    echo "$1" | jq -r '.[] | .file // empty'
}


#----------------------------------------------------------#
#                    Output and reports                    #
#----------------------------------------------------------#

# CSV report (column order compatible with Wordfence CLI reports, so that
# existing consumers of such files keep working)
# $1 = results JSON
imav_results_to_csv() {
    echo 'filename,signature_id,signature_name,status,size,hash,scan_id,detected_at'
    echo "$1" | jq -r '.[] | [
        (.file // ""), (.type // ""), (.type // ""), (.status // ""),
        ((.size // "") | tostring), (.hash // ""), (.scanid // .scan_id // ""),
        ((.created // .created_at // "") | tostring)
    ] | @csv'
}

# Human readable table
# $1 = results JSON
imav_results_to_shell() {
    {
        echo "FILE|SIGNATURE|STATUS|SIZE"
        echo "----|---------|------|----"
        echo "$1" | jq -r '.[] | "\(.file // "")|\(.type // "")|\(.status // "")|\(.size // "")"'
    } | column -t -s '|'
}

# Tab separated, no header
# $1 = results JSON
imav_results_to_plain() {
    echo "$1" | jq -r '.[] | [(.file // ""), (.type // ""), (.status // ""), ((.size // "") | tostring), (.hash // "")] | @tsv'
}

# Print findings in the requested format
# $1 = format, $2 = results JSON
imav_print_results() {
    case $1 in
        json)  echo "$2" | jq '.' ;;
        plain) imav_results_to_plain "$2" ;;
        csv)   imav_results_to_csv "$2" ;;
        shell) imav_results_to_shell "$2" ;;
    esac
}

# Write a report for a domain: the latest copy in the domain directory (owned
# by the user) and a timestamped copy in the history directory.
# $1 = user, $2 = domain, $3 = report name (imav-scan, imav-vuln, ...),
# $4 = content
imav_write_report() {
    local user="$1" domain="$2" name="$3" content="$4"
    local stamp=$(date +%Y%m%d-%H%M%S)
    local history="$REPORT_HISTORY_DIR/$domain"
    local target=''

    mkdir -p "$history"
    echo "$content" > "$history/$name-$stamp.csv"
    find "$history" -type f -name "$name-*.csv" -mtime +"$REPORT_KEEP_DAYS" -delete 2>/dev/null

    case $REPORT_IN_DOMAIN_DIR in
        private)     target="$(imav_domain_private_dir "$user" "$domain")/$name.csv" ;;
        public_html) target="/home/$user/web/$domain/public_html/$name.csv" ;;
        *)           target='' ;;
    esac
    if [ -n "$target" ]; then
        mkdir -p "$(dirname "$target")"
        echo "$content" > "$target"
        chown "$user:$user" "$target"
        chmod 640 "$target"
        echo "$target"
    else
        echo "$history/$name-$stamp.csv"
    fi
}


#----------------------------------------------------------#
#                    License and settings                  #
#----------------------------------------------------------#

# JSON SHAPE: returns 0 when an ImunifyAV+ (or Imunify360) license is active.
# Measured: rstatus --json returns {"status": true, "license_type": "imunifyAV",
# "id": "IMUNIFYAV", ...} for the free edition; only license_type is checked,
# because the upgrade URLs in the same document contain "ImunifyAvPlus".
imav_is_av_plus() {
    local status
    status=$($IMAV_BIN rstatus --json 2>/dev/null)
    [ -z "$status" ] && return 1
    echo "$status" | jq -e '
        (.status == true)
        and ((.license_type // .license.license_type // "") | test("plus|360"; "i"))' >/dev/null 2>&1
}

# Apply one ImunifyAV configuration change
# $1 = JSON for "config update"
imav_config_update() {
    $IMAV_BIN config update "$1" >/dev/null 2>&1
}


#----------------------------------------------------------#
#                    WordPress helpers                     #
#----------------------------------------------------------#

# Is the directory a WordPress document root. WordPress also accepts
# wp-config.php one level above the document root.
# $1 = docroot
imav_is_wordpress() {
    # A damaged installation (core files deleted by an attacker or a failed
    # cleanup) is still a WordPress site: wp-config.php with wp-content or
    # wp-includes is enough. The core version may then be unknown.
    [ -n "$(imav_wp_config "$1")" ] || return 1
    [ -d "$1/wp-content" ] || [ -d "$1/wp-includes" ]
}

# Path of the wp-config.php of a document root (docroot or its parent), empty if none
# $1 = docroot
imav_wp_config() {
    if [ -f "$1/wp-config.php" ]; then
        echo "$1/wp-config.php"
    elif [ -f "$(dirname "$1")/wp-config.php" ]; then
        echo "$(dirname "$1")/wp-config.php"
    fi
}

# WordPress core version of a document root
# $1 = docroot
imav_wp_version() {
    grep -m1 "^\$wp_version" "$1/wp-includes/version.php" 2>/dev/null \
        | sed -e "s/.*= *['\"]//" -e "s/['\"].*//"
}

# Value of a WordPress plugin or theme header field
# $1 = file, $2 = field (Version, Plugin Name, Theme Name)
imav_wp_header() {
    head -c 8192 "$1" 2>/dev/null \
        | tr -d '\r' \
        | grep -m1 -i "^[[:space:]*#/]*$2:" \
        | sed -e "s/^[[:space:]*#\/]*$2:[[:space:]]*//I" -e 's/[[:space:]]*$//'
}

# Main file of a plugin directory (the one with a "Plugin Name:" header)
# $1 = plugin directory
imav_wp_plugin_main_file() {
    local f
    for f in "$1"/*.php; do
        [ -f "$f" ] || continue
        if head -c 8192 "$f" | grep -qi 'Plugin Name:'; then
            echo "$f"
            return 0
        fi
    done
    return 1
}

# Version of an installed plugin
# $1 = docroot, $2 = slug
imav_wp_plugin_version() {
    local main
    if [ -f "$1/wp-content/plugins/$2.php" ]; then
        main="$1/wp-content/plugins/$2.php"
    else
        main=$(imav_wp_plugin_main_file "$1/wp-content/plugins/$2") || return 1
    fi
    imav_wp_header "$main" 'Version'
}

# Is the file an index.php guard: the small index.php that WordPress, plugins
# and themes put into directories to stop listings. Only comments, exit/die,
# a 404 header and the ABSPATH check are allowed; any other statement means
# the file does something else.
# $1 = file
imav_is_guard_index() {
    [ "$(basename "$1")" = 'index.php' ] || return 1
    # long license comments are common in guard files, so the size is judged
    # after comments are removed: at most 4 KB raw, at most 6 real lines
    [ "$(wc -c < "$1")" -lt 4096 ] || return 1
    # no PHP open tag at all: plain text placeholder, nothing can execute
    grep -q '<?' "$1" || return 0
    local rest
    rest=$(tr -d '\r' < "$1" \
        | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' \
        | grep -v -E '^$|^<\?php$|^\?>$|^(//|#).*|^/\*.*\*/$|^/\*|^\*' \
        | grep -v -E "^(exit|die)( *\( *\))? *;?$" \
        | grep -v -E "^header *\( *(\\\$_SERVER\[ *['\"]SERVER_PROTOCOL['\"] *\] *\. *)?['\"][^'\"]*404[^'\"]*['\"] *\) *;$" \
        | grep -v -E "^if *\( *! *defined *\( *['\"]ABSPATH['\"] *\) *\) *\{? *(exit|die)( *\( *\))? *; *\}? *$" \
        | grep -v -E "^defined *\( *['\"]ABSPATH['\"] *\) *(\|\||or) *(exit|die)( *\( *\))? *;$")
    [ -z "$rest" ] && [ "$(tr -d '\r' < "$1" | grep -c -v -E '^[[:space:]]*$|^[[:space:]]*(//|#|/\*|\*)')" -le 6 ]
}

# Version of an installed theme
# $1 = docroot, $2 = slug
imav_wp_theme_version() {
    imav_wp_header "$1/wp-content/themes/$2/style.css" 'Version'
}


#----------------------------------------------------------#
#            Version comparison (PHP semantics)            #
#----------------------------------------------------------#

# Canonical form as PHP version_compare() builds it: separators become dots,
# a dot is inserted between digit/letter transitions, everything lowercase.
# Pure bash (no subprocess), because the vulnerability matching calls it
# thousands of times for WordPress core.
# $1 = version
imav_version_canon() {
    _imav_version_canon_var "$1"
    echo "$IMAV_CANON"
}

# Same as imav_version_canon, result in $IMAV_CANON (no subshell)
# $1 = version
_imav_version_canon_var() {
    local v="$1" out='' i c prev='' idx
    local upper='ABCDEFGHIJKLMNOPQRSTUVWXYZ' lower='abcdefghijklmnopqrstuvwxyz'
    v=${v//[-_+]/.}
    for ((i = 0; i < ${#v}; i++)); do
        c=${v:i:1}
        if [[ "$c" == [A-Z] ]]; then
            idx=${upper%%$c*}
            c=${lower:${#idx}:1}
        fi
        if [ -n "$prev" ]; then
            if [[ "$prev" == [0-9] && "$c" == [a-z] ]] || [[ "$prev" == [a-z] && "$c" == [0-9] ]]; then
                out+='.'
            fi
        fi
        out+=$c
        prev=$c
    done
    while [[ "$out" == *..* ]]; do out=${out//../.}; done
    out=${out#.}
    out=${out%.}
    IMAV_CANON=$out
}

# Order of special version forms, as in PHP
# $1 = form
imav_version_special() {
    case $1 in
        dev)      echo 0 ;;
        alpha|a)  echo 1 ;;
        beta|b)   echo 2 ;;
        rc|c)     echo 3 ;;
        '#')      echo 4 ;;
        pl|p)     echo 5 ;;
        *)        echo -1 ;;
    esac
}

# Compare two versions. Prints -1, 0 or 1.
# $1 = version A, $2 = version B
imav_version_cmp() {
    _imav_version_cmp_var "$1" "$2"
    echo "$IMAV_CMP"
}

# Order of a special version form, result in $IMAV_SPECIAL (no subshell)
_imav_version_special_var() {
    case $1 in
        dev)      IMAV_SPECIAL=0 ;;
        alpha|a)  IMAV_SPECIAL=1 ;;
        beta|b)   IMAV_SPECIAL=2 ;;
        rc|c)     IMAV_SPECIAL=3 ;;
        '#')      IMAV_SPECIAL=4 ;;
        pl|p)     IMAV_SPECIAL=5 ;;
        *)        IMAV_SPECIAL=-1 ;;
    esac
}

# Same as imav_version_cmp, result in $IMAV_CMP. No subshells at all, so
# that thousands of comparisons (Wordfence core records) stay fast.
# $1 = version A, $2 = version B
_imav_version_cmp_var() {
    local a b x y i n sx sy
    _imav_version_canon_var "$1"; a=$IMAV_CANON
    _imav_version_canon_var "$2"; b=$IMAV_CANON
    local -a pa pb
    IFS='.' read -r -a pa <<< "$a"
    IFS='.' read -r -a pb <<< "$b"
    n=${#pa[@]}
    [ ${#pb[@]} -gt $n ] && n=${#pb[@]}
    IMAV_CMP=0

    for ((i = 0; i < n; i++)); do
        x="${pa[$i]-}"
        y="${pb[$i]-}"
        if [ -z "$x" ] && [ -z "$y" ]; then
            break
        fi
        if [ -z "$x" ]; then
            if [[ "$y" =~ ^[0-9]+$ ]]; then IMAV_CMP=-1; return; fi
            x='#'
        fi
        if [ -z "$y" ]; then
            if [[ "$x" =~ ^[0-9]+$ ]]; then IMAV_CMP=1; return; fi
            y='#'
        fi
        if [[ "$x" =~ ^[0-9]+$ ]] && [[ "$y" =~ ^[0-9]+$ ]]; then
            if [ $((10#$x)) -lt $((10#$y)) ]; then IMAV_CMP=-1; return; fi
            if [ $((10#$x)) -gt $((10#$y)) ]; then IMAV_CMP=1; return; fi
            continue
        fi
        [[ "$x" =~ ^[0-9]+$ ]] && x='#'
        [[ "$y" =~ ^[0-9]+$ ]] && y='#'
        _imav_version_special_var "$x"; sx=$IMAV_SPECIAL
        _imav_version_special_var "$y"; sy=$IMAV_SPECIAL
        if [ "$sx" -lt "$sy" ]; then IMAV_CMP=-1; return; fi
        if [ "$sx" -gt "$sy" ]; then IMAV_CMP=1; return; fi
    done
}

# Test a version relation. Returns 0 when true.
# $1 = version A, $2 = operator (lt, le, eq, ne, gt, ge), $3 = version B
imav_version_compare() {
    local c
    _imav_version_cmp_var "$1" "$3"
    c=$IMAV_CMP
    case $2 in
        lt) [ "$c" -eq -1 ] ;;
        le) [ "$c" -le 0 ] ;;
        eq) [ "$c" -eq 0 ] ;;
        ne) [ "$c" -ne 0 ] ;;
        gt) [ "$c" -eq 1 ] ;;
        ge) [ "$c" -ge 0 ] ;;
        *)  return 1 ;;
    esac
}


#----------------------------------------------------------#
#                    Downloads and cache                   #
#----------------------------------------------------------#

# Download a URL to a file unless a fresh cached copy exists.
# Returns 0 when the file is usable (fresh or stale), 1 when nothing is available.
# Sets IMAV_CACHE_STALE=1 when a stale copy had to be used.
# $1 = url, $2 = file, $3 = max age in seconds, $4.. = extra curl arguments
imav_cached_download() {
    local url="$1" file="$2" ttl="$3"
    shift 3
    local error code
    IMAV_CACHE_STALE=0
    IMAV_DOWNLOAD_ERROR=''
    IMAV_DOWNLOAD_CODE=''
    mkdir -p "$(dirname "$file")"
    if [ -f "$file" ] && [ -s "$file" ]; then
        local age=$(( $(date +%s) - $(stat -c %Y "$file") ))
        if [ "$age" -lt "$ttl" ]; then
            return 0
        fi
    fi
    if [ -f "$file.404" ] && [ $(( $(date +%s) - $(stat -c %Y "$file.404") )) -lt "$ttl" ]; then
        IMAV_DOWNLOAD_CODE='404'
        IMAV_DOWNLOAD_ERROR='not found (HTTP 404, remembered)'
        return 1
    fi
    error=$(curl -sS -f -m 60 -L "$@" -o "$file.tmp" -w '\n%{http_code}' "$url" 2>&1)
    if [ $? -eq 0 ]; then
        mv -f "$file.tmp" "$file"
        return 0
    fi
    code=$(echo "$error" | tail -n 1 | grep -o '^[0-9]\{3\}$')
    IMAV_DOWNLOAD_ERROR=$(echo "$error" | head -n 1 | sed 's/^curl: ([0-9]*) //')
    [ "$code" = '429' ] && IMAV_DOWNLOAD_ERROR='rate limited by the server (HTTP 429), try again later'
    [ "$code" = '401' ] && IMAV_DOWNLOAD_ERROR='not authorized (HTTP 401), the API key was rejected'
    IMAV_DOWNLOAD_CODE=$code
    # A 404 is an answer (the item does not exist), not a failure: remember it
    # for the TTL instead of asking again and do not log it as a warning.
    if [ "$code" = '404' ]; then
        touch "$file.404"
    else
        imav_log WARN "download of $url failed: $IMAV_DOWNLOAD_ERROR"
    fi
    rm -f "$file.tmp"
    if [ -f "$file" ] && [ -s "$file" ]; then
        IMAV_CACHE_STALE=1
        return 0
    fi
    return 1
}
