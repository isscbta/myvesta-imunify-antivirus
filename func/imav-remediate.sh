#!/bin/bash
# myVesta ImunifyAV integration: remediation engine.
#
# For every infected file of a WordPress site: if the file belongs to WordPress
# core, a wordpress.org plugin or a wordpress.org theme, the original file of
# the installed version is downloaded (cached) and put in place of the infected
# one. Everything else is moved to quarantine. Nothing is ever deleted, and a
# tar.gz of the affected files is made before any change.
#
# Requires func/imav.sh.

WP_CORE_URL='https://wordpress.org/wordpress-VERSION.zip'
WP_PLUGIN_URL='https://downloads.wordpress.org/plugin/SLUG.VERSION.zip'
WP_THEME_URL='https://downloads.wordpress.org/theme/SLUG.VERSION.zip'
WP_ARCHIVE_TTL=315360000


#----------------------------------------------------------#
#                    Classification                        #
#----------------------------------------------------------#

# Classify a file by its position inside the document root.
# Prints CLASS, SLUG and RELATIVE_PATH separated by $IMAV_FS, where CLASS is
# core, plugin, theme or other, and SLUG is set for plugin and theme.
# $1 = docroot, $2 = absolute file path
imav_remediate_classify() {
    local rel="${2#$1/}"
    local class='other' slug=''
    # Note: "*" in a case pattern also matches "/", so patterns are ordered
    # from the most specific to the least specific and root files are matched
    # only after every path with a directory has been handled.
    case "$rel" in
        wp-admin/*|wp-includes/*)
            class='core' ;;
        wp-content/index.php|wp-content/plugins/index.php|wp-content/themes/index.php)
            class='core' ;;
        wp-content/plugins/*/*)
            class='plugin'
            slug=${rel#wp-content/plugins/}; slug=${slug%%/*} ;;
        wp-content/themes/*/*)
            class='theme'
            slug=${rel#wp-content/themes/}; slug=${slug%%/*} ;;
        wp-content/plugins/hello.php)
            # Hello Dolly: a single-file plugin, on wordpress.org as hello-dolly
            # and also shipped with core (the core copy is the fallback)
            class='plugin'
            slug='hello-dolly' ;;
        wp-content/plugins/*.php)
            # other single-file plugins: no wordpress.org slug can be derived
            class='other' ;;
        */*)
            class='other' ;;
        wp-*.php|index.php|xmlrpc.php|license.txt|readme.html)
            class='core' ;;
    esac
    printf '%s\x1f%s\x1f%s\n' "$class" "$slug" "$rel"
}


#----------------------------------------------------------#
#                    Original files                        #
#----------------------------------------------------------#

# Download and unpack an archive into the cache; prints the directory.
# $1 = url, $2 = cache subdirectory name
imav_remediate_archive() {
    local url="$1" dir="$CACHE_DIR/wp/$2" zip="$CACHE_DIR/wp/$2.zip"
    if [ -d "$dir" ] && [ -f "$dir/.complete" ]; then
        echo "$dir"
        return 0
    fi
    imav_cached_download "$url" "$zip" "$WP_ARCHIVE_TTL" || return 1
    rm -rf "$dir"
    mkdir -p "$dir"
    if ! unzip -q -o "$zip" -d "$dir" 2>/dev/null; then
        rm -rf "$dir" "$zip"
        return 1
    fi
    touch "$dir/.complete"
    echo "$dir"
}

# Path of the original copy of a file, if it exists in the official archive.
# Prints ORIGINAL_PATH and SOURCE (core-VERSION, plugin-SLUG-VERSION, ...)
# separated by $IMAV_FS.
# Returns 1 when no original is available.
# $1 = docroot, $2 = class, $3 = slug, $4 = relative path
imav_remediate_original() {
    local docroot="$1" class="$2" slug="$3" rel="$4"
    local version dir candidate url

    case $class in
        plugin)
            if [ "$slug" = 'hello-dolly' ]; then
                version=$(imav_wp_header "$docroot/wp-content/plugins/hello.php" 'Version')
            else
                version=$(imav_wp_plugin_version "$docroot" "$slug")
            fi
            if [ -n "$version" ]; then
                url="${WP_PLUGIN_URL/SLUG/$slug}"
                dir=$(imav_remediate_archive "${url/VERSION/$version}" "plugin-$slug-$version")
                if [ -n "$dir" ]; then
                    if [ "$slug" = 'hello-dolly' ]; then
                        candidate="$dir/hello-dolly/hello.php"
                    else
                        candidate="$dir/${rel#wp-content/plugins/}"
                    fi
                    if [ -f "$candidate" ]; then
                        printf '%s\x1fplugin-%s-%s\n' "$candidate" "$slug" "$version"
                        return 0
                    fi
                fi
            fi
            ;;
        theme)
            version=$(imav_wp_theme_version "$docroot" "$slug")
            if [ -n "$version" ]; then
                url="${WP_THEME_URL/SLUG/$slug}"
                dir=$(imav_remediate_archive "${url/VERSION/$version}" "theme-$slug-$version")
                if [ -n "$dir" ]; then
                    candidate="$dir/${rel#wp-content/themes/}"
                    if [ -f "$candidate" ]; then
                        printf '%s\x1ftheme-%s-%s\n' "$candidate" "$slug" "$version"
                        return 0
                    fi
                fi
            fi
            ;;
    esac

    # Core archive: covers core files and the plugins and themes shipped with it
    version=$(imav_wp_version "$docroot")
    if [ -n "$version" ]; then
        dir=$(imav_remediate_archive "${WP_CORE_URL/VERSION/$version}" "core-$version")
        if [ -n "$dir" ] && [ -f "$dir/wordpress/$rel" ]; then
            printf '%s\x1fcore-%s\n' "$dir/wordpress/$rel" "$version"
            return 0
        fi
    fi
    return 1
}


#----------------------------------------------------------#
#                    Actions                               #
#----------------------------------------------------------#

# Create a tar.gz of the listed files before changing anything; prints the archive
# $1 = domain, $2 = file with one absolute path per line
imav_remediate_backup() {
    local dir="$BACKUP_DIR/$1" stamp=$(date +%Y%m%d-%H%M%S)
    mkdir -p "$dir"
    chmod 700 "$dir"
    if tar -czf "$dir/$stamp.tar.gz" -C / --files-from <(sed 's|^/||' "$2") 2>/dev/null; then
        echo "$dir/$stamp.tar.gz"
        return 0
    fi
    rm -f "$dir/$stamp.tar.gz"
    return 1
}

# Move a file to quarantine keeping its relative path; prints the new location
# $1 = user, $2 = domain, $3 = docroot, $4 = absolute file path
imav_remediate_quarantine() {
    local rel="${4#$3/}"
    local target="$QUARANTINE_DIR/$2/$rel"
    mkdir -p "$(dirname "$target")"
    mv -f "$4" "$target" || return 1
    find "$QUARANTINE_DIR/$2" -type d -exec chown "$1:$1" {} \; 2>/dev/null
    echo "$target"
}

# Replace a file with its original, keeping owner and mode
# $1 = infected file, $2 = original file
imav_remediate_replace() {
    local owner mode
    owner=$(stat -c '%U:%G' "$1")
    mode=$(stat -c '%a' "$1")
    cp -f "$2" "$1.imav-tmp" || return 1
    chown "$owner" "$1.imav-tmp"
    chmod "$mode" "$1.imav-tmp"
    mv -f "$1.imav-tmp" "$1"
}

# Try the built-in ImunifyAV+ cleanup for one finding
# $1 = finding id
imav_remediate_imunify_cleanup() {
    $IMAV_BIN malware malicious cleanup --ids "$1" >/dev/null 2>&1
}

# Remediate one file. Prints a CSV row: file,action,source,result
# $1 = user, $2 = domain, $3 = docroot, $4 = mode (auto, dry-run, quarantine),
# $5 = absolute file path, $6 = finding id (may be empty)
imav_remediate_file() {
    local user="$1" domain="$2" docroot="$3" mode="$4" file="$5" id="$6"
    local class slug rel original source target

    if [ ! -f "$file" ]; then
        printf '%s,skip,,file no longer exists\n' "$file"
        return 0
    fi

    IFS="$IMAV_FS" read -r class slug rel < <(imav_remediate_classify "$docroot" "$file")

    if [ "$mode" != 'quarantine' ] && [ "$class" != 'other' ]; then
        if IFS="$IMAV_FS" read -r original source < <(imav_remediate_original "$docroot" "$class" "$slug" "$rel"); then
            if cmp -s "$file" "$original"; then
                printf '%s,skip,%s,identical to the original file (possible false positive)\n' "$file" "$source"
                return 0
            fi
            if [ "$mode" = 'dry-run' ]; then
                printf '%s,replace,%s,would be replaced with the original\n' "$file" "$source"
                return 0
            fi
            if imav_remediate_replace "$file" "$original"; then
                imav_log INFO "replaced $file from $source"
                printf '%s,replace,%s,replaced with the original\n' "$file" "$source"
            else
                imav_log ERROR "failed to replace $file from $source"
                printf '%s,replace,%s,failed\n' "$file" "$source"
            fi
            return 0
        fi
        if [ "$class" != 'other' ]; then
            source="no original for $class${slug:+ $slug}"
        fi
    fi

    if [ "$mode" = 'dry-run' ]; then
        printf '%s,quarantine,%s,would be moved to %s\n' "$file" "$source" "$QUARANTINE_DIR/$domain/$rel"
        return 0
    fi
    if target=$(imav_remediate_quarantine "$user" "$domain" "$docroot" "$file"); then
        imav_log INFO "quarantined $file to $target"
        printf '%s,quarantine,%s,moved to %s\n' "$file" "$source" "$target"
    else
        imav_log ERROR "failed to quarantine $file"
        printf '%s,quarantine,%s,failed\n' "$file" "$source"
    fi
}

# Remediate all findings of a domain. Reads findings JSON (imav.sh shape),
# prints CSV with header. Uses the ImunifyAV+ cleanup first when available.
# $1 = user, $2 = domain, $3 = docroot, $4 = mode, $5 = findings JSON
imav_remediate_run() {
    local user="$1" domain="$2" docroot="$3" mode="$4" results="$5"
    local list file id av_plus=0 backup

    echo 'file,action,source,result'

    list=$(mktemp)
    imav_results_files "$results" | grep -v '^$' > "$list"
    if [ ! -s "$list" ]; then
        rm -f "$list"
        return 0
    fi

    if [ "$mode" != 'dry-run' ]; then
        if backup=$(imav_remediate_backup "$domain" "$list"); then
            imav_log INFO "backup of $(wc -l < "$list") files for $domain in $backup"
        else
            rm -f "$list"
            check_result $E_DISK "could not create the backup archive for $domain"
        fi
    fi

    if [ "$mode" = 'auto' ] && [ "$REMEDIATE_USE_IMUNIFY_CLEANUP" = 'yes' ] && imav_is_av_plus; then
        av_plus=1
    fi

    while IFS="$IMAV_FS" read -r file id; do
        [ -z "$file" ] && continue
        if [ $av_plus -eq 1 ] && [ -n "$id" ] && imav_remediate_imunify_cleanup "$id"; then
            imav_log INFO "cleaned $file with ImunifyAV+ cleanup"
            printf '%s,cleanup,imunify,cleaned by ImunifyAV+\n' "$file"
            continue
        fi
        imav_remediate_file "$user" "$domain" "$docroot" "$mode" "$file" "$id"
    done < <(echo "$results" | jq -r '.[] | [(.file // ""), ((.id // "") | tostring)] | join("\u001f")')

    rm -f "$list"
}
