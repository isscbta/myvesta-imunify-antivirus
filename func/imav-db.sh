#!/bin/bash
# myVesta ImunifyAV integration: WordPress database scan engine.
#
# ImunifyAV has no database scanner (the Malware Database Scanner exists only
# in Imunify360), so suspicious rows of the WordPress tables are exported to
# files that the ImunifyAV file scanner checks, and a set of heuristics looks
# for typical injections that signatures do not cover. The database is never
# modified.
#
# Requires func/imav.sh.

# Tables and text columns exported for the file scanner: TABLE:ID_COLUMN:COLUMN,COLUMN
IMAV_DB_TABLES='posts:ID:post_content,post_excerpt postmeta:meta_id:meta_value options:option_id:option_value comments:comment_ID:comment_content commentmeta:meta_id:meta_value usermeta:umeta_id:meta_value termmeta:meta_id:meta_value'
# Values shorter than this cannot carry a payload
IMAV_DB_MIN_LEN=32
# ImunifyAV applies signatures only to files up to max_signature_size_to_scan (1 MB)
IMAV_DB_MAX_VALUE=1048576
IMAV_DB_ADMIN_DAYS=30


#----------------------------------------------------------#
#                    Connection                            #
#----------------------------------------------------------#

# Load the database name and table prefix of a domain (from wp-config.php via
# v-get-database-credentials-of-domain) and the MySQL root credentials of the
# matching host from $VESTA/conf/mysql.conf, the same way myVesta's db.sh does.
# Sets IMAV_DB_NAME, IMAV_DB_PREFIX, IMAV_DB_HOST, IMAV_DB_USER, IMAV_DB_PASS.
# Returns 1 when the domain is not a WordPress site with readable credentials.
# $1 = domain
imav_db_credentials() {
    local output host_str config
    output=$($BIN/v-get-database-credentials-of-domain "$1" 2>/dev/null)
    CMS_TYPE=''; DATABASE_NAME=''; DATABASE_USERNAME=''; DATABASE_PASSWORD=''; DATABASE_HOSTNAME=''; CONFIG_FILE_FULL_PATH=''
    [ -n "$output" ] && parse_object_kv_list_non_eval "$output"
    if [ "$CMS_TYPE" != 'wordpress' ] || [ -z "$DATABASE_NAME" ]; then
        # myVesta looks for wp-config.php in the document root only; WordPress
        # also accepts it one level above, so read it from there ourselves
        config=$(imav_wp_config "$docroot")
        [ -n "$config" ] || return 1
        DATABASE_NAME=$(imav_wp_config_value "$config" 'DB_NAME')
        DATABASE_USERNAME=$(imav_wp_config_value "$config" 'DB_USER')
        DATABASE_PASSWORD=$(imav_wp_config_value "$config" 'DB_PASSWORD')
        DATABASE_HOSTNAME=$(imav_wp_config_value "$config" 'DB_HOST')
        CONFIG_FILE_FULL_PATH=$config
        [ -n "$DATABASE_NAME" ] || return 1
    fi

    IMAV_DB_NAME=$DATABASE_NAME
    IMAV_DB_PREFIX=$(grep -m1 '^\$table_prefix' "$CONFIG_FILE_FULL_PATH" 2>/dev/null \
        | sed -e "s/.*= *['\"]//" -e "s/['\"].*//")
    [ -n "$IMAV_DB_PREFIX" ] || IMAV_DB_PREFIX='wp_'
    IMAV_DB_HOST=${DATABASE_HOSTNAME:-localhost}
    case $IMAV_DB_HOST in
        127.0.0.1|'') IMAV_DB_HOST='localhost' ;;
        *:*)          IMAV_DB_HOST=${IMAV_DB_HOST%%:*} ;;
    esac

    # Root credentials from mysql.conf (one line per host), site credentials as fallback
    IMAV_DB_USER=''
    IMAV_DB_PASS=''
    if [ -f "$VESTA/conf/mysql.conf" ]; then
        host_str=$(grep "HOST='$IMAV_DB_HOST'" "$VESTA/conf/mysql.conf" | head -n 1)
        [ -z "$host_str" ] && host_str=$(head -n 1 "$VESTA/conf/mysql.conf")
        if [ -n "$host_str" ]; then
            USER_SAVE=$user
            parse_object_kv_list_non_eval "$host_str"
            IMAV_DB_USER=$USER
            IMAV_DB_PASS=$PASSWORD
            user=$USER_SAVE
        fi
    fi
    if [ -z "$IMAV_DB_USER" ]; then
        IMAV_DB_USER=$DATABASE_USERNAME
        IMAV_DB_PASS=$DATABASE_PASSWORD
    fi
    [ -n "$IMAV_DB_USER" ] || return 1
    return 0
}

# Value of a define('KEY', 'value') in wp-config.php
# $1 = wp-config.php, $2 = key
imav_wp_config_value() {
    grep -E "^[[:space:]]*define[[:space:]]*\([[:space:]]*['\"]$2['\"]" "$1" 2>/dev/null | head -n 1 \
        | sed -E "s/^[^,]*,[[:space:]]*['\"]//; s/['\"][[:space:]]*\)[[:space:]]*;.*$//"
}

# Run a query. Tab separated rows, no header, escaped newlines.
# Errors go to stderr only when IMAV_DB_VERBOSE=1.
# $1 = SQL
imav_db_query() {
    if [ "$IMAV_DB_VERBOSE" = '1' ]; then
        MYSQL_PWD="$IMAV_DB_PASS" mysql -h "$IMAV_DB_HOST" -u "$IMAV_DB_USER" \
            -D "$IMAV_DB_NAME" --batch --skip-column-names -e "$1"
    else
        MYSQL_PWD="$IMAV_DB_PASS" mysql -h "$IMAV_DB_HOST" -u "$IMAV_DB_USER" \
            -D "$IMAV_DB_NAME" --batch --skip-column-names -e "$1" 2>/dev/null
    fi
}

# Run a query and write the raw value of a single cell to a file.
# $1 = SQL, $2 = file
imav_db_query_raw() {
    MYSQL_PWD="$IMAV_DB_PASS" mysql -h "$IMAV_DB_HOST" -u "$IMAV_DB_USER" \
        -D "$IMAV_DB_NAME" --batch --raw --skip-column-names -e "$1" > "$2" 2>/dev/null
}


#----------------------------------------------------------#
#                    Export for the file scanner           #
#----------------------------------------------------------#

# Export every text value that could carry a payload into one file per row,
# for the ImunifyAV file scanner. Which values are malicious is left to the
# signatures; the only filter is what cannot be a payload at all: values
# shorter than IMAV_DB_MIN_LEN, or without any markup, code, escape, entity or
# URL character (<, (, backslash, &#, http). One query per table and column,
# one awk pass writing the files, so that large tables export in seconds.
# Files are named TABLE-COLUMN-ID.EXT (.php when the value contains a PHP
# open tag, .html otherwise) so that findings map back to rows. Values above
# IMAV_DB_MAX_VALUE cannot be signature-scanned and are listed in the file
# "$1.oversized" instead. Prints the number of exported files.
# $1 = export directory
imav_db_export() {
    local dir="$1" p="$IMAV_DB_PREFIX" count=0 n spec table idcol cols col where tables

    rm -rf "$dir"
    mkdir -p "$dir"
    chmod 700 "$dir"
    : > "$dir.oversized"

    tables=$(imav_db_query "SHOW TABLES")
    for spec in $IMAV_DB_TABLES; do
        IFS=':' read -r table idcol cols <<< "$spec"
        echo "$tables" | grep -qx "${p}${table}" || continue
        for col in ${cols//,/ }; do
            where="LENGTH($col) >= $IMAV_DB_MIN_LEN AND ($col LIKE '%<%' OR $col LIKE '%(%' OR INSTR($col, CHAR(92)) > 0 OR $col LIKE '%&#%' OR $col LIKE '%http%')"
            n=$(imav_db_query "SELECT $idcol, $col FROM ${p}${table} WHERE $where" \
                | awk -F'\t' -v dir="$dir" -v prefix="$table-$col" -v max="$IMAV_DB_MAX_VALUE" -v over="$dir.oversized" '
                {
                    id = $1
                    v = substr($0, length($1) + 2)
                    # mysql --batch escapes newline, tab and backslash; restore them
                    gsub(/\\\\/, "\001", v)
                    gsub(/\\n/, "\n", v)
                    gsub(/\\t/, "\t", v)
                    gsub(/\\0/, "", v)
                    gsub(/\001/, "\\", v)
                    if (length(v) > max) { print prefix "-" id > over; next }
                    ext = (index(v, "<?") > 0) ? "php" : "html"
                    f = dir "/" prefix "-" id "." ext
                    printf "%s", v > f
                    close(f)
                    n++
                }
                END { print n + 0 }')
            count=$((count + ${n:-0}))
        done
    done

    echo "$count"
}

# Map ImunifyAV findings on exported files back to rows.
# Prints TSV: TABLE<TAB>ROW_ID<TAB>COLUMN<TAB>FINDING<TAB>SOURCE
# $1 = export directory, $2 = findings JSON
imav_db_map_findings() {
    local dir="$1" file sig base table column id
    while IFS="$IMAV_FS" read -r file sig; do
        [ -z "$file" ] && continue
        base=$(basename "$file")
        base=${base%.*}
        # TABLE-COLUMN-ID; table and column names contain no dashes
        table=${base%%-*}
        column=${base#*-}; column=${column%%-*}
        id=${base##*-}
        printf '%s\t%s\t%s\t%s\timunify\n' "$table" "$id" "$column" "$sig"
    done < <(echo "$2" | jq -r '.[] | [(.file // ""), (.type // "")] | join("\u001f")')
}

# Rows that were too large for signature scanning, one per line (TABLE-COLUMN-ID)
# $1 = export directory
imav_db_oversized() {
    cat "$1.oversized" 2>/dev/null
}

# Remove the findings on exported files from the ImunifyAV malicious list,
# once they have been mapped to rows and the files are about to be deleted;
# otherwise they would stay listed forever. Measured syntax:
# "malware malicious remove-from-list ID [ID ...]".
# $1 = export directory, $2 = findings JSON
imav_db_forget_findings() {
    local ids
    ids=$(echo "$2" | jq -r --arg p "$1/" '.[] | select((.file // "") | startswith($p)) | .id' 2>/dev/null | tr '\n' ' ')
    if [ -n "${ids// /}" ]; then
        $IMAV_BIN malware malicious remove-from-list $ids >/dev/null 2>&1 \
            || imav_log WARN "could not remove exported database rows from the ImunifyAV malicious list: $ids"
    fi
}


#----------------------------------------------------------#
#                    Heuristics                            #
#----------------------------------------------------------#

# Heuristic checks. Prints the same TSV as imav_db_map_findings with SOURCE = heuristic.
# $1 = domain, $2 = docroot, $3 = export directory (unused, kept for the call signature)
imav_db_heuristics() {
    local domain="$1" docroot="$2" dir="$3" p="$IMAV_DB_PREFIX"
    local name value host plugin login registered

    # siteurl and home must point to the domain
    while IFS=$'\t' read -r name value; do
        [ -z "$name" ] && continue
        host=$(echo "$value" | sed -e 's|^[a-z]*://||' -e 's|[/:].*||' -e 's/^www\.//')
        if [ -n "$host" ] && [ "$host" != "${domain#www.}" ] && [[ "$host" != *".${domain#www.}" ]]; then
            printf 'options\t%s\toption_value\t%s points to %s instead of %s\theuristic\n' "$name" "$name" "$value" "$domain"
        fi
    done < <(imav_db_query "SELECT option_name, option_value FROM ${p}options WHERE option_name IN ('siteurl','home')")

    # active_plugins entries whose files do not exist
    value=$(imav_db_query "SELECT option_value FROM ${p}options WHERE option_name='active_plugins'")
    for plugin in $(echo "$value" | grep -o 's:[0-9]*:"[^"]*"' | sed -e 's/^s:[0-9]*:"//' -e 's/"$//'); do
        if [ ! -f "$docroot/wp-content/plugins/$plugin" ]; then
            printf 'options\tactive_plugins\toption_value\tactive plugin file missing: %s\theuristic\n' "$plugin"
        fi
    done

    # administrators registered recently
    while IFS=$'\t' read -r login registered; do
        [ -z "$login" ] && continue
        printf 'users\t%s\tuser_registered\tadministrator created on %s\theuristic\n' "$login" "$registered"
    done < <(imav_db_query "SELECT u.user_login, u.user_registered FROM ${p}users u JOIN ${p}usermeta m ON m.user_id=u.ID WHERE m.meta_key='${p}capabilities' AND m.meta_value LIKE '%administrator%' AND u.user_registered > NOW() - INTERVAL $IMAV_DB_ADMIN_DAYS DAY")

    # cron entries with URLs
    value=$(imav_db_query "SELECT option_value FROM ${p}options WHERE option_name='cron'")
    for host in $(echo "$value" | grep -o 'https\?://[^"\\ ;]*' | sed -e 's|^[a-z]*://||' -e 's|[/:].*||' | sort -u); do
        if [ "${host#www.}" != "${domain#www.}" ]; then
            printf 'options\tcron\toption_value\tcron job references external host %s\theuristic\n' "$host"
        fi
    done

}


#----------------------------------------------------------#
#                    Output                                #
#----------------------------------------------------------#

# Print database findings (TSV on stdin) in a format
# $1 = format
imav_db_print() {
    case $1 in
        json)
            jq -R -s -c '
                split("\n") | map(select(length > 0) | split("\t")) |
                map({table: .[0], row_id: .[1], column: .[2], finding: .[3], source: .[4]})' | jq '.'
            ;;
        csv)
            echo 'table,row_id,column,finding,source'
            jq -R -r 'split("\t") | @csv'
            ;;
        plain)
            cat
            ;;
        shell)
            {
                echo "TABLE|ROW|COLUMN|FINDING|SOURCE"
                echo "-----|---|------|-------|------"
                tr '\t' '|'
            } | column -t -s '|'
            ;;
    esac
}
