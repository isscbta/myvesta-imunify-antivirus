#!/bin/bash
# myVesta ImunifyAV integration: mail delivery.
#
# One function to send a message through the transport chosen in imav.conf:
#   MAIL_TRANSPORT='sendmail'  local Exim through /usr/sbin/sendmail
#   MAIL_TRANSPORT='mailgun'   Mailgun HTTP API; key, domain, sender and API
#                              URL from imav.conf (MAILGUN_API_KEY,
#                              MAILGUN_DOMAIN, MAILGUN_FROM, MAILGUN_API_URL)
#
# Requires func/imav.sh (for imav_log). Runs as root.

: "${MAIL_TRANSPORT:=sendmail}"
: "${MAIL_FROM:=}"
: "${MAIL_FROM_NAME:=myVesta Imunify Antivirus}"
: "${MAILGUN_API_KEY:=}"
: "${MAILGUN_DOMAIN:=}"
: "${MAILGUN_FROM:=}"
: "${MAILGUN_API_URL:=https://api.eu.mailgun.net/v3}"

# Send a message. Returns 0 on success, 1 on failure with IMAV_MAIL_ERROR set.
# $1 = recipients (comma separated), $2 = subject, $3 = text body file,
# $4 = HTML body file (optional)
imav_mail_send() {
    local to="$1" subject="$2" text_file="$3" html_file="$4"
    IMAV_MAIL_ERROR=''
    [ -z "$to" ] && { IMAV_MAIL_ERROR='no recipients'; return 1; }
    [ -f "$text_file" ] || { IMAV_MAIL_ERROR="text body $text_file missing"; return 1; }
    case $MAIL_TRANSPORT in
        mailgun)  imav_mail_send_mailgun "$to" "$subject" "$text_file" "$html_file" ;;
        sendmail) imav_mail_send_sendmail "$to" "$subject" "$text_file" "$html_file" ;;
        *)        IMAV_MAIL_ERROR="unknown MAIL_TRANSPORT '$MAIL_TRANSPORT'"; return 1 ;;
    esac
}

# Sender for sendmail: "MAIL_FROM_NAME <MAIL_FROM>"; the address defaults to imav@hostname
imav_mail_from() {
    local addr="$MAIL_FROM"
    [ -z "$addr" ] && addr="imav@$(hostname -f 2>/dev/null || hostname)"
    if [ -n "$MAIL_FROM_NAME" ]; then
        echo "$MAIL_FROM_NAME <$addr>"
    else
        echo "$addr"
    fi
}

imav_mail_send_sendmail() {
    local to="$1" subject="$2" text_file="$3" html_file="$4"
    local sendmail_bin='/usr/sbin/sendmail' boundary output rc
    [ -x "$sendmail_bin" ] || sendmail_bin=$(command -v sendmail 2>/dev/null)
    if [ -z "$sendmail_bin" ]; then
        IMAV_MAIL_ERROR='sendmail is not available'
        return 1
    fi
    boundary="imav-$(date +%s)-$$"
    output=$({
        printf 'From: %s\nTo: %s\nSubject: %s\nMIME-Version: 1.0\n' "$(imav_mail_from)" "$to" "$subject"
        if [ -n "$html_file" ] && [ -f "$html_file" ]; then
            printf 'Content-Type: multipart/alternative; boundary="%s"\n\n' "$boundary"
            printf -- '--%s\nContent-Type: text/plain; charset=UTF-8\nContent-Transfer-Encoding: 8bit\n\n' "$boundary"
            cat "$text_file"
            printf '\n--%s\nContent-Type: text/html; charset=UTF-8\nContent-Transfer-Encoding: 8bit\n\n' "$boundary"
            cat "$html_file"
            printf '\n--%s--\n' "$boundary"
        else
            printf 'Content-Type: text/plain; charset=UTF-8\nContent-Transfer-Encoding: 8bit\n\n'
            cat "$text_file"
        fi
    } | "$sendmail_bin" -t 2>&1)
    rc=$?
    if [ $rc -ne 0 ]; then
        IMAV_MAIL_ERROR="sendmail exited with $rc: $output"
        imav_log ERROR "mail to $to failed: $IMAV_MAIL_ERROR"
        return 1
    fi
    imav_log INFO "mail sent to $to via sendmail: $subject"
    return 0
}

imav_mail_send_mailgun() {
    local to="$1" subject="$2" text_file="$3" html_file="$4"
    local key mg_domain mg_from mg_url response code

    key=$MAILGUN_API_KEY
    mg_domain=$MAILGUN_DOMAIN
    mg_from=$MAILGUN_FROM
    mg_url=$MAILGUN_API_URL
    [ -z "$mg_from" ] && [ -n "$mg_domain" ] && mg_from="postmaster@$mg_domain"
    # Add the display name unless the configured sender already has one
    if [ -n "$MAIL_FROM_NAME" ] && [[ "$mg_from" != *'<'* ]]; then
        mg_from="$MAIL_FROM_NAME <$mg_from>"
    fi

    if [ -z "$key" ]; then
        IMAV_MAIL_ERROR="MAILGUN_API_KEY is empty in $VESTA/conf/imav.conf"
        imav_log ERROR "mail to $to failed: $IMAV_MAIL_ERROR"
        return 1
    fi
    if [ -z "$mg_domain" ]; then
        IMAV_MAIL_ERROR="MAILGUN_DOMAIN is empty in $VESTA/conf/imav.conf"
        imav_log ERROR "mail to $to failed: $IMAV_MAIL_ERROR"
        return 1
    fi

    local -a html_arg=()
    if [ -n "$html_file" ] && [ -f "$html_file" ]; then
        html_arg=( -F "html=@$html_file" )
    fi
    response=$(curl -sS -m 60 --user "api:$key" "$mg_url/$mg_domain/messages" \
        -F "from=$mg_from" -F "to=$to" -F "subject=$subject" \
        -F "text=@$text_file" "${html_arg[@]}" -w '\n%{http_code}' 2>&1)
    code=$(echo "$response" | tail -n 1)
    if [ "$code" != '200' ]; then
        IMAV_MAIL_ERROR="Mailgun returned HTTP ${code:-none}: $(echo "$response" | head -n 1 | head -c 300)"
        imav_log ERROR "mail to $to failed: $IMAV_MAIL_ERROR"
        return 1
    fi
    imav_log INFO "mail sent to $to via Mailgun: $subject"
    return 0
}
