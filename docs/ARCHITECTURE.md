# Architecture

This document describes how the project is put together, which decisions were made and why, and how every command works. It is meant for whoever maintains the code. The operator guide is in [README.md](../README.md).

## 1. Principles

1. **One surface for the operator.** Every command takes the domain as its first argument, resolves the owner and document root from myVesta, prints a human-readable result and saves a report in the same place and format. The CSV report keeps the column order of Wordfence CLI reports, so scripts written for those keep working.
2. **myVesta conventions.** The repository maps onto `/usr/local/vesta`. Commands are in `bin/`, shared functions in `func/`, and files that live outside `/usr/local/vesta` on the server (configuration defaults, cron job, ImunifyAV integration file) are in `files/`, which maps to `/`. Every command uses the four-section structure (Variable&Function, Verifications, Action, Vesta), positional parameters with an optional trailing `FORMAT`, `check_args`, `is_format_valid`, `check_result`, `log_event` and `log_history` from `$VESTA/func/main.sh`, and the standard `E_*` exit codes. Everything is bash; JSON is handled with `jq`.
3. **No Docker and no own signature engine.** Malware scanning is done exclusively by the ImunifyAV agent. The project does not maintain signatures, does not parse PHP and does not try to be an antivirus. It is an integration layer between myVesta and ImunifyAV.
4. **Designed for the free edition.** Nothing in the basic flow may depend on an ImunifyAV+ license. If a license exists, it is used as an improvement (cleanup), not as a requirement.
5. **Everything that depends on network services is cached and degrades.** If WPVulnerability does not answer, the vulnerability scanner works from cache and says clearly that the data is stale. If the ImunifyAV agent is down, the command fails immediately and never reports "clean".
6. **Never report a clean result after an error.** A failed scan keeps the previous report and exits with an error code.

## 2. Layout on the server

| Path | What | Owner / mode |
|---|---|---|
| `/root/myvesta-imunify-antivirus/` | Clone of this repository, used by `imav-install.sh` and `imav-update.sh` | `root:root` |
| `/usr/local/vesta/bin/v-imav-*` | Commands, copied from `bin/` (not symlinked, like all myVesta commands) | `root:root`, `755` |
| `/usr/local/vesta/bin/v-imav-notify-hook` | Hook ImunifyAV calls; world-readable like every command | `root:root`, `755` |
| `/usr/local/vesta/func/imav*.sh` | Shared functions, copied from `func/` | `root:root`, `644` |
| `/usr/local/vesta/conf/imav.conf` | Project configuration, myVesta `KEY='value'` format | `root:root`, `640`; read only by root commands, never by the `_imunify` hook |
| `/var/spool/myvesta-imav/` | Notification spool: the hook drops one JSON file per event | `root:_imunify`, `1730` (`_imunify` can create files, not list or read others) |
| `/etc/systemd/system/myvesta-imav-notify.path`, `.service` | Path unit that runs `v-imav-notify-send` as root when the spool is not empty | `root:root`, `644` |
| `/var/log/myvesta-imav/reports/DOMAIN/` | Timestamped report history (scan CSVs and `report-*.txt`/`.html`) | `root:root` |
| `/usr/local/vesta/data/imav/monitor.conf`, `monitor/DOMAIN.conf` | Registry of monitored domains and per-domain trend state | `root:root`, `600` |
| `/etc/cron.d/myvesta-imav-monitor` | Hourly `v-imav-run-monitors`, installed by the first `v-imav-add-monitor` | `root:root`, `644` |
| `/usr/local/vesta/data/imav/backups/DOMAIN/` | Archives of files touched by remediate | `root:root` |
| `/var/log/myvesta-imav/imav.log` | Log of every command run (one line per run plus errors), in addition to `log_event` | `root:root` |
| `/etc/sysconfig/imunify360/integration.conf` | ImunifyAV stand-alone integration | written by the installer |
| `/etc/sysconfig/imunify360/imunify360.config.d/90-local.config` | ImunifyAV config (changed only through `imunify-antivirus config update`) | managed by ImunifyAV |
| `/var/cache/imav/` | Cache: WPVulnerability responses, Wordfence feed, original WordPress archives | `root:root` |
| `/home/USER/web/DOMAIN/private/imav-scan.csv` | Latest report for the domain | `USER:USER` |
| `/srv/wp-quarantine/DOMAIN/` | Quarantine (`QUARANTINE_DIR`), one subdirectory per domain | directories `USER:USER` |

Report location decision: a report in `public_html` would make the list of infected files reachable over the web, so the default is the `private/` directory of the domain (part of the myVesta domain layout, not web-accessible). `REPORT_IN_DOMAIN_DIR='public_html'` is available for setups whose tooling expects the file there.

## 3. Shared layer: `func/imav.sh`

Every `v-imav-*` command starts with:

```bash
# Includes
source $VESTA/func/main.sh
source $VESTA/func/imav.sh
source $VESTA/conf/vesta.conf
source $VESTA/conf/imav.conf
```

`func/imav.sh` provides:

| Function | Purpose |
|---|---|
| `imav_require_agent` | Checks that `imunify-antivirus` exists and the agent responds (`imunify-antivirus version --json`); otherwise `check_result $E_DISABLED "ImunifyAV agent is not running"` |
| `imav_domain_owner DOMAIN` | `v-search-domain-owner`, sets `$user` and `$USER_DATA`, exits with `$E_NOTEXIST` if the domain does not exist |
| `imav_domain_docroot USER DOMAIN` | Sets `$docroot` to `/home/USER/web/DOMAIN/public_html` (or `public_shtml` for single-SSL domains, same check as `v-get-database-credentials-of-domain`), with existence check |
| `imav_start_scan PATH [imunify-args...]` | Runs `malware on-demand start --path PATH args`, sets `$scan_id` |
| `imav_wait_scan SCAN_ID` | Loop: `malware on-demand status --json` until the scan is finished; prints progress (file count) every N seconds; timeout from configuration |
| `imav_scan_results SCAN_ID` | `malware malicious list --by-scan-id SCAN_ID --limit N --json`, with pagination |
| `imav_results_to_csv` | JSON → CSV report |
| `imav_write_report USER DOMAIN CSV` | Writes to the domain's `private/` plus a copy in `/var/log/myvesta-imav/reports/` |
| `imav_log LEVEL MSG` | Log to `/var/log/myvesta-imav/imav.log` |
| `imav_version_compare A OP B` | Version comparison with PHP `version_compare` semantics (`lt`, `le`, `eq`, `ne`, `gt`, `ge`), a bash port of the PHP algorithm (canonicalisation, special forms `dev < alpha < beta < rc < # < pl`); used by the vulnerability engine |
| `imav_cached_download URL FILE TTL` | Download with cache and stale fallback (`IMAV_CACHE_STALE=1`) |

Two conventions apply to all functions:

- Functions that validate something (`imav_domain_owner`, `imav_domain_docroot`, `imav_start_scan`, `imav_wait_scan`) set global variables and are called directly, never inside `$(...)`. `check_result` exits the current shell, and inside a command substitution that would only end the subshell while the command carries on with an empty value.
- Multi-column records that are read back with `read` use `$IMAV_FS` (ASCII unit separator, `join("\u001f")` in jq) instead of tabs. A tab is an IFS whitespace character, so `read` collapses consecutive tabs and an empty column shifts every column after it.

### 3.1 Obtaining `scan_id`

According to the documentation `malware on-demand start` prints `OK`. To reliably get the id of the scan just started, `imav_start_scan` does:

1. Before starting, read `malware on-demand list --json` and remember the set of existing `scan_id` values.
2. Start the scan.
3. Read the list again and take the `scan_id` that is new and whose `path` matches the requested path.

If `on-demand start --json` in practice returns `scan_id` directly, that is used and steps 1 and 3 remain as a fallback. The exact output shape is checked on the test server and recorded in [imunifyav-cli-notes.md](imunifyav-cli-notes.md).

### 3.2 Waiting

On-demand scans in ImunifyAV are queued. If another scan is already running (for example the nightly `v-imav-scan-all`), the new one waits. `imav_wait_scan` shows this to the operator ("queued, 1 scan ahead") instead of staying silent. The timeout is configurable (`SCAN_TIMEOUT`, default 6 hours for a single domain, unlimited for `v-imav-scan-all`).

### 3.3 Report format

The CSV columns keep the order of Wordfence CLI reports (`filename`, `signature_id`, `signature_name` first), so existing consumers of such files keep working:

```
filename,signature_id,signature_name,status,size,hash,scan_id,detected_at
```

`signature_id` and `signature_name` are the Imunify `TYPE` (for example `SMW-INJ-04174-bkdr`), `status` is the Imunify `STATUS` (`found`, `cleanup_done`, ...).

### 3.4 Exit codes

Following myVesta, a command that completed its work exits with `0`, whether it found malware or not; the findings are in the output and in the report. Errors use the standard codes from `main.sh`: `$E_ARGS` (usage), `$E_INVALID` (bad parameter), `$E_NOTEXIST` (domain or path does not exist), `$E_DISABLED` (agent not running), `$E_CONNECT` (API or download failure), `$E_UPDATE` (scan stopped or timed out). Cron and Ansible check for infections with `v-imav-list-infected DOMAIN json`.

## 4. Flow of every command

### 4.1 `v-imav-malware-scan DOMAIN [FORMAT]`

```bash
#!/bin/bash
# info: scan domain for malware with ImunifyAV
# options: DOMAIN [FORMAT]
#
# The function starts an ImunifyAV on-demand scan of the domain's document root,
# waits for it to finish and prints the list of infected files.
```

1. `check_args '1' "$#" 'DOMAIN [FORMAT]'`, `is_format_valid 'domain' 'format'`, `imav_require_agent`.
2. `user=$(imav_domain_owner "$domain")`, `is_object_valid 'user' 'USER' "$user"`, `is_object_valid 'web' 'DOMAIN' "$domain"`.
3. `imav_start_scan "$docroot" --intensity-cpu $SCAN_INTENSITY_CPU --intensity-io $SCAN_INTENSITY_IO`.
4. `imav_wait_scan`.
5. `imav_scan_results` → CSV → screen in the chosen `FORMAT` + report.
6. `log_history "malware scan of $domain: N infected files"`, `log_event "$OK" "$ARGUMENTS"`.

There is no separate "hyperscan" or "fast" variant: ImunifyAV always scans with Hyperscan and RapidScan.

### 4.2 `v-imav-scan-path PATH [MINUTES] [ALL_EXTENSIONS] [FORMAT]`

Positional parameters are the primary interface; the environment variables are honoured as well so that existing cron jobs keep working:

| Parameter | Old variable | Meaning |
|---|---|---|
| `MINUTES` | `cmin=-N`, `chour=-N`, `cday=-N` | Only files changed in the last N minutes (`0` = everything) |
| `ALL_EXTENSIONS` | `all=1` | `yes`: all extensions, not only `php`, `js`, `htm`, `html` |
| (none) | `SCANPATH` | Glob to scan instead of `PATH` (for example `/home/*/web`); `PATH` stays the report location |

Without `MINUTES`: `on-demand start --path "$scanpath"`. ImunifyAV supports a glob in `--path` (documentation example: `--path='/var/www/vhosts/d*'`).

With `MINUTES`: `find` produces the file list, the list is split into batches of 200 paths and each batch goes to `malware on-demand queue put PATH1 PATH2 ...`. ImunifyAV has no `--read-stdin`, so this is the substitute. Afterwards the command waits for the queue to drain and collects the findings of all scans started in that pass.

Note: thanks to RapidScan a plain `on-demand start --path /home` already scans only changed files plus a share of unchanged ones, so the `MINUTES` mode is kept mainly for compatibility and for quick checks after an incident.

### 4.3 `v-imav-scan-all [WAIT]`

`on-demand start --path /home` with the intensity from configuration, wait, then a summary report per user and domain in `/var/log/myvesta-imav/reports/_all/`. No reports in `private/` directories. Notification is sent by the hook, not by the command. Meant for cron; with `WAIT=no` it only starts the scan and exits.

### 4.4 `v-imav-vuln-scan DOMAIN [FORMAT]`

The command sources `func/imav-vuln.sh` and calls `imav_vuln_scan "$docroot"`. The engine:

1. **Inventory from disk**, without wp-cli and without database access:
   - core: `wp-includes/version.php` → `$wp_version`
   - plugins: for every directory in `wp-content/plugins/` the first `*.php` file with a `Plugin Name:` header → `Version:`; the slug is the directory name. Single-file plugins (`hello.php`) are recognised too.
   - themes: `wp-content/themes/*/style.css` → `Theme Name:`, `Version:`
   - mu-plugins are listed but not checked (no wordpress.org slug)

   Reason for reading from disk: it works on broken sites, does not execute PHP as the user and needs no database access. Drawback: it does not know whether a plugin is active. This is shown as the column `active=unknown`; reading `active_plugins` from the database can be added later.

2. **WPVulnerability query**: `https://www.wpvulnerability.net/plugin/SLUG`, `/theme/SLUG`, `/core/VERSION`. No key. The response is cached in `CACHE_DIR/wpv/TYPE/SLUG.json` for `VULN_CACHE_TTL`. On a server with hundreds of sites the number of unique slugs is a few hundred, so the daily API load is acceptable. A slug that does not exist on wordpress.org returns `name: null` and is shown as "unknown plugin (custom or premium)".

3. **Version comparison**: every record has `operator` with `min_version`/`min_operator`, `max_version`/`max_operator`, `unfixed`. Semantics are PHP `version_compare`; `imav_version_compare` implements them (normalisation `1.2` → `1.2.0`, suffixes `beta`, `rc`). If `unfixed = 1`, "no fix available" is shown.

4. **Optional Wordfence Intelligence v3**: if `WF_API_KEY` is set, the `scanner` feed is downloaded once a day (`Authorization: Bearer KEY`, `GET /api/intelligence/v3/vulnerabilities/scanner`) into `CACHE_DIR/wf-scanner.json`. For every component, records with the same `slug` and `type` are matched and the `affected_versions` ranges (`from_version`, `from_inclusive`, `to_version`, `to_inclusive`, `*`) compared. Findings from both sources are merged by CVE or title, the source is shown in a column. Feed v2 (no key) was shut down on 9 March 2026, hence the key is required for this source. The key is free, obtained from a Wordfence account (Integrations).

5. **Output**: table on screen (type, slug, installed version, vulnerability title, CVSS, fixed in, source, link), CSV in `private/imav-vuln.csv`, and `json` for further processing.

### 4.5 `v-imav-remediate DOMAIN [MODE] [SCAN_ID]`

`MODE` is `auto` (default), `dry-run` (print the plan only) or `quarantine` (quarantine everything, no downloads). With `SCAN_ID` only the findings of that scan are handled (this is how `v-imav-malware-scan-with-remediate` calls it).

Input: the files ImunifyAV currently reports as infected under the docroot (`malware malicious list --user USER` or `--by-scan-id`, filtered to the docroot and to findings that are not already cleaned or ignored).

For every file:

1. If an AV+ license exists (`imunify-antivirus rstatus` reports active AV+) and `REMEDIATE_USE_IMUNIFY_CLEANUP='yes'`: `malware malicious cleanup --ids ID`. If Imunify reports success, done.
2. Otherwise the file is classified by its path inside the docroot:
   - **core** (`wp-admin/`, `wp-includes/`, root files `wp-*.php`, `index.php`, `xmlrpc.php`): the original is downloaded from `https://wordpress.org/wordpress-VERSION.zip` (cached in `CACHE_DIR/wp/`), version from `wp-includes/version.php`. The file is replaced with the original. If the file does not exist in the original (a file added to `wp-includes/`), it goes to quarantine.
   - **plugin** (`wp-content/plugins/SLUG/`): `https://downloads.wordpress.org/plugin/SLUG.VERSION.zip`. If the plugin does not exist on wordpress.org (premium), the file goes to quarantine and this is reported clearly.
   - **theme**: `https://downloads.wordpress.org/theme/SLUG.VERSION.zip`, same.
   - **everything else** (`wp-content/uploads/`, root, unknown directories): quarantine.
3. Quarantine: `mv` to `QUARANTINE_DIR/DOMAIN/relative/path`, directories get the user's ownership, as before. Never `rm`.
4. After a replacement, ownership and mode are checked to be the same as before (`stat` before, `chown`/`chmod` after).
5. Every action goes to the log and to the report `private/imav-remediate.csv` (`filename,action,source,result`).

Before any change a `tar.gz` of the affected files is created in `$VESTA/data/imav/backups/DOMAIN/TIMESTAMP.tar.gz`, so every step can be reverted.

### 4.6 `v-imav-malware-scan-with-remediate DOMAIN [MODE]`

`v-imav-malware-scan`, then, if there are findings:

- `MODE=interactive` (or `INTERACTIVE=1`): for every file `stat`, `mcedit`, the question "move to quarantine? (y/n, default y)" read from `/dev/tty`.
- otherwise: `v-imav-remediate DOMAIN` with the findings of the scan that just finished.

### 4.7 `v-imav-db-scan DOMAIN [FORMAT]`

The Imunify Malware Database Scanner exists only in Imunify360, not in ImunifyAV, so this is an own implementation in `func/imav-db.sh`:

1. Database name through `v-get-database-credentials-of-domain DOMAIN`, root credentials from `mysql.conf`, table prefix from `wp-config.php`.
2. Export to a temporary directory `$VESTA/data/imav/dbscan/DOMAIN/` (not `/tmp`): one file per row for every text column of `posts` (`post_content`, `post_excerpt`), `postmeta`, `options`, `comments`, `commentmeta`, `usermeta` and `termmeta`. The only filter is what cannot be a payload: values shorter than 32 bytes or without any of `<`, `(`, backslash, `&#`, `http`; which values are malicious is left to the signatures. One `SELECT id, column` per table and column runs through `mysql --batch` (newlines, tabs and backslashes escaped) into a single `awk` pass that restores the escapes and writes the files, so large tables export in seconds. Files are named `TABLE-COLUMN-ID.php` when the value contains a PHP open tag, `.html` otherwise. Values above 1 MB (`max_signature_size_to_scan`) cannot be signature-scanned; they are listed in the report as unchecked instead of pretending they were.
3. `on-demand start --path` on that directory. Imunify signatures for JS injections, blackhat SEO and PHP backdoors work on content exported this way as well; a whole-table SQL dump would not do, because files above 1 MB skip the signatures and the SQL escaping breaks HTML and JS patterns.
4. Additional heuristics (bash/grep, because signatures do not cover site logic): `siteurl` and `home` different from the domain, `<script src="http` pointing to domains outside the site in `post_content`, `active_plugins` pointing to non-existent directories, unknown users with the `administrator` role created in the last N days, `wp_options` cron entries calling external URLs.
5. Report: `table,row_id,column,finding,source(imunify|heuristic)`. The database is never modified. The temporary directory is removed after the scan.

### 4.8 `v-imav-list-infected [DOMAIN] [FORMAT]`, `v-imav-add-ignore PATH`, `v-imav-delete-ignore PATH`, `v-imav-list-ignore [FORMAT]`

Thin wrappers around `malware malicious list --user USER --json` (filtered to the domain's docroot) and `malware ignore add|delete|list`. They exist so that an operator does not have to learn the Imunify CLI for everyday tasks. Named verb-first (`add`, `delete`, `list`) like all myVesta commands.

### 4.9 `v-imav-notify-hook` and `v-imav-notify-send`

Not operator commands. The agent calls `v-imav-notify-hook` as `_imunify` with JSON on stdin (fields `event_id`, `scan_id`, `started`, `completed`, `total_malicious`, `malicious_files[]`). `_imunify` must have no access to `/usr/local/vesta/conf` (the directory is `drwxr-x--- root root` and stays that way), so the hook reads nothing: it validates that stdin is JSON and writes it to `/var/spool/myvesta-imav/event-TIMESTAMP-PID.json` (via a temporary file and `mv`, so the sender never sees a partial file). It exits `0` in every case, so that ImunifyAV does not mark the event as failed; problems go to syslog (`logger -t v-imav-notify-hook`).

The systemd path unit `myvesta-imav-notify.path` (`DirectoryNotEmpty=/var/spool/myvesta-imav`) starts `myvesta-imav-notify.service`, a oneshot unit that runs `v-imav-notify-send` as root. The sender sources `main.sh`, `imav.sh` and `imav.conf`, builds one message per event (host name, scan id, count, first 30 files), sends it by email (`/usr/sbin/sendmail -t`, Exim on myVesta) when `ALERT_EMAIL` is set and by Telegram when the token and chat id are set, logs the result to syslog and `/var/log/myvesta-imav/imav.log`, and removes the spool file whether delivery succeeded or not, so that the path unit cannot loop on a bad event. Temporary files older than five minutes are removed as leftovers of a crashed hook.

Measured on the test server: the agent invokes the hook a few seconds after every on-demand scan with findings, and Exim accepts mail from `_imunify` as well as from root.

### 4.10 Security reports: `v-imav-report-domain`, the monitor registry and `v-imav-run-monitors`

Scheduled reports are driven by a registry instead of one cron line per site, so that adding a site is one command and every report has the same structure and priorities.

**Registry** (`func/imav-monitor.sh`): `$VESTA/data/imav/monitor.conf`, one myVesta-style line per domain (`DOMAIN`, `USER`, `EMAIL`, `HOUR`, `SUSPENDED`, `TIME`, `DATE`). `v-imav-add-monitor` also installs `/etc/cron.d/myvesta-imav-monitor` (hourly `v-imav-run-monitors`) if missing; the nightly scan cron stays separate and optional. Per-domain trend state (`TOTAL_FILES`, `UPLOADS_FILES`, `ADMINS`, `PLUGINS`, `LAST_REPORT`) lives in `$VESTA/data/imav/monitor/DOMAIN.conf`.

**Runner**: `v-imav-run-monitors [HOUR]` takes a `flock`, walks the registry and runs `v-imav-report-domain DOMAIN '' yes` for every unsuspended domain whose `HOUR` matches, sequentially (ImunifyAV queues scans anyway). Each run's output goes to `$VESTA/data/imav/run-monitors-DOMAIN.log`.

**Report** (`func/imav-report.sh`): every check is a function that opens a section (`report_section`), raises its level (`report_level`, never lowered: OK < INFO < WARNING < CRITICAL), sets a one-line summary and writes lines, preformatted blocks or table rows into a body file. Bodies are kept as files, not variables, so checks may write from inside pipelines. Two renderers build the plain-text and the HTML version from the same sections: a coloured status header, a summary table with one row per check, then the sections. Empty table cells are stored as `-` so that a trailing empty column survives the tab-separated read-back. The overall level is the highest section level and goes into the mail subject.

Checks and their data sources:

| Check | Source |
|---|---|
| Malware | `func/imav.sh` on-demand scan of the docroot |
| Unexpected locations in wp-content | `func/imav-heuristic.sh`: PHP files in `wp-content` directories outside the known set (`index.php` guard files excluded), plugin and theme directories matching `-[0-9a-f]{6,}$`. Location only; file content is left to the signatures |
| Vulnerabilities | `func/imav-vuln.sh` (WPVulnerability, Wordfence feed when `WF_API_KEY` is set) |
| Database | `func/imav-db.sh` export, ImunifyAV scan, heuristics |
| Core integrity | `api.wordpress.org/core/checksums/1.0/?version=V&locale=en_US`, cached; `md5sum` of `wp-admin`, `wp-includes` and root files; unknown PHP files in the core directories |
| Plugin integrity | `v-run-wp-cli DOMAIN plugin verify-checksums --all --format=csv` (skipped when wp-cli does not run) |
| Updates | `api.wordpress.org` version-check, plugin and theme info endpoints, cached 24 h, compared with `imav_version_compare` |
| PHP files in unexpected places | `find` in uploads; image and text files modified in the last 30 days whose first 256 bytes contain `<?php`; double extensions |
| Backups and dumps | `find -maxdepth 3` for archives, SQL, `.bak`, `.old`, config copies, `debug.log`, `error_log` |
| `.htaccess` | all `.htaccess` files: `auto_prepend_file`, `AddHandler`/`AddType`/`SetHandler` with php, `RewriteRule`/`Redirect` to another registrable domain, recent changes |
| Site from outside | `curl -L` of the home page (final host compared with the domain, HTTP code, meta refresh, external script hosts), `openssl s_client` certificate end date |
| Administrators | `v-run-wp-cli user list --role=administrator`, database fallback; compared with the state |
| Plugins | directory listing, `plugin list` for inactive ones, compared with the state |
| Cron | `v-run-wp-cli cron event list`, core hooks separated from plugin and custom ones |
| Outgoing mail | Exim `mainlog` and `mainlog.1`, `<=` lines with `U=user` in the last 24 hours |
| PHP version | `v-get-php-version-of-domain`, end-of-life table in the function |
| Hidden files and symlinks | `find -maxdepth 2 -name '.*'`, `find -type l` with `readlink -f` outside the docroot |
| Sizes | `du`, `find -type f | wc -l`, compared with the state |
| Root PHP, modified files | `find` in the root and over `*.php`, sorted by modification and status change time |

**Mail** (`func/imav-mail.sh`): `imav_mail_send TO SUBJECT TEXT_FILE [HTML_FILE]`. `sendmail` builds a `multipart/alternative` message for `/usr/sbin/sendmail -t`; `mailgun` posts to `MAILGUN_API_URL/MAILGUN_DOMAIN/messages` with `text=@` and `html=@`, authenticated with `MAILGUN_API_KEY`; all four come from `imav.conf`, which is readable only by root. `v-imav-notify-send` uses the same function for alert mails.

### 4.11 `v-imav-list-users-integration`, `v-imav-list-domains-integration`

Called by ImunifyAV through `integration.conf`. They print the JSON documented for `integration_scripts`:

- users: from `$VESTA/data/users/*/user.conf` (`id` from `id -u`, `username`, `owner='root'`, `email` from `CONTACT`, `package`), `metadata.result = ok`
- domains: from `$VESTA/data/users/*/web.conf`, `document_root = /home/USER/web/DOMAIN/public_html/`, `owner = USER`, `is_main = true` for the first domain of a user

They run as root (ImunifyAV calls integration scripts as root) and use `parse_object_kv_list_non_eval` from `main.sh` to read the config files. With them ImunifyAV knows which domain belongs to which user, the `infected-domains` command works, and per-user scans cover the right paths. Without them ImunifyAV would take all system users from the `login.defs` range, which on myVesta mostly matches the accounts, but without domain data.

## 5. Installation and update

`imav-install.sh` is idempotent: running it again does not break an existing installation (every step checks its state). It supports:

- `--key KEY`: ImunifyAV+ license
- `--no-hook`: skip notification registration
- `--wf-key KEY`: store a Wordfence Intelligence key without asking (the installer otherwise prompts for it and validates it against the feed, where a bad key gets HTTP 401)
- `--cron yes|no`: install or skip the nightly cron job without asking
- `--update`: only copy `bin/` and `func/`, set permissions and re-register the hook, without the ImunifyAV installer (this is what `imav-update.sh` calls)

`integration.conf` installed from `files/`:

```ini
[paths]
ui_path = /opt/imunifyav-ui

[integration_scripts]
panel_info = /usr/local/vesta/bin/v-imav-panel-info-integration
users = /usr/local/vesta/bin/v-imav-list-users-integration
domains = /usr/local/vesta/bin/v-imav-list-domains-integration
```

`panel_info` is mandatory for the Imunify installer (it warns when missing and announces that it will refuse to install without it); the script returns `{"data": {"name": "myVesta", "version": "..."}, "metadata": {"result": "ok"}}` with the version from `vesta.conf`.

The cron job is not installed silently: the installer asks at the end (default no), `--cron yes|no` answers for unattended runs, and `--update` only refreshes a cron file that already exists.

ImunifyAV settings applied by the installer through `config update`:

```json
{"MALWARE_SCAN_SCHEDULE": {"interval": "NONE"},
 "MALWARE_SCAN_INTENSITY": {"cpu": 2, "io": 2},
 "MALWARE_SCANNING": {"rapid_scan": true, "hyperscan": true, "sends_file_for_analysis": false},
 "MALWARE_CLEANUP": {"trim_file_instead_of_removal": false, "keep_original_files_days": 30}}
```

`sends_file_for_analysis: false` is the default for customer data privacy; it can be enabled in `imav.conf`. Background scanning is disabled because cron does it, and the free edition can only do monthly anyway.

## 6. Dependencies

| Tool | Why | Package |
|---|---|---|
| `imunify-antivirus` | engine | Imunify repository, installer |
| `jq` | JSON in bash commands and the hook | `jq` |
| `curl` | API calls, archive downloads | `curl` |
| `unzip` | original WordPress archives | `unzip` |
| `mcedit` | interactive mode (optional) | `mc` |
| `v-search-domain-owner`, `v-get-database-credentials-of-domain`, `v-list-web-domain`, `main.sh` functions | myVesta | `/usr/local/vesta` |

## 7. Security

- The hook runs as `_imunify` and never gets root or any access to `/usr/local/vesta/conf`; all it does is drop the event JSON into a spool directory it cannot list. Delivery, and therefore reading of tokens and addresses from `imav.conf`, happens in `v-imav-notify-send` as root, started by systemd. No myVesta file or directory permission is changed.
- Remediate never deletes; it moves to quarantine or replaces with an original after a backup.
- Original WordPress archives are downloaded only from `wordpress.org` and `downloads.wordpress.org` over HTTPS.
- Reports do not go into `public_html` unless explicitly enabled.
- Sending infected files to the Imunify team for analysis is off until enabled in the configuration.

## 8. Open questions (to verify on the test server)

1. Exact JSON shape of `malware on-demand start`, `on-demand status` and `on-demand list` (field names, status values).
2. Whether `malware malicious list --by-scan-id` returns all findings of the scan or only the first 50 without `--limit`.
3. Behaviour of `on-demand queue put` with 200 paths in one call.
4. Whether `--path` with a glob works for `/home/*/web/*/public_html`.
5. Which field in the `notifications-config` JSON carries the file list (`malicious_files` per the documentation example) and whether it includes the signature `type`.
6. Whether ImunifyAV works correctly without a served UI (`ui_path` pointing to an empty directory).
7. Duration of the first scan over `/home` on a server with about 100 sites, and of the second one (RapidScan).
