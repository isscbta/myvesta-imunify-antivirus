# myvesta-imunify-antivirus

Malware scanning, vulnerability detection, remediation and scheduled security reports for websites hosted on [myVesta](https://github.com/myvesta/vesta) servers, built on [ImunifyAV](https://www.imunify360.com/antivirus) and public WordPress vulnerability databases.

The project adds a set of `v-imav-*` commands to a myVesta server. They scan a domain, a path or the whole server for malware with ImunifyAV, check WordPress core, plugins and themes against known vulnerabilities, restore infected WordPress files from the official archives or move them to quarantine, scan the WordPress database, and send a complete security report of a domain by email, once or on a daily schedule. Everything runs from the console; the ImunifyAV web interface is not used. The free edition of ImunifyAV is enough.

The project is made for myVesta and follows its conventions: commands live in `/usr/local/vesta/bin`, shared functions in `/usr/local/vesta/func`, configuration in `/usr/local/vesta/conf`, every command has the myVesta script structure, positional parameters with an optional `FORMAT` (`shell`, `json`, `plain`, `csv`), and the standard exit codes.

## Contents

- [How it works](#how-it-works)
- [Installation](#installation)
- [Usage](#usage)
- [Scheduled security reports](#scheduled-security-reports)
- [Configuration](#configuration)
- [Notifications](#notifications)
- [Mail transport](#mail-transport)
- [Cron](#cron)
- [Free vs. ImunifyAV+](#free-vs-imunifyav)
- [Documentation](#documentation)

## How it works

```
operator / cron
      │
      ▼
/usr/local/vesta/bin/v-imav-*                 commands (bash, myVesta structure)
      │  source
      ▼
/usr/local/vesta/func/imav*.sh                shared functions
      │
      ├── imav.sh ──────────► imunify-antivirus     malware scan of a path, findings,
      │                       (ImunifyAV agent)     ignore list, scan history
      │
      ├── imav-vuln.sh ─────► WPVulnerability API   known vulnerabilities of the installed
      │                       Wordfence Intelligence  core, plugin and theme versions
      │                       (optional, free key)
      │
      ├── imav-remediate.sh ► wordpress.org         original files of the installed version;
      │                                             everything else goes to quarantine
      │
      ├── imav-db.sh ───────► MySQL                 suspicious rows exported to files and
      │                                             scanned by ImunifyAV, plus heuristics
      │
      ├── imav-report.sh ───► all of the above +    security report of a domain with a
      │                       checksums, updates,   status per check, as text and HTML
      │                       .htaccess, external
      │                       view, admins, cron...
      │
      └── imav-mail.sh ─────► sendmail / Mailgun    delivery of reports and alerts

ImunifyAV agent ──(malware found)──► v-imav-notify-hook ──► spool ──► v-imav-notify-send ──► mail
```

ImunifyAV scans asynchronously: the commands start a scan, wait for the agent to finish (progress is shown), then read the findings for that scan and write the report. Every command prints its result and saves a CSV in the `private/` directory of the domain (owned by the domain user, not web-accessible) and in the report history under `/var/log/myvesta-imav/reports/`.

## Installation

Requirements: myVesta on Debian 11, 12 or 13, root access. `jq`, `curl` and `unzip` are installed by the installer if missing.

```bash
cd /root && git clone https://github.com/isscbta/myvesta-imunify-antivirus.git && cd myvesta-imunify-antivirus && bash imav-install.sh
```

The installer:

1. Copies the commands to `/usr/local/vesta/bin/` and the functions to `/usr/local/vesta/func/`, creates `/usr/local/vesta/conf/imav.conf` with defaults (an existing file is kept and only new options are added).
2. Writes `/etc/sysconfig/imunify360/integration.conf` for the stand-alone ImunifyAV (an empty UI directory, plus scripts that give ImunifyAV the panel name and the list of myVesta users and domains), then downloads and runs the official ImunifyAV installer. This takes a few minutes; `--key KEY` passes an ImunifyAV+ license.
3. Applies the ImunifyAV settings (built-in background scan off, RapidScan and Hyperscan on, no upload of files for analysis) and registers the notification hook.
4. Asks for the mail transport (local sendmail or Mailgun, with its API key and sending domain) and the default recipient of alerts and reports.
5. Asks for an optional Wordfence Intelligence API key for a second vulnerability source (free, from a wordfence.com account), checks it and stores it.
6. Asks whether to install the nightly whole-server scan cron job (default: no).

Unattended installation, for example from Ansible:

```bash
bash imav-install.sh --mail-transport sendmail --email support@example.com --wf-key 'KEY' --cron no
```

Options: `--key`, `--wf-key`, `--email`, `--mail-transport sendmail|mailgun`, `--mailgun-key`, `--mailgun-domain`, `--cron yes|no`, `--no-hook`, `--no-imunify`, `--update`.

Update to the latest version (pulls the repository, re-installs the files, updates the ImunifyAV signatures):

```bash
bash /root/myvesta-imunify-antivirus/imav-update.sh
```

Check the installation on a real domain (an EICAR test file is scanned, reported and removed):

```bash
bash /root/myvesta-imunify-antivirus/test/smoke.sh example.com
```

Removal: `bash imav-uninstall.sh` removes the commands, functions, cron jobs and the notification service; `--purge-imunify` uninstalls ImunifyAV as well.

## Usage

All commands take the domain as the first argument; the owner and the document root come from myVesta. An optional last argument `FORMAT` (`shell`, `json`, `plain`, `csv`) selects the output format where listed.

### Malware scan

```bash
v-imav-malware-scan example.com
v-imav-malware-scan example.com json
```

Scans the document root of the domain with ImunifyAV and lists infected files with their signature. The report is saved as `private/imav-scan.csv`.

```bash
v-imav-scan-path /home/user/web 1440
```

Scans an arbitrary path (a glob is allowed). With a second argument only files changed in the last N minutes are scanned, limited to web extensions unless the third argument is `yes`. The environment variables `cmin`, `chour`, `cday`, `all` and `SCANPATH` are honoured as well, for existing cron jobs.

```bash
v-imav-scan-all
```

Scans the whole `/home` and prints a summary per user and domain. With `no` as the first argument it only starts the scan. This is what the optional nightly cron job runs.

### Findings and ignore list

```bash
v-imav-list-infected example.com
v-imav-list-infected
v-imav-add-ignore /home/user/web/example.com/public_html/wp-content/plugins/x/false-positive.php
v-imav-delete-ignore /home/user/web/example.com/public_html/wp-content/plugins/x/false-positive.php
v-imav-list-ignore
```

The findings ImunifyAV currently knows, for one domain or the whole server, without a new scan; and the list of paths ImunifyAV skips.

### Vulnerabilities

```bash
v-imav-vuln-scan example.com
```

Reads the installed WordPress core, plugin and theme versions from the files of the site (no wp-cli, no database) and checks them against the WPVulnerability database and, when `WF_API_KEY` is set, the Wordfence Intelligence feed. Prints the vulnerability, CVSS score, fixed version and source; the first line of the output says which sources were used. Components that are not on wordpress.org (custom or premium) are listed as not checked.

### Remediation

```bash
v-imav-remediate example.com dry-run
v-imav-remediate example.com
v-imav-malware-scan-with-remediate example.com
v-imav-malware-scan-with-remediate example.com interactive
```

`v-imav-remediate` takes the infected files ImunifyAV reports for the domain and, for WordPress core files and wordpress.org plugins and themes, replaces them with the original file of the installed version downloaded from wordpress.org (cached). Every other file is moved to `/srv/wp-quarantine/DOMAIN/`. Nothing is deleted, and a tar.gz of the affected files is made before any change. `dry-run` prints the plan only, `quarantine` quarantines everything without downloads. If an ImunifyAV+ license is active, the built-in cleanup is tried first.

`v-imav-malware-scan-with-remediate` scans and then remediates in one go. In `interactive` mode every infected file is shown with `stat`, opened in `mcedit`, and the operator decides whether to move it to quarantine.

### Database

```bash
v-imav-db-scan example.com
```

Exports every text value of the WordPress tables (posts, postmeta, options, comments, commentmeta, usermeta, termmeta) that could carry a payload into one file per row and has ImunifyAV scan them with its full signature set; only values that are too short or contain no markup, code, escape, entity or URL characters are skipped, so what counts as malicious is decided by the signatures, not by a fixed list of patterns. Rows larger than 1 MB cannot be checked by signatures and are listed separately. Heuristic checks follow: site URL pointing elsewhere, active plugins whose files are missing, administrators created recently, cron entries and scripts calling external hosts. The database is never modified.

## Scheduled security reports

`v-imav-report-domain` builds a complete security report of one domain and emails it. A registry of monitored domains and a single hourly cron job replace per-site cron lines.

```bash
v-imav-report-domain example.com                     # build, save and send to REPORT_EMAIL
v-imav-report-domain example.com client@example.com  # extra recipients (comma separated)
v-imav-report-domain example.com '' no               # build and save only
```

```bash
v-imav-add-monitor example.com client@example.com 9  # daily report at 09:00
v-imav-list-monitors
v-imav-change-monitor-email example.com client@example.com,agency@example.com 7
v-imav-suspend-monitor example.com
v-imav-unsuspend-monitor example.com
v-imav-delete-monitor example.com
```

Recipients are `REPORT_EMAIL` from `imav.conf` plus the addresses stored for the domain. The first `v-imav-add-monitor` installs `/etc/cron.d/myvesta-imav-monitor`, which runs `v-imav-run-monitors` every hour; the runner produces the reports due at that hour, one after the other.

The report is sent as HTML with a plain-text alternative, printed to the terminal, and saved as `imav-report.html` and `imav-report.txt` in the domain's `private/` directory and in the report history. It opens with a summary table where every check has a status, and the overall status goes into the subject: `[host][OK|INFO|WARNING|CRITICAL] Security report for DOMAIN [date]`.

| Check | CRITICAL when | WARNING when |
|---|---|---|
| Malware scan (ImunifyAV) | infected files found | |
| Unexpected locations in wp-content | | PHP in `wp-content` directories that nothing legitimate creates, plugin or theme directories with a random suffix |
| Known vulnerabilities | CVSS 9.0 or higher, or no fix available | CVSS 7.0 to 8.9 |
| Database scan | signature hit in a table row | heuristic finding |
| WordPress core integrity (official checksums) | modified or unknown files in `wp-admin`, `wp-includes` or the root | core files missing |
| Plugin integrity (wordpress.org checksums via wp-cli) | | plugin files differ from the release |
| Available updates | | WordPress core outdated (plugins and themes: INFO) |
| PHP files in unexpected places | PHP in `wp-content/uploads`, image or text files containing PHP | double extensions after `.php` |
| Backups, dumps and logs reachable over the web | database dump anywhere in the document root | archives, config copies, debug logs |
| `.htaccess` files | `auto_prepend_file`, handlers that make other files executable | redirects to external hosts |
| Site seen from outside | home page redirects to another domain, SSL certificate expired | site unreachable, HTTP 5xx, meta refresh, certificate expiring soon |
| WordPress administrators | | new administrator since the previous report, or registered in the last 30 days |
| Plugins | | (new and inactive plugins: INFO) |
| WordPress cron tasks | | (plugin and custom events listed for review) |
| Outgoing mail from this account | | more than `REPORT_MAIL_WARN` messages in 24 hours |
| PHP version | | PHP version past its end of life |
| Hidden files and symbolic links | | `.git`, `.svn`, `.env` in the document root; symlinks pointing outside it |
| Directory sizes and file count trend | | more than `REPORT_FILE_GROWTH_WARN` new files since the previous report |
| PHP files in the root directory | | non-standard PHP files in the WordPress root |
| Recently modified PHP files | | (for reference) |

The report starts with a note that malware scanning is done by ImunifyAV and vulnerability detection by the WPVulnerability database and, when configured, the Wordfence Intelligence feed, and that no scanner can guarantee 100% detection.

## Configuration

File `/usr/local/vesta/conf/imav.conf`, myVesta `KEY='value'` format, created by the installer with the defaults from `files/usr/local/vesta/conf/imav.conf`.

| Option | Default | Description |
|---|---|---|
| `ALERT_EMAIL` | empty | Recipient of the alert sent on every malware finding |
| `REPORT_EMAIL` | empty | Default recipient of security reports (always included, per-domain addresses are added) |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | empty | Optional Telegram channel for alerts |
| `MAIL_TRANSPORT`, `MAIL_FROM`, `MAIL_FROM_NAME`, `MAILGUN_API_KEY`, `MAILGUN_DOMAIN`, `MAILGUN_FROM`, `MAILGUN_API_URL` | `sendmail`, `myVesta Imunify Antivirus` | See [Mail transport](#mail-transport) |
| `WF_API_KEY` | empty | Wordfence Intelligence v3 key; adds the Wordfence feed to the vulnerability sources |
| `VULN_CACHE_TTL`, `VULN_SHOW_INFORMATIONAL` | `86400`, `no` | Cache time of vulnerability data; whether informational entries are shown |
| `SCAN_INTENSITY_CPU`, `SCAN_INTENSITY_IO` | `2` | ImunifyAV scan intensity, 1 (lowest) to 7 |
| `SCAN_TIMEOUT`, `SCAN_PROGRESS_INTERVAL` | `21600`, `15` | Maximum wait for a scan in seconds; progress refresh |
| `REPORT_IN_DOMAIN_DIR` | `private` | Where per-domain reports go: `private`, `public_html` or `none` |
| `REPORT_HISTORY_DIR`, `REPORT_KEEP_DAYS` | `/var/log/myvesta-imav/reports`, `90` | Report history and retention |
| `REPORT_FILE_GROWTH_WARN`, `REPORT_MAIL_WARN`, `REPORT_SSL_WARN_DAYS`, `REPORT_NEW_ADMIN_DAYS` | `500`, `500`, `14`, `30` | Thresholds of the report checks |
| `QUARANTINE_DIR`, `BACKUP_DIR`, `CACHE_DIR` | `/srv/wp-quarantine`, `/usr/local/vesta/data/imav/backups`, `/var/cache/imav` | Quarantine, pre-remediation backups, download cache |
| `REMEDIATE_USE_IMUNIFY_CLEANUP` | `yes` | Try the ImunifyAV+ cleanup first when a license is active |
| `IMUNIFY_SEND_FILES_FOR_ANALYSIS`, `IMUNIFY_DETECT_ELF`, `IMUNIFY_KEEP_ORIGINAL_DAYS` | `no`, `no`, `30` | ImunifyAV settings applied by the installer |

## Notifications

ImunifyAV runs a hook after every scan that found malware, including the nightly whole-server scan. The hook (`v-imav-notify-hook`) runs as the unprivileged `_imunify` user, which has no access to `/usr/local/vesta/conf`; it only writes the event into `/var/spool/myvesta-imav`. The systemd path unit `myvesta-imav-notify.path` then runs `v-imav-notify-send` as root, which reads `imav.conf`, sends the email to `ALERT_EMAIL` and the optional Telegram message, and removes the spool file. No myVesta permissions are changed.

The events used are `CUSTOM_SCAN_MALWARE_FOUND` (on-demand scans, which is what all `v-imav-*` commands run) and `USER_SCAN_MALWARE_FOUND` (ImunifyAV background scans, if enabled).

## Mail transport

Alerts and reports use the transport set in `imav.conf`:

- `MAIL_TRANSPORT='sendmail'`: the local Exim, sender `MAIL_FROM` (default `imav@hostname`) shown with the display name `MAIL_FROM_NAME` (default `myVesta Imunify Antivirus`).
- `MAIL_TRANSPORT='mailgun'`: the Mailgun HTTP API, configured entirely in `imav.conf`: `MAILGUN_API_KEY`, the sending domain `MAILGUN_DOMAIN`, the sender `MAILGUN_FROM` (default `postmaster@MAILGUN_DOMAIN`) and `MAILGUN_API_URL` (default: the EU endpoint). `MAIL_FROM_NAME` is used as the display name here too.

The installer asks which transport to use; with Mailgun it also asks for the API key and the sending domain (or takes them from `--mailgun-key` and `--mailgun-domain`). When myVesta's own `/usr/local/vesta/conf/mailgun.conf` exists, its values are used for the settings that are still empty.

## Cron

Two cron jobs exist, both optional:

- `/etc/cron.d/myvesta-imav`: nightly `v-imav-scan-all` at 03:00. The installer asks whether to install it (`--cron yes|no` answers without asking). Free ImunifyAV has a built-in background scan only monthly; this job gives a daily one. Thanks to RapidScan it only touches changed files plus a small share of unchanged ones.
- `/etc/cron.d/myvesta-imav-monitor`: hourly `v-imav-run-monitors`, installed by the first `v-imav-add-monitor`.

## Free vs. ImunifyAV+

| Feature | ImunifyAV (free) | ImunifyAV+ |
|---|---|---|
| File scanning, all signatures, Hyperscan, RapidScan | yes | yes |
| On-demand scan from the CLI, no limit | yes | yes |
| Ignore list, history, findings list, events | yes | yes |
| Automatic signature-based cleanup (`malware malicious cleanup`) | no | yes |
| Daily or weekly built-in background scan | no (monthly only) | yes |

The project is designed for the free edition: remediation restores original files from wordpress.org and quarantines the rest, and the nightly scan comes from cron. With an ImunifyAV+ key, `v-imav-remediate` tries the built-in cleanup first.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): layout on the server, shared functions, flow of every command, design decisions
- [docs/imunifyav-cli-notes.md](docs/imunifyav-cli-notes.md): ImunifyAV CLI syntax, configuration keys, event payloads and JSON output as measured on a real server
- [CHANGELOG.md](CHANGELOG.md)
- myVesta conventions: https://github.com/myvesta/vesta/tree/master/.cursor/rules
- ImunifyAV documentation: https://docs.imunify360.com/imunifyav/
- WPVulnerability API: https://docs.wpvulnerability.com/
- Wordfence Intelligence v3 feed: https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/
