# Changelog

## Unreleased

- Report levels recalibrated so that CRITICAL means a likely compromise or an exposed secret: PHP files in `wp-content/uploads` are WARNING (plugin data directories listed in `REPORT_UPLOADS_PHP_DIRS` are INFO), code hidden in image or text files stays CRITICAL; `.htaccess` is CRITICAL only for `auto_prepend_file` and PHP handlers on non-PHP extensions, the `cgi-script` + `Options -ExecCGI` hardening recipe and PHP handlers for `.php` are no longer flagged; vulnerability level follows the CVSS only; archives count only in the root of the document root and PHP error logs are INFO; CloudLinux leftovers (`.cagefs`, `.cl.selector`, `.rnd`) and symbolic links inside the home directory are no longer warnings.
- The administrators check no longer treats an email on the domain of the site, or logins containing dev/temp/tmp, as suspicious.
- Security plugin directories (`wflogs`, `imunify-security`, `aiowps_backups`, `ai1wm-backups`, `updraft`, `backups-dup-lite`, `backup-guard`, `wpvividbackups`) are known locations in `wp-content`.
- New unit test `test/test-report-checks.sh` for the file-based report checks.

## 1.0.0 (2026-10-02)

First release.

- Malware scanning with ImunifyAV: `v-imav-malware-scan`, `v-imav-scan-path`, `v-imav-scan-all`, `v-imav-list-infected`, ignore list commands.
- Vulnerability detection for WordPress core, plugins and themes from the WPVulnerability database and, optionally, the Wordfence Intelligence feed: `v-imav-vuln-scan`.
- Remediation: `v-imav-remediate` restores core, plugin and theme files from wordpress.org or quarantines them; `v-imav-malware-scan-with-remediate` with an interactive mode.
- WordPress database scan: `v-imav-db-scan`.
- Security reports per domain with a status per check, as text and HTML, sent by email: `v-imav-report-domain`; registry of monitored domains with an hourly runner: `v-imav-add-monitor` and related commands, `v-imav-run-monitors`.
- Alerts on every ImunifyAV finding through a spool and a systemd path unit, by email and optionally Telegram.
- Installer, updater and uninstaller; unit and smoke tests; architecture and ImunifyAV CLI documentation.
- WordPress detection covers sites with `wp-config.php` one level above the document root and damaged installations whose `wp-includes/version.php` is gone; a missing core is reported as CRITICAL instead of skipping the WordPress checks.
- The administrators check flags accounts with the traits of planted accounts: reserved email domains, random logins, logins built from words such as backup, seo, support or wpadmin, and emails on the domain of the site itself.
- Mail through sendmail or the Mailgun API, configured entirely in `imav.conf`; the installer asks for the transport, the Mailgun key and sending domain, and the default recipient, or takes them from command line options for unattended installation.
