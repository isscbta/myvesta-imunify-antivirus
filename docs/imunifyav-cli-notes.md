# ImunifyAV CLI: verified notes

Source: official documentation (`docs.imunify360.com/imunifyav/`, markdown in `github.com/cloudlinux/imunify360-documentation`, directory `docs/imunifyav/`), read on 24 September 2026. The section "Measured" is filled in with real output from the test server.

The ImunifyAV web UI is not used in this project; everything is done from the console. UI-related settings (`ui_path`, PAM, `login get`) are listed only because the installer requires `ui_path` to exist.

## Installation (stand-alone, no panel)

Supported OS for stand-alone: Debian 11, 12, 13; Ubuntu 22.04, 24.04, 26.04; AlmaLinux 8, 9, 10; Rocky 8, 9; CentOS/RHEL/CloudLinux 7, 8, 9. Hardware: 512 MB RAM, 20 GB disk, x86_64.

Before the installer, `/etc/sysconfig/imunify360/integration.conf` with `ui_path` is mandatory. The web UI is a SPA served by a web server; if the UI is not used, the path can be an empty directory.

```ini
[paths]
ui_path = /opt/imunifyav-ui
```

Optional keys:

```ini
[paths]
ui_path_owner = user:group        ; chown of UI files after installation

[pam]
service_name = system-auth        ; PAM service for UI login

[integration_scripts]
panel_info = /path/get-panel-info.sh ; JSON {"data": {"name": "...", "version": "..."}}, mandatory (installer warns without it)
admins  = /path/get-admins.sh     ; JSON list of admins
users   = /path/get-users.sh      ; JSON list of users (otherwise login.defs uid_min..uid_max)
domains = /path/get-domains.sh    ; JSON map domain -> document_root, owner, is_main
```

Seen on the test server (installer 2.155, agent 8.8.6, Debian 12): `WARNING: integration_scripts.panel_info field will be mandatory soon`, and `cp: cannot stat '/etc/sysconfig/imunify360/imunify360.config.defaults.example'` from the Imunify installer itself.

`users` JSON format:

```json
{"data": [{"id": 1000, "username": "user1", "owner": "root", "domain": "user1.com",
           "package": {"name": "default", "owner": "root"}, "email": "x@y", "locale_code": "EN_us"}],
 "metadata": {"result": "ok"}}
```

`domains` JSON format:

```json
{"data": {"example.com": {"document_root": "/home/user1/web/example.com/public_html/",
                          "is_main": true, "owner": "user1"}},
 "metadata": {"result": "ok"}}
```

Installer:

```bash
wget https://repo.imunify360.cloudlinux.com/defence360/imav-deploy.sh -O imav-deploy.sh
bash imav-deploy.sh            # free ImunifyAV
bash imav-deploy.sh --key KEY  # ImunifyAV+
bash imav-deploy.sh -h         # options
imunify-antivirus register KEY # register a license later
```

The stand-alone UI needs PHP with `proc_open` and access to the socket `/var/run/defence360agent/non_root_simple_rpc.sock`; not relevant if the UI is not used.

## Global options

```
imunify-antivirus [command] [--json] [--verbose|-v] [--console-log-level {ERROR,WARNING,INFO,DEBUG}]
```

`--json` returns JSON, `-v` with `--json` pretty-prints it.

## Commands

| Command | Description |
|---|---|
| `version` | agent version |
| `update` | update signatures |
| `rstatus` | license check |
| `register KEY` / `unregister` | license |
| `update-license` | force license refresh |
| `config update '{"SECTION": {"param": value}}'` | change configuration |
| `doctor` | diagnostics, sent to the Imunify team |
| `checkdb` | integrity of the agent's local database |
| `infected-domains` | list of infected domains (works with the `domains` integration) |
| `feature-management` | features available to users (AV+) |
| `notifications-config show\|update` | events and scripts |
| `hook add\|delete\|list --event E --path P` | old mechanism, marked deprecated |
| `submit false-positive\|false-negative` | report a file to the Imunify team |
| `login get --username U` | token for the stand-alone UI |
| `malware ...` | everything around scanning, see below |

## `malware` commands

```
malware on-demand start --path PATH [--file-mask M] [--ignore-mask M] [--follow-symlinks|--no-follow-symlinks]
                                    [--intensity-cpu 1..7] [--intensity-io 1..7]
malware on-demand status
malware on-demand stop [--all]           # --all also clears the queue
malware on-demand list                   # history of on-demand scans with scan_id
malware on-demand queue put PATH [PATH...] [same options as start]
malware on-demand queue remove SCAN_ID [SCAN_ID...]

malware malicious list [--user U] [--by-scan-id ID] [--by-status S...] [--limit N] [--offset N]
                       [--since D] [--to D] [--order-by ...] [--items ...] [--search Q]
malware malicious cleanup ...            # AV+
malware malicious cleanup-all            # AV+
malware malicious diff --id ID           # base64 unified diff infected/cleaned
malware malicious restore-original ...
malware malicious restore-from-backup ...
malware malicious move-to-ignore ...
malware malicious remove-from-list ...

malware suspicious list                  # documented, but NOT present in 8.8.6 (see below)
malware suspicious move-to-ignore

malware ignore add PATH [PATH...]        # absolute paths, files or directories
malware ignore delete PATH [PATH...]
malware ignore list

malware user list                        # all users and their infection status
malware user scan                        # scan all users
malware user cleanup USER                # AV+
malware user restore-original USER

malware history list [--limit N ...]
malware cleanup status
malware rebuild patterns
```

Notes from the documentation:

- `--path` accepts a glob: `--path='/var/www/vhosts/d*' --ignore-mask='/var/www/vhosts/x.com/*,/var/www/vhosts/y.com/*'`.
- `queue put` accepts several paths and `--file-mask="*.php"`.
- A successful `start`, `stop`, `ignore add` prints `OK`.
- `malicious list` returns 50 records by default (`--limit` for more). Columns: `CLEANED_AT CREATED EXTRA_DATA FILE HASH ID MALICIOUS SCAN_ID SCAN_TYPE SIZE STATUS TYPE USERNAME`. `SCAN_TYPE` is `on-demand` or `background`. `TYPE` is the signature name, for example `SMW-SA-05057-eicar.tst-4`, `SMW-INJ-04174-bkdr`, `SMW-INJ-04346-js.inj`. `STATUS` values seen in examples: `found`, `cleanup_done`, `cleanup_removed`.
- `malicious diff --id N --json | jq .diff -r | base64 --decode` gives the diff.
- Measured on 8.8.6: the `malware` subcommands are `cleanup, history, ignore, malicious, on-demand, read, rebuild, rescan, send, user`; `malware suspicious` does not exist despite the documentation.
- Measured detection gap on 8.8.6: an 83-byte file `<?php eval($_POST['...']??'http_response_code(404);');` in `wp-content/fun-<hex>/` was not detected (full scan of 32780 files and a targeted scan), while a fake plugin `media-optimization-core-<hex>` was (`SMW-INJ-2039082-php.bkdr.wshll-0`). Wordfence CLI flagged both (`Backdoor:PHP/EvalSuperGlobal.B`). Such files are reported to Imunify with `imunify-antivirus submit false-negative FILE`, which is how the signature base is meant to improve; the project does not add its own content patterns. Measured turnaround: the file was submitted on 27 September 2026 and detected on 30 September 2026 as `SMW-BLKH-SA-CLOUDAV-php.bkdr-NP252-3` (cloud-assisted detection), so a false-negative report takes effect within about three days without any update on the server.

## Configuration (`imunify360.config`)

File: `/etc/sysconfig/imunify360/imunify360.config`, since v5.8 a link to `imunify360.config.d/90-local.config`. Changed with `config update`.

Relevant sections and defaults:

```yaml
MALWARE_SCANNING:
  max_signature_size_to_scan: 1048576      # bytes, standard mode
  max_cloudscan_size_to_scan: 10485760     # bytes, cloud-assisted by hash
  max_mrs_upload_file: 10485760
  detect_elf: False                        # ELF binaries in home directories = malware
  sends_file_for_analysis: True            # send files to the Imunify team
  cloud_assisted_scan: True
  rapid_scan: True
  rapid_scan_rescan_unchanging_files_frequency: null   # null = by schedule (month 1, week 5, day 10)
  hyperscan: True                          # needs SSE3
  crontabs: True                           # scan crontab files
  prioritize_user_on_demand_scans: False
MALWARE_SCAN_INTENSITY:
  cpu: 2      # 1..7
  io: 2       # 1..7
  ram: 2048   # min 1024
MALWARE_SCAN_SCHEDULE:
  interval: month     # none | day | week | month, lowercase (day and week are AV+ only);
                      # "NONE" is rejected with "unallowed value NONE" (measured on 8.8.6)
  day_of_month: <day after installation>
  day_of_week: 0
  hour: 3
MALWARE_CLEANUP:
  trim_file_instead_of_removal: True
  keep_original_files_days: 14
ERROR_REPORTING:
  enable: True
```

On systems other than CloudLinux the intensity is enforced with `nice` and `ionice` (ionice only with the CFQ scheduler).

## Events and notifications

New mechanism: `notifications-config`. Settings in `/etc/sysconfig/imunify360/hooks.yaml`. In ImunifyAV/AV+ the only target is `SCRIPT` (no `ADMIN` email target). All events are off by default.

Events:

| Event | When |
|---|---|
| `CUSTOM_SCAN_STARTED` | on-demand scan started |
| `CUSTOM_SCAN_FINISHED` | on-demand scan finished (with or without findings) |
| `CUSTOM_SCAN_MALWARE_FOUND` | on-demand scan finished and found malware |
| `USER_SCAN_STARTED` / `USER_SCAN_FINISHED` / `USER_SCAN_MALWARE_FOUND` | per-user scan (the scheduled background scan reports itself as USER_SCAN) |

`REALTIME_MALWARE_FOUND` and `SCRIPT_BLOCKED` are Imunify360 and do not exist in AV.

Registering a script:

```bash
imunify-antivirus notifications-config update \
  '{"rules": {"CUSTOM_SCAN_MALWARE_FOUND": {"SCRIPT": {"scripts": ["/usr/local/vesta/bin/v-imav-notify-hook"], "enabled": true}},
              "USER_SCAN_MALWARE_FOUND":   {"SCRIPT": {"scripts": ["/usr/local/vesta/bin/v-imav-notify-hook"], "enabled": true}}}}'
imunify-antivirus notifications-config show
```

The script runs as the user `_imunify`. It must be executable and reachable through every directory on its path; nothing under `/root` works (error `fork/exec ...: permission denied`, the event is silently dropped). Recommendation from the documentation:

```bash
mkdir -p /opt/imunify-hooks
chown root:_imunify /opt/imunify-hooks /opt/imunify-hooks/script.sh
chmod 750 /opt/imunify-hooks /opt/imunify-hooks/script.sh
```

In this project the hook is `/usr/local/vesta/bin/v-imav-notify-hook`, world-readable and executable like every myVesta command, which satisfies the requirement.

The payload on stdin is JSON. Fields according to the reference script of the Imunify team (`hook_script.sh`):

| Event | Fields |
|---|---|
| `*_SCAN_STARTED` | `event_id`, `scan_id`, `started` |
| `*_SCAN_FINISHED` | `event_id`, `scan_id`, `started`, `completed`, `total_malicious`, `malicious_files[]` |
| `*_SCAN_MALWARE_FOUND` | `event_id`, `started`, `completed`, `total_malicious`, `malicious_files[]` |

The older `hook add --event malware-detected` mechanism gives a richer JSON (`scan_id`, `path`, `total_files`, `total_malicious`, `files[]` with `file`, `type`, `status`, `username`, `hash`, `size`), but is marked deprecated. Its log is `/var/log/imunify360/hook.log`. If the new mechanism does not include the signature name in the payload, the hook can fetch it with `malware malicious list --by-scan-id`.

## What is AV+ (paid)

- `malware malicious cleanup`, `cleanup-all`, `malware user cleanup` (automatic cleanup)
- background scan `DAY` and `WEEK` (`MONTH` works in the free edition)
- Features Management, Reputation Management (UI)
- Malware Database Scanner (MDS) does not exist even in AV+, only in Imunify360

## Paths on the server

| Path | What |
|---|---|
| `/usr/bin/imunify-antivirus` | CLI |
| `/var/run/defence360agent/` | agent socket |
| `/etc/sysconfig/imunify360/` | `imunify360.config`, `imunify360.config.d/`, `integration.conf`, `hooks.yaml`, `auth.admin` |
| `/var/log/imunify360/` | agent logs, `hook.log` |
| `/var/imunify/tmp/hooks/` | temporary JSON files for hooks (old mechanism) |

## Measured on the test server

Fill in with real outputs. While empty, code is written on the assumptions from the documentation.

Every `--json` answer is wrapped in an envelope with `items`, `warnings`, `version`, `eula` and `license` (the same object as `rstatus`). The payload is always under `items`.

### `malware on-demand start --path ... --json`

Returns no scan id: `{"items": null, "warnings": [], "version": "8.8.6", ...}`, exit code 0. The id must be read from `on-demand list`, where the new scan appears within a second or two.

### `malware on-demand status --json`

While a scan runs:

```json
{"items": {"status": "running", "path": "/home/user/web/example.com/public_html",
           "scanid": "c3d336e3535b45ceb24e12a02d15f191", "started": 1790433760.86, "created": 1790433760,
           "scan_type": "on-demand", "resource_type": "file",
           "intensity_cpu": 2, "intensity_io": 2, "intensity_ram": 2048, "initiator": null,
           "file_patterns": null, "exclude_patterns": null, "follow_symlinks": false, "detect_elf": null,
           "phase": "preparing file list", "progress": 0, "queued": 0}, ...}
```

When idle: `{"items": {"queued": 0, "status": "stopped"}, ...}`.

### `malware on-demand list --json`

```json
{"max_count": 1, "items": [
  {"scanid": "c3d336e3535b45ceb24e12a02d15f191", "path": "/home/user/web/example.com/public_html",
   "scan_status": "stopped", "scan_type": "on-demand", "resource_type": "file",
   "started": 1790433760, "created": 1790433760, "completed": 1790433770, "duration": 10,
   "error": null, "total_resources": 0, "total_malicious": 0, "total": 0}], ...}
```

The key is `scanid` (not `scan_id`). A running scan has `scan_status: "running"` and `completed: null`; a finished one has `scan_status: "stopped"` and a `completed` timestamp. `error` is a string when the scan failed.

### `malware malicious list --json`

`{"max_count": N, "items": [...], "malicious_count": N, ...}`. One item (EICAR test file created by root):

```json
{"id": 1, "username": "0",
 "file": "/home/wprocket/web/example.com/public_html/imav-eicar-raw.php",
 "created": 1790434684, "scan_id": "04709f7ed9d143efb1a17caf56194553", "scan_type": "on-demand",
 "resource_type": "file", "type": "SMW-BLKH-SA-CLOUDAV-eicar.tst-05057-2",
 "hash": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "size": "68",
 "malicious": true, "status": "found", "cleaned_at": null, "extra_data": {},
 "db_name": null, "app_name": null, "db_host": null, "db_port": null, "snippet": null, "table_fields": []}
```

Notes: here the key is `scan_id` (in the on-demand list it is `scanid`); `size` is a string; `username` is the file owner, `"0"` for a root-owned file, so `--user USER` does not return root-owned findings. A finding disappears from the list on its own after a rescan no longer detects the file; when the file is deleted without a rescan the entry stays until `malware malicious remove-from-list ID [ID ...]` (positional ids, or `--items`). EICAR is detected by the hash of the whole 68-byte file (`SMW-BLKH-SA-CLOUDAV-eicar.tst`), so EICAR embedded in other content is not a valid test. A PHP backdoor exported from a database row (`<?php if(isset($_POST["cmd"])){ eval(base64_decode($_POST["cmd"])); } ?>` in a `.php` file under `/usr/local/vesta/data/imav/dbscan/`) was detected as `SMW-INJ-22143-php.bkdr.wshll-2`, so paths outside `/home` are scanned normally.

### `malware ignore list --json`

```json
{"max_count": 3, "items": [{"id": 1, "path": "/proc", "resource_type": "file", "added_date": 1790432798},
                           {"id": 2, "path": "/sys", ...}, {"id": 3, "path": "/usr/share/cagefs-skeleton/proc", ...}]}
```

A fresh installation already ignores `/proc`, `/sys` and the CageFS skeleton.

### `malware malicious list --by-scan-id ID --json`

```
(not measured)
```

### `rstatus --json` (free license)

Measured on 8.8.6, Debian 12, 26 September 2026 (ids shortened):

```json
{"status": true, "expiration": null, "user_limit": -1, "id": "IMUNIFYAV", "user_count": 4,
 "message": "", "license_type": "imunifyAV",
 "upgrade_url": "https://cln.cloudlinux.com/console/purchase/ImunifyAvPlus",
 "upgrade_url_360": "https://www.cloudlinux.com/upgrade-imunify-30/?iaid=...&users=4",
 "ip_license": false, "eligible_for_imunify_patch": false, "warnings": [], "version": "8.8.6",
 "license": {"status": true, "license_type": "imunifyAV", "id": "IMUNIFYAV", ...}}
```

`license_type` is the field to check; the upgrade URLs contain "ImunifyAvPlus" even on the free license.

### `config show --json` (free license, 8.8.6)

Sections present: `ADMIN_CONTACTS`, `BACKUP_RESTORE`, `CONTROL_PANEL`, `DASHBOARD`, `ERROR_REPORTING`, `LOGGER`, `MALWARE_CLEANUP`, `MALWARE_DATABASE_SCAN`, `MALWARE_SCANNING`, `MALWARE_SCAN_INTENSITY`, `MALWARE_SCAN_SCHEDULE`, `MOD_SEC_BLOCK_BY_CUSTOM_RULE`, `MY_IMUNIFY`, `PAM`, `PATCHMAN`, `PERMISSIONS`, `PROACTIVE_DEFENCE`, `RESOURCE_MANAGEMENT`, `SEND_ADDITIONAL_DATA`, `WEBSHIELD`, `WORDPRESS`.

`MALWARE_SCANNING` defaults seen: `default_action: cleanup`, `detect_admin_tools: true`, `enable_scan_inotify: true`, `max_cloudscan_size_to_scan: 104857600`, `max_targets_per_scan_type: 100000`, `scan_modified_files: null`, `try_restore_from_backup_first: false`, `sends_file_for_analysis: false`.
`MALWARE_SCAN_INTENSITY`: `cpu 2, io 2, ram 2048, resident_ram 2048, user_scan_cpu 2, user_scan_io 2, user_scan_ram 1024`.
`MALWARE_DATABASE_SCAN: {"db_timeout": 15, "enable": true}` is present even though the documentation lists MDS as Imunify360 only; whether it does anything on the free edition is still to be checked.
`RESOURCE_MANAGEMENT: {"cpu_limit": 2, "io_limit": 2, "ram_limit": 500}`.

`config update` returns exit code 11 and a Python-style dict with the validation error when a value is rejected, and the full config on success.

### `notifications-config show --json`

```json
{"items": {"rules": {"CUSTOM_SCAN_FINISHED": {"SCRIPT": {"enabled": false, "scripts": []}},
                     "CUSTOM_SCAN_MALWARE_FOUND": {"SCRIPT": {"enabled": true, "scripts": ["/usr/local/vesta/bin/v-imav-notify-hook"]}},
                     ...}},
 "warnings": [], "version": "8.8.6", "eula": null, "license": {...}}
```

### `CUSTOM_SCAN_MALWARE_FOUND` payload

```
(not measured)
```

### Duration of a `/home` scan

| Server | Sites | Files | First scan | Second scan (RapidScan) | CPU/IO intensity |
|---|---|---|---|---|---|
| test, Debian 12, 2 cores, 3.8 GB RAM | 4 accounts, 8 domains | small | 43 s | 46 s (too small for RapidScan to matter) | 2/2 |

Other measurements on the same server: a single small WordPress domain scans in about 18 s, an incremental scan of files changed in the last 60 minutes under `/home` (queue put in batches) in 34 s. The agent reports the phases `preparing file list` and `ai-bolit scanning` with a percentage.
