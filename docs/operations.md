# Operating netrescale

## Dashboard access

The `netrescale-web` service is separate from the appliance-monitoring daemon. It listens
on `127.0.0.1:8080` by default. Use an SSH tunnel/VS Code forwarding, or an HTTPS reverse
proxy with `web.public_url` configured. Temporary direct HTTP is an explicit opt-in for
trusted internal networks via `netrescale web allow-http`; it is not enabled by default.

`sudo netrescale web allow-http --host <server-ip> --allow-network <client-cidr> --restart`
backs up config, binds the server address, enables HTTP, and adds the client network to a
dedicated systemd drop-in. Repeat `--allow-network` as needed. Existing firewall rules are
not modified; both the host firewall and systemd allowlist must permit the client. HTTP
transmits passwords, session cookies, and submitted credentials unencrypted. Read-only
NetScaler access and appliance TLS pinning are unchanged.

```bash
sudo netrescale web user-set admin
sudo systemctl enable --now netrescale-web
sudo systemctl status netrescale-web
journalctl -u netrescale-web -n 50
```

`web user-set` prompts for a password; there are no initial/default credentials. Web users
and Argon2id hashes are stored in `/var/lib/netrescale/web-users.json` (0600, service user).
Administrators can manage settings, users, vault entries and maintenance. Operators can run
read-only probes/hunts and queue notification tests; viewers can only inspect dashboard data.
No role can retrieve stored appliance passwords or perform mutating NITRO calls through the UI.
Reset a password with `web user-set <name>`; existing sessions are invalidated immediately.
Sessions expire after eight hours by default. Saving settings preserves existing sessions
unless web access or session settings change. A full web service restart invalidates all sessions.
Five failed logins from an address trigger a five-minute throttle; do not repeatedly retry.

Include the web user file in protected state backups. The UI shows cached monitoring status,
not a direct appliance probe. The browser's `Send test` queues a notification; confirm receipt
at the destination. The sample-data `web preview` command is never a substitute for live checks.

The web sandbox reads state/configuration, has no systemd vault credential, and masks the
default vault and raw archive paths. If you customize storage paths, update its inaccessible
paths as well. Remote PostgreSQL requires a deliberate web-unit egress override; the default
unit allows only local communication.

## Syslog transport and network exposure

rsyslog receives NetScaler syslog over **plain TCP** (`imtcp`, no TLS). Anyone on the network
path can read or inject log lines, so the syslog network is part of the trust boundary:

- Keep the NetScaler-to-netrescale syslog path on an isolated management network.
- Apply the nftables rules from `netrescale rsyslog-config --nft`. Without them, any host that
  can reach 514/tcp can write to the quarantine file. `install.sh` installs a logrotate rule
  (`/etc/logrotate.d/netrescale-syslog`) that caps that file at 50 MB x 3, but it is a
  safety net, not a substitute for the firewall.
- Treat injected lines as untrusted: detection rules never evaluate log content, but a
  forged line from an allowlisted source address can still raise or mask findings.

## Dashboard authentication

The dashboard has local accounts only (no MFA or SSO). If it is reachable beyond loopback,
put it behind an HTTPS reverse proxy that enforces your organization's authentication (SSO or
client certificates), set `web.public_url`, and make the proxy overwrite `X-Forwarded-For`.
Login attempts are throttled per source address and per username.

## Production rollout (there is no lab appliance)

1. Run `sudo bash deploy/install.sh --verify-only` from the release checkout. It must report
  that the CLI, config, units, and database are verified.
2. Configure one secondary in `mode: observe`, notification sinks, syslog allowlists and the
  systemd egress drop-in. Pin its management TLS key and store its NITRO credential.
3. Run `sudo netrescale probe <device>` during a change window. This checks read-only NITRO
  permissions and response parsing; it does not run SSH or change appliance configuration.
4. Apply the printed syslog setup manually, activate the generated rsyslog configuration,
  and persist the inventory firewall rules. Start the service.
5. Confirm `systemctl is-active netrescale`, then wait for the first poll and require
  `sudo -u netrescale netrescale status` to report `healthy`.
6. Run `sudo -u netrescale netrescale notify test` and confirm actual delivery through every
  enabled sink. A queued notification is not delivery proof. Check `findings`,
  `config history`, and archive `search` output.
7. Verify real command, Gateway and shell-log formats against the rule pack. Then add the
  primary and remaining pairs in stages. Keep every device in observe mode in this release.

`status` is updated every ten seconds; it reports stale after sixty seconds without an
update. A PostgreSQL outage does not stop monitoring: the loops back off and retry, findings
the daemon generates are written to the local `findings.jsonl` first and queued for the
outbox when the database returns, and config-change findings stay pending in the poller state.
If PostgreSQL is unreachable at startup, the daemon stays in administration mode and repeats
the setup checks after 30 seconds, doubling up to every five minutes. Configuration errors
still wait for **Save settings** or a restart. Other worker failures stop the daemon so systemd
can restart it. The unit allows 10 starts in 15 minutes (`StartLimitBurst`,
`StartLimitIntervalSec`), so a crash loop ends in the `failed` state. Watch
`systemctl is-failed netrescale` (or add an `OnFailure=` notifier), fix the cause, then run
`sudo systemctl reset-failed netrescale` and start it. A singleton lock prevents
two daemons from consuming the same files. Password changes reload automatically; **Save settings**
activates changes in one request. Worker-bound changes refresh monitoring workers without
resetting credential lockout state or restarting the web app. Manual config edits can still
be activated with `sudo systemctl restart netrescale netrescale-web`.

## Monitoring the monitor

- **Log coverage per source.** `status --json` shows, per device, `syslog.sources` (lines and
  last receive time per source), `syslog.coverage`, and `syslog.missing_sources`: the expected
  source classes (ns.log, shell bash.log/sh.log, web access/error) with no line since the
  monitor started. The daily digest lists them under "LOG SOURCES NEVER RECEIVED" and is then
  MEDIUM. It says "All N device(s) polled OK" only when every expected source has arrived. The
  shell rules need `-managementlog` export. A quiet appliance may have no shell activity, and
  HA secondaries do not export management logs over TCP by default, so confirm the export with
  archive `search` rather than assuming. "unclassified" lines are in a log framing the parser
  does not recognise.
- **Quarantined syslog batches.** After three failed indexing attempts, a pending batch moves
  to `state_dir/pending/quarantine/` so new logs keep flowing. A CRITICAL
  `syslog-batch-quarantined` finding is raised, status shows a warning, and the digest lists
  it. The raw lines remain in the archive.
- **Failing notification sinks.** When a sink delivers nothing for 15 minutes after a queued
  notification first failed, a HIGH `notification-sink-failing` finding is sent straight to the
  other sinks (the outbox keeps it for any that do not accept it then), once per outage, and
  status becomes degraded. The outage ends at the sink's next successful delivery, with an info
  `notification-sink-recovered`. A single notification the sink keeps rejecting while others
  are delivered is counted in `undelivered_failures` but does not keep an outage open or hide a
  later one. With a single sink, only status, the web UI and the local findings log show it.
  The 15-minute clock restarts when the daemon restarts.
- **Coverage changes by administrators.** Pausing raises a HIGH `monitor-coverage-reduced`
  finding naming the web user; resuming raises an info `monitor-resumed`. Saving settings also
  raises `monitor-coverage-reduced` when it removes a device or a notification sink, disables
  syslog, raises the syslog silence threshold or the config probe interval, raises a sink's
  `min_severity`, changes a sink's destination (webhook URL; SMTP host, port, STARTTLS, sender
  or recipients; SIEM host, port, transport or CA bundle), adds entries to a non-empty
  `admin_networks`/`admin_users` allowlist or clears one, or changes a device's `nsip`,
  `nitro_port`, `spki_pin`, `spki_pinning`, `ca_bundle` or `syslog_sources` (or the device
  defaults for port and CA bundle), or disables file-integrity monitoring on a device, raises
  the FIM walk or re-hash interval, or lowers a FIM limit. A sink that is being removed or
  redirected gets the finding
  immediately through its old settings, before the change is applied, and never at its new
  destination. The finding names the changed settings, not their values.
- **Config-change attribution.** Changes are attributed from the ns.log management audit trail
  (CLI/GUI/API `CMD_EXECUTED`). Suppose ns.log lines have arrived from the device since the
  monitor started, but none in the last two minutes, or ingestion is failing. Running and saved
  configuration changes without attribution are then raised to at least HIGH, with "audit feed
  unavailable since <time>". The last ns.log receive time per device is kept in
  `state_dir/audit-feed.json`, so a settings reload or restart does not reset it. There is no
  such escalation when syslog is disabled, when ns.log has never been received from the device,
  or when NITRO (`show ha node`, `hacurmasterstate` Secondary or STAYSECONDARY) reports the
  device as the HA secondary. If the HA role cannot be read, the change is escalated.
- **Exposure.** The daily exposure check also reports exploited advisories whose exposure cannot
  be determined for the device's train (HIGH `exposure-unknown-*`), trains at end of
  maintenance (MEDIUM) or end of life (HIGH) (`exposure-lifecycle`, when the train or its
  status changes and then weekly, not daily), and advisory data older
  than 30 days (`exposure-data-stale`). `status --json` shows `advisory_data` and, per device,
  `exposure.posture`: worst status, lifecycle, minimum safe build and undetermined advisories.

## File-integrity monitoring (opt-in per device)

netrescale can watch the appliance filesystem through read-only NITRO `GET systemfile`
(listing, and reading small files to hash them). It never writes and never uses SSH. It never
requests file content under `/nsconfig/ssl`, `/nsconfig/keys`, `/flash/nsconfig/{ssl,keys}`,
`/var/core` or `/var/crash`, for key-like file names (`ssh_host_*`, `id_rsa*` and similar,
`*.key`, `*.pem`, `*.p12`, `*.pfx`, `*.ppk`), or in the SSH directories for anything but
`authorized_keys*` and `*.pub`. That deny list is hard-coded in `collect/fim.py` and cannot be
configured away.

- **Tier A, every config probe:** `/nsconfig` (`rc.netscaler`, `nsbefore.sh`, `nsafter.sh`),
  `/nsconfig/ssh`, `/var/pubkey/<user>`, `/var/cron/tabs`, `/etc/httpd.conf`, `/etc/crontab`.
  Content is hashed when the listing's size or mtime moves, and re-hashed at least every
  `defaults.fim.rehash_interval` (900 s), so an edit with a forged mtime is still caught.
- **Tier B, every `defaults.fim.webroot_interval` (600 s, 300-900):** web roots
  (`/var/netscaler/logon` incl. LogonPoint and themes, `/netscaler/ns_gui/vpn`,
  `/netscaler/ns_gui/epa/scripts`, `/var/vpn`, both portal template directories), staging
  directories (`/var/tmp`, `/tmp`, `/var/nstmp`), and crash artifacts (`/var/core`,
  `/var/crash`; metadata only). Each pass is bounded by `max_depth`, `max_entries`,
  `walk_seconds` for listing, another `walk_seconds` for reading, and `max_hashes` reads. New
  and moved files are hashed first and the rest of the budget re-hashes the web-root scripts
  checked longest ago. Tier A findings are recorded before Tier B starts, so a slow or failing
  web-root pass never delays or loses them.

Findings (category `sweep`): a boot hook, crontab or `authorized_keys` change, a new script
(`.php .phtml .xhtml .pl .py .sh .js .cgi`) in a web root, a hash-verified change to a web-root
script, and a known intrusion artifact path are CRITICAL. A new core or crash file, a new
script in a staging directory, an `httpd.conf` change and a web-root script change that could
only be seen on metadata are HIGH. Other web-root additions and changes are MEDIUM and
removals LOW. Each finding lists the files and says when a change was compared on listing
metadata only.

The first listing of each directory raises a MEDIUM `fim-baseline-recorded` with an inventory
(boot hooks, crontabs, SSH keys, web-root and staging scripts). This includes a subdirectory
that was refused or beyond a limit until now; a directory that is new on the appliance is a
change. Review the inventory on a known-good node: the baseline is not assumed clean. After a
firmware change (the build string from `show ns version` moved), web-root files and
`httpd.conf` are re-baselined in one HIGH `fim-rebaselined-after-upgrade` that lists the scripts
and configuration it accepted. Each watched directory leaves the re-baseline after the first
pass since the upgrade. Boot hooks, crontabs (including `/etc/crontab`, with a note that the
firmware changed), SSH keys, staging and crash directories are always reported normally.

**Coverage is never silent.** Each of these is a coverage gap:

- a directory the account may not list, or a listing error;
- a walk cut short by a limit;
- a refused, failed or unrequestable content read;
- content the hash budget has not reached yet ("content not hashed yet", for example while a
  large web root is first hashed, or "changed content not verified yet");
- a failed web-root pass;
- a refused `show ns version`.

A gap raises a `fim-coverage-unknown` health finding (HIGH when a Tier A path is affected, else
MEDIUM). It also shows as a status warning and a degraded state, and appears as "FILE INTEGRITY
COVERAGE UNKNOWN" in the digest. The finding is raised whenever a gap appears that has not been
reported yet; a shrinking set is recorded quietly, and `fim-coverage-restored` follows when no
gap is left. A walk-time-limit gap is cleared only after three web-root passes complete in
time, so marginal timing does not alternate the two. A file that waits for the hash budget for
more than six web-root passes after its listing moved is reported as modified, on metadata.

Only a watched directory itself may be missing: it is then treated as empty, so a later
`/var/pubkey/<user>/authorized_keys` is reported as added. A subdirectory or file that its
parent listed but that then reads as missing is a gap, never a removal. A pass that fails as a
whole (rejected or missing FIM credential, unreachable appliance) raises `fim-unavailable`.

To enable it on a device:

1. Run `sudo netrescale snippets <device> --server-ip <ip>` with `fim: {enabled: true}` set on
   the device. Apply the printed `nr_fim` account and its three command policies on the
   primary. A listing-only account (leave out `netrescale_fim_read`) works too: files are then
   compared on size and mtime only, and the refused reads are reported as a coverage gap.
2. `sudo netrescale cred set nr_fim`, then `sudo netrescale cred test nr_fim`.
3. Before the first rollout, run the read-only feasibility probe against a secondary of each
   firmware train (`tests/prod/test_fim_feasibility.py`, marker `prod_probe`). It records which
   paths the account may list and read and what a missing directory looks like on that build.
4. Set `fim: {enabled: true}` on the device and **Save settings**. Review the baseline
   finding.

```yaml
defaults:
  fim:
    credential: local:nr_fim   # default; a separate account, so nr_nitro stays narrow
    webroot_interval: 600      # Tier B walk, 300-900 s
    rehash_interval: 900       # re-hash unchanged files, 300-3600 s
devices:
  - name: ns-gw-02
    fim: {enabled: true}
```

FIM state (baselines and hashes, never content) is kept in
`state_dir/configs/state/_fim-<device>.json`. Findings are stored there until they reach the
database, so an outage does not lose them. Where NITRO refuses a path, use NetScaler Console
file-integrity monitoring or an SSH sweep for that path.

## Forensic analysis workflows

### Exported files, offline

Use copies of exported configuration and logs. These commands do not need the daemon,
PostgreSQL, vault, or appliance connectivity:

```bash
netrescale config diff before.ns.conf after.ns.conf
netrescale config diff before.ns.conf after.ns.conf --json > config-diff.json
netrescale hunt ns.log ns.log.0.gz --source nslog --device ns-gw-01 \
  --admin-networks 10.20.0.0/16 --admin-users admin1
netrescale hunt ns.log --source nslog --device ns-gw-01 --json > hunt.jsonl
netrescale exposure --version-string "NetScaler NS14.1: Build 47.46.nc" --json \
  > exposure.json
```

- A configuration diff includes redacted before/after values, severity, matching risk rule
  IDs, and reasons. JSON output is one array.
- A hunt finding identifies the matched rule, severity, timestamp, and available evidence.
  JSON output is ECS-aligned JSON Lines, one finding per line. Use `jq -s . hunt.jsonl` when
  a consuming tool requires an array.
- Supply the actual log family with `--source` and the appliance date convention with
  `--date-format`. Supply administrator allowlists when assessing allowlist rules. The text
  command reports skipped rules on stderr.
- Exposure JSON is one array. Exit 2 means at least one result needs action. That includes an
  exploited advisory, or a whole release train, that the advisory data does not cover. Exit 1
  means the assessment failed. Capture output before interpreting a nonzero exit as command
  failure. Each result carries `bulletin`, `exploited`, `verified` and `post_patch_actions`.
  Each report carries `data_version`, `min_safe_build` and `needs_attention`.

No match means only that the bundled rules did not match the supplied, parseable lines. It is
not a clean-host verdict. Offline firmware analysis cannot discover configured features and
the bundled advisory data is not a live feed. Preserve original evidence separately: these
commands parse copies and do not provide acquisition, legal hold, or malware analysis.

### Retained deployed evidence

```bash
sudo -u netrescale netrescale status --json > status.json
sudo -u netrescale netrescale findings --days 30 --min-severity low --json > findings.json
sudo -u netrescale netrescale config history ns-gw-01
sudo -u netrescale netrescale config history ns-gw-01 --show 3
sudo -u netrescale netrescale search CMD_EXECUTED ns-gw-01 --days 30 \
  > archive-hits.jsonl
sudo -u netrescale netrescale archive verify ns-gw-01 --days 30 \
  --expected-head <externally-preserved-head>
```

`status` and `findings` produce JSON objects/arrays; `search` produces JSON Lines with a
scrubbed line and `raw_ref`. An empty search has no summary line and means no retained line
matched the case-insensitive text. Snapshot history is local chronological evidence;
`--show N` diffs N against N-1. Archive verification proves retained bytes match the local
manifest. Only comparison with a chain head preserved outside this host adds protection
against local archive and manifest rewriting.

Expected findings depend on the enabled rules and evidence: configuration findings describe
risk-scored observed changes, IOC findings identify matching log rules, exposure findings
describe bundled advisory status, and health findings describe collection/delivery failures.
They are leads for investigation, not proof of compromise, intent, or actor identity.

Polling can miss changes reverted between polls. Searches cover only logs that were received,
processed, and retained. In-memory session correlation does not survive daemon restart.
Unknown-sender quarantine is not searched by the normal archive command. Parser coverage must
be validated against real appliance builds. Treat configuration, raw lines, findings, and
even redacted exports as sensitive incident data.

## Browser administration

**Sensitive settings are host-managed.** The browser cannot change appliance addresses
(`nsip`), TLS trust files (`ca_bundle`), credential references, new appliances, or
SMTP/SIEM/webhook destinations; the save is refused with a 403 naming the field. Make
those edits in `/etc/netrescale/config.yaml` on the host. Setting
`web.allow_sensitive_settings: true` (host edit only) lifts the restriction; leave it off
unless every dashboard administrator is trusted with the ability to redirect where
appliance and mail credentials are sent. TLS pins can still be saved from the browser.

The daemon listens on `/run/netrescale/control.sock` (0600, service user), verifies the peer
UID and the operator's current role, and allows only known actions. The web process checks
role, session, origin and CSRF before forwarding requests. It has no root shell or vault key.
Actions are serialized and recorded in `/var/lib/netrescale/administration.jsonl`; secret
values and request bodies are not logged. Protect and rotate/archive this audit file as part
of host operations; it is not included in indexed-event retention.

**Device actions:** the Devices page puts read-only probe, configuration poll, exposure check
and TLS inspection directly below each management IP. Clicking the device name opens its
settings; the configuration icon remains a separate snapshot-history link. Progress indicators
stay visible during the request and across in-app navigation. A full browser reload resets the
local indicator; Health's recent actions retain the requested/completed/failed outcome.
HA pair editors use inventory selections and exclude the other member and devices already
assigned to another pair. Server-side validation remains authoritative.

**Health:** Platform shows host load, CPU count, free physical memory, filesystems, host uptime,
daemon uptime, process CPU/RSS/peak RSS, threads/descriptors, database size/counts and delivery
retries. CPU percentage is the daemon's sampled usage (100% equals one core); host load is a
separate 1/5/15-minute average. Free physical memory excludes reclaimable caches. Measurements
unavailable inside the OS sandbox are explicitly listed; the systemd sandbox is unchanged.
These measurements describe the monitoring host, not the appliances.

The daemon normally publishes resources and device diagnostics every ten seconds. Samples
older than sixty seconds are stale. NITRO/exposure counters cover the current worker lifetime
and reset when settings reload workers; process uptime/resource counters cover the daemon
process lifetime. Device failures include timestamps and exception classifications, with
TLS, network, authentication, permission and syslog errors kept distinct where known.

Recent action diagnostics read at most the last 512 KiB / 100 distinct audit requests, with
safe error text, response code, error type, duration and request ID. Partial log downloads are
recorded as partial outcomes. Older audit records do not have these extra fields. Administrators
can see all administrative actions; operators see device actions and log fetches without actor
names; viewers cannot access this action history. All authenticated roles can view basic health
and stored health findings. Raw exception traces, credentials and request bodies are not exposed.

**Settings:** a single Save validates, persists and activates the configuration. Validation and
stale-edit checks happen before writing. There is no separate Apply button. Retention,
credential-age policy, daily digest time and syslog silence thresholds are read dynamically;
these changes preserve workers, pipeline state, health counters and sessions. Inventory, TLS,
polling intervals, syslog-engine and notification-transport changes refresh monitoring workers
after in-flight work is stopped safely. The daemon process and its credential lockout state remain.

The daemon publishes the activated configuration for the web process, which updates its read
models without rebuilding the application for ordinary changes. Web access/session settings,
host-managed path changes, or a database connection change require a web-app rebuild. Web-only
changes do not restart healthy monitoring workers. Session expiry and the ten-minute admin
verification window are never extended; web security changes revoke existing sessions.
The browser reconnects only when the web app needs rebuilding, not after every save.

Activation errors after persistence return the saved revision and a retryable error. Save can
retry; invalid settings never replace the file. A valid configuration with a monitoring setup
problem is retained with explicit health warnings so it can be corrected. The legacy
`settings.apply` control action remains available for compatibility. Changing database connection
does not migrate data; prepare the new database separately. Filesystem paths and the OS group
remain host-managed and cannot be changed from the running UI.

**Users:** only the legacy `admin` account (or first account if absent) is promoted on upgrade;
other legacy users become operators. Disable/delete/password reset/role changes invalidate
existing sessions. The last enabled administrator is protected. CLI `web user-set` remains
the host recovery path; create routine users and assign roles from the Users screen.

**Detection:** this is a main-menu view for administrators and operators. **Device logs** fetches
selected current log files over the existing TLS-validated, read-only NITRO session, using
`GET /nitro/v1/config/systemfile?args=filename:...,filelocation:/var/log`. The existing credential
lockout guard applies. No SSH mode, shell command, or appliance mutation is involved. Review
the ADC command policy if file reads are denied; the application does not broaden permissions
or silently fall back to another transport. Upload exported logs when a build does not expose
their content through this API. Rotated and compressed files are not fetched.

Each file request has a 15-second deadline and a 16 MiB decoded transfer limit. The latest
1 MiB and at most 10,000 lines are retained with a SHA-256 integrity check, collection time,
original byte count, and truncation status. Captures use 0600 files in private per-device
directories under `state_dir/device-logs`. A successful fetch replaces that source's prior
capture; a failed fetch leaves the prior capture and its original timestamp intact. Device
removal does not delete retained captures; include these sensitive files in state backup and
retention procedures. Browser previews scrub registered secrets and show at most 500 matching
lines; the displayed digest refers to the retained original, not the scrubbed download.

Hunts use locally retained captures, not a new appliance request. Results are capped at 500
findings per source and partial coverage is marked. Each source produces a persistent hunt run;
uploads are saved too. Results are not added to monitoring findings or notifications. Rules
needing absent allowlists are listed as inactive. No findings is not proof of a clean appliance.

**Hunt history:** the PostgreSQL `hunt_runs` table stores start/completion times, actor, device,
source, status, result counts, redacted findings, input fingerprint, capture metadata,
and the rule definitions and fingerprint used at execution. Zero-match and failed runs are
retained. A hard process interruption can leave an unfinished run with no recorded completion.
Captured-log fingerprints refer to retained original bytes; upload fingerprints refer to the
submitted text encoded as UTF-8. The encoding is recorded with the run.
**Detection / History** supports filters, pagination, full run export and finding details.
Deleting/changing a custom rule or replacing a capture does not rewrite history. Full uploaded
input is not archived; retained evidence and its input fingerprint are stored with the results.
Older captures are not recovered from history. Existing hunts made before this feature are not
backfilled. `retention.findings_days` also governs hunt history.

**Hunt rules:** only administrators can save, disable or delete custom rules. Operators can
inspect/export definitions and run hunts. Rules use the existing YAML/JSON log-rule schema with
positive and negative tests. IDs must have the `custom-` prefix, sources must be supported log
types, and unknown fields or failing tests reject the entire import. Up to 100 custom rules
are supported, with 256 KiB per import and bounded regex/test fields. Version checks reject
stale edits. The private `state_dir/hunt-rules.json` and its `.bak` should be included in state
backups; package upgrades leave them untouched. Custom rules affect manual hunts only and do
not replace packaged continuous-monitoring rules.

Rule validation and manual hunts execute in a separate local Python worker, never an appliance
shell. Input/output limits and a 30-second wall-clock deadline bound the worker; timed-out
processes are terminated and failed hunts are recorded. A 512 MiB address-space cap is applied
where supported by the host sandbox. The worker does not receive the vault credential directory
environment variable. Test vectors are always checked before saving or re-enabling a rule.

The **Templates** catalog contains 17 selected log-only adaptations of the user-supplied
`ctx697096_check.sh` v1.13 (Thomas Poppelgaard), with attribution and scope notes. Import one
or review the whole pack before saving; templates are not activated automatically. They are
community hunting leads, not verified Citrix IOC data or proof of compromise. The complete
script's process/memory/filesystem checks, file hashes, partition checks, firmware eligibility,
patch-time correlation and full IOC lists are not implemented by these templates. The script
is never executed or uploaded to a device, and Exposure advisory data is unchanged.

The installer runs `db init` to add the hunt table without deleting prior data. When upgrading
without the installer, initialize the database as the service user before restarting the daemon
and web service. Missing database schema must not be interpreted as empty history.

**Configuration:** the DIFF view shows redacted unified additions/removals. Choose **Compare
with** to select a historical baseline within the running or saved snapshot history. The default
is the previous capture; the first capture is compared with an empty baseline. Snapshot view
and downloads remain redacted.

**Credentials:** blank replacement fields preserve existing secrets. Deletion is blocked
while either saved or active configuration references an entry, including SMTP authentication.
Credential tests share the daemon's lockout guard. Verify a TLS fingerprint independently
before confirming a pin inspection result, then apply the saved settings.

**Vault restore:** upload only a trusted encrypted netrescale backup. Restore pauses collection,
verifies entries, and re-encrypts under the existing host key; it does not replace the
systemd-sealed master key. A `.bak` copy is retained. Review/test credentials and resume
explicitly. Initial bootstrap and master-key rekey remain host-level maintenance tasks.

**Pause:** scheduled config/exposure/syslog/HA work pauses. Administration, status reporting,
retention housekeeping and queued delivery remain up. In-flight work may finish; direct
read-only operator checks remain available. Pause survives restarts. Pausing and resuming
are reported as findings (see Monitoring the monitor). The daemon stays in
administration mode if monitoring setup is incomplete, except when systemd cannot load the
sealed key before process startup.

## Storage and delivery

- PostgreSQL holds hunt history, indexed security events, findings and the transactional notification
  outbox. Delivery retries back off from 30 seconds to one hour, independently per sink.
  Each sink has its own two delivery slots, and higher severities go first. After a failed
  send, the sink's other due notifications are deferred unsent for 30 seconds, so a sink that
  drops traffic cannot delay the others. A sink that keeps failing for 15 minutes is reported
  through the other sinks.
  Delivery is at least once: a crash after a remote send but before acknowledgement can
  produce a duplicate. Pending notifications are not deleted by findings retention.
- Original log bytes are stored in daily per-device zstd files under
  `/var/lib/netrescale/archive`. The manifest records frame offsets, hashes, and a chained
  digest. Each daily digest carries archive chain heads to configured notification sinks.
  Preserve SIEM copies as external anchors; a local privileged attacker can rewrite local files.
- `archive verify <device> --expected-head <head>` checks against an external anchor. A
  mismatching/incomplete manifest requires investigation; do not delete it to silence errors.
- Daily cleanup applies `retention.raw_days`, `events_days` and `findings_days`.
  Source syslog files are deleted after `syslog.source_days` only when fully acknowledged.
  Snapshot history is retained; include it when sizing storage. Unknown-sender quarantine
  files need administrator review/rotation and are not processed by the detection pipeline.
- Monitor disk use with `df -h /var/lib/netrescale /var/log/netrescale` and `df -i`.
  Size PostgreSQL and raw storage from pilot traffic; do not assume a fixed estate-wide rate.

## Polling and TLS failures

ADC polling uses HTTPS NITRO calls; it does not use SSH. A self-signed or browser-untrusted
ADC certificate works with an independently verified SPKI pin. Keep the CA bundle unset for
pin-only validation, unless CA validation is also deliberately required. Plain HTTP-only
appliances and obsolete TLS versions are not supported by the current transport.

SPKI can be disabled per device with `spki_pinning: false`, or by unchecking **Use TLS key
fingerprint (SPKI)** in **Settings / Devices** and saving. The old fingerprint remains
stored but is not checked. CA-based certificate validation is then mandatory, using the device
`ca_bundle`, inherited `defaults.ca_bundle`, or system CA trust if neither is configured. Chain,
expiry and NSIP identity validation remain enabled. Certificates with only a DNS identity do not
match an IP-only NSIP connection; provision the appropriate IP SAN or use a verified pin.
Private CA bundles are local PEM files readable by the monitoring service. This option never
enables HTTP, obsolete TLS protocols, or unverified HTTPS. A verified pin saved through the TLS
inspection dialog explicitly re-enables SPKI pinning.

The dashboard's `web allow-http` client-network allowance does not grant the monitoring
daemon access to appliances. If `systemctl show netrescale -p IPAddressAllow` lists only
localhost, run `sudo netrescale device allow-network --restart`. It grants exact management
addresses from the saved inventory via `30-appliance-egress.conf`; the default deny remains.
Re-run after inventory changes. Existing manual allowances in other drop-ins are preserved.

After network access is allowed, configure a verified ADC TLS fingerprint or select CA-based
validation, then save before probing. The UI retains operation errors in a dialog. Missing pins,
key mismatches, CA verification errors, TLS protocol errors, timeout/connectivity failures
and NITRO command-policy denials have distinct messages. Bad credentials still use the same
lockout guard. Do not repeatedly restart/retest an account rejected by an appliance.

## Credentials

- **Rotate:** run `sudo netrescale cred rotate <name>` after changing the password on the
  NetScaler. It stores the new password and immediately tests it on every device that
  uses the entry.
- **Blocked credentials:** a credential the appliance rejected is blocked on that device
  until its username/password/key actually changes. Changes to another entry or re-saving
  the same value do not unblock it. The guard is process-local: restarts and separate CLI
  invocations can retry a bad password. Do not repeatedly test a known-rejected credential.
- **Age:** a low-severity finding fires when an entry is older than
  `max_credential_age_days` (default 90).

## Backup and recovery drill (do this once, on a VM)

```bash
sudo netrescale vault backup /root/vault.bak          # passphrase-protected
# on a fresh host after install.sh:
sudo netrescale vault restore /root/vault.bak          # re-seals the key for the new host
sudo systemctl start netrescale
```

The `bootstrap` escrow file holds only the master key. With the passphrase, it decrypts a
vault file copied from the old server's `/var/lib/netrescale/vault`.

Also back up `/etc/netrescale`, `/var/lib/netrescale` and the egress/firewall/rsyslog
configuration. Stop the service or use a coordinated filesystem snapshot when copying
state so manifests and frames remain consistent. Make a PostgreSQL backup separately:

```bash
sudo -u postgres pg_dump -Fc netrescale > netrescale-database.dump
```

Protect that dump and all state copies as sensitive. On a fresh host, restore the database
as PostgreSQL administrator, restore state with `netrescale:netrescale` ownership, and run
the vault restore procedure above. Check archive integrity and notification delivery before
resuming the fleet rollout.

## Upgrades

Stop the daemon, back up state and PostgreSQL, then run the installer from a release checkout.
It retains the existing unit and writes a `.service.packaged` template for comparison;
merge applicable hardening/lifecycle changes while keeping the egress drop-in. This includes the
`StartLimitIntervalSec`/`StartLimitBurst` lines in `[Unit]`, which let a crash loop reach the
failed state. Run
`systemctl daemon-reload`, start the service, and repeat the status/delivery checks.
Schema version 1 is initialized idempotently; unknown schema versions are rejected.
Legacy 0.1 JSONL findings remain on disk and are not automatically imported into PostgreSQL.

## Rekey

```bash
sudo systemctl stop netrescale
sudo netrescale vault rekey /root/new-escrow.json
sudo systemctl start netrescale
```

Old escrow files and backups no longer match the new key. Replace them.

## If a TPM becomes available

Re-seal the key so it is bound to the TPM as well as the host key:

```bash
sudo systemd-creds decrypt --name=netrescale.vault-key \
  /etc/credstore.encrypted/netrescale.vault-key - \
  | sudo systemd-creds encrypt --with-key=host+tpm2 --name=netrescale.vault-key - \
      /etc/credstore.encrypted/netrescale.vault-key.new
sudo mv /etc/credstore.encrypted/netrescale.vault-key.new /etc/credstore.encrypted/netrescale.vault-key
sudo systemctl restart netrescale
```

## Troubleshooting

| Symptom | Check |
|---|---|
| Service won't start | `journalctl -u netrescale -b`. A missing credential usually means `bootstrap` wasn't run, or the sealed file was created on another host |
| `health-device-blocked` finding | The appliance rejected the password. Fix it on the appliance or vault side, then run `cred rotate` |
| `TLS key changed` (critical) | Expected after a cert/key renewal: verify with the appliance team, then run `device pin` and update `spki_pin`. **Otherwise treat it as an incident** |
| `health-device-unreachable` | Network, the `IPAddressAllow=` list in the unit, NITRO reachability, cmdPolicy (`PermissionDenied`) |
| No email | `notify.smtp` severity floor; the relay allowlist; `IPAddressAllow` for the relay |
| `notification-sink-failing` | The named sink's last error in `status --json` (`notifications`); relay or SIEM reachability and `IPAddressAllow` |
| `monitor-coverage-reduced` | Confirm with the named administrator that the pause or settings change was intended; check `administration.jsonl` |
| `syslog-batch-quarantined` | Review the batch in `pending/quarantine/` and its raw lines with archive `search`; the error names the database failure |
| `exposure-unknown-*` | The device's train is missing from the advisory data; check the Citrix bulletins and treat the device as exposed until confirmed fixed |
| Unit is `failed` after restarts | `journalctl -u netrescale -b`; fix the cause, then `systemctl reset-failed netrescale` |
| Sandboxing check | `systemd-analyze security netrescale` (target < 2.0) |
