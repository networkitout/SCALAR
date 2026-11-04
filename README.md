# SCALAR

> The project is named **SCALAR**. The Python package, CLI command, systemd units and file
> paths keep the original `netrescale` identifier (for example `sudo netrescale web user-set`,
> `/etc/netrescale/config.yaml`), so existing installs and the commands below are unchanged.

A self-hosted monitor for Citrix/NetScaler ADC and Gateway appliances, with an authenticated
browser dashboard and an administrative CLI. It runs on an Ubuntu 24.04 server with management
access to the NetScalers, and it:

- **alerts on observed configuration changes** (running and saved, polled every 60 seconds), with a risk-scored,
  secret-redacted diff, unsaved-change ("drift") detection, and detection of an `ns.conf`
  edited on disk;
- **checks firmware builds** against the CVEs exploited in the wild (CitrixBleed,
  CitrixBleed 2, CVE-2025-6543/7775, the 2026 SAML and CVE-2026-88771 bulletins). It gates
  each CVE on whether the vulnerable feature (Gateway/AAA, SAML, IPv6 LB, ...) is configured;
- **hunts for indicators of compromise** in NetScaler logs with a tested YAML rule pack and
  session-hijack correlation;
- **stores NetScaler credentials in an encrypted local vault** (AES-256-GCM, key sealed with
  systemd-creds), with passphrase escrow for disaster recovery;
- **notifies** by email, by webhook (generic JSON or Slack) and to a SIEM (RFC 5424 over
  TLS, ECS-style JSON or CEF; built for Cribl → CrowdStrike NG-SIEM).

SCALAR is **read-only toward the NetScalers**. The NITRO client refuses anything but
GET (plus login/logout). Appliance setup is printed as commands for an admin to apply.

## Release 0.4.4: Browser Administration and Monitoring

This release implements read-only NITRO monitoring and continuous ingestion of forwarded
syslog. Install it on Ubuntu 24.04, validate one HA secondary, then expand the inventory.
Appliance credentials, pins, firewall policy, and notification destinations must be
configured locally. The installer does not start monitoring automatically.

The browser UI includes fleet health, searchable findings and audit events, exposure records,
device status, redacted configuration history/diffs, notification delivery status, and workspace
administration. PostgreSQL/daemon failures are displayed explicitly; an empty dashboard is not proof
that monitoring is healthy.

The sun/moon button on the login page and dashboard switches light/dark mode. Your choice is
remembered in that browser; without a saved choice, the interface follows the system theme.

| Milestone | State |
|---|---|
| M1 Credentials, inventory, exposure check | **Working**: vault, escrow/backup/restore/rekey, lockout guard, TLS key pinning, `exposure` |
| M2 Config-change alerts | Poller, recoverable config alerts, snapshots, risk scoring, drift/tamper detection, audit-command candidates, and HA configuration divergence after a sync grace period |
| M3 Syslog pipeline | Live tailer, restart checkpoints, truncation detection, rule/session evaluation, silence alerts, daily zstd archives, hash-chain verification, PostgreSQL indexing, and durable notification retries |
| File-integrity monitoring (NITRO) | Opt-in per device (`fim.enabled`): boot hooks, crontabs, SSH keys and httpd.conf on every probe; web roots, temp and crash directories every 5-15 min, over read-only `GET systemfile` with a separate `nr_fim` account. Built against the emulator; validate on your firmware first (docs/operations.md) |
| M4 SSH log pulls / M5 SSH host sweeps / M6 telemetry | Not included in 0.4. Active mode is rejected at startup; no SSH superuser account is needed |

The rule pack's test lines follow the documented NetScaler log formats. Add sanitized real
lines from your appliances as you collect them.

## Access the Web UI

After installation, create your own web account and start the separate dashboard service:

```bash
sudo netrescale web user-set admin
sudo systemctl enable --now netrescale-web
```

**There is no default password.** The first command prompts for a password of at least
16 characters. The username is the name you supply (`admin` above). These are dashboard
credentials, not NetScaler appliance credentials. Repeat `web user-set <name>` to add an
administrator or reset a password; existing sessions for that user are invalidated. After initial
setup, manage users and their roles from **Users** in the dashboard.

Open **http://127.0.0.1:8080** on the server. From your workstation, use VS Code port
forwarding or an SSH tunnel:

```bash
ssh -N -L 8080:127.0.0.1:8080 YOUR_SSH_USER@YOUR_SERVER
```

Then open http://127.0.0.1:8080 locally. The dashboard binds only to loopback by default.
Network HTTP requires an explicit opt-in; HTTPS remains the recommended deployment.

For shared network access, put an HTTPS reverse proxy on this host in front of
`127.0.0.1:8080`, restrict access to your management network, and configure:

```yaml
web:
  host: 127.0.0.1
  port: 8080
  public_url: https://netrescale.example.internal
  allowed_hosts: [localhost, 127.0.0.1, netrescale.example.internal]
  session_hours: 8
```

The proxy must preserve `Host`, set `X-Forwarded-Proto: https`, and replace (not blindly
append) `X-Forwarded-For` with the originating client address. Forwarded headers are trusted
only from loopback. Saving web access settings reloads the web service automatically; other
settings refresh its data in place. The web unit
receives no vault master key and cannot read the default vault or raw archive paths.

### Temporary Internal HTTP

For an explicitly trusted internal network, enable HTTP with a specific server IPv4 address
and an allowed client IP/CIDR (repeat `--allow-network` for additional client networks):

```bash
sudo netrescale web allow-http --host 192.0.2.50 --allow-network 198.51.100.0/24 --restart
```

Replace those example addresses with your server and permitted clients. The command sets
`web.allow_http: true`, binds that address, configures the HTTP public URL, and creates
`netrescale-web.service.d/20-http-access.conf` with only the specified `IPAddressAllow=`
entries. The unit's default deny and other sandbox restrictions remain in place. It backs
up the application config, does not change UFW/firewall rules, and does not change appliance
TLS settings. Permit the configured port through the host firewall for those clients as needed.
`--restart` reloads systemd and restarts both application services; omit it to stage changes.

**HTTP is unencrypted:** login passwords, administrative credential submissions, session
cookies, and monitoring data can be intercepted by a party able to observe that network.
Authentication, HttpOnly/SameSite cookies, CSRF, origin validation and user roles still apply.

To return to localhost-only access, set `web.host: 127.0.0.1`, `web.public_url: null`, and
`web.allow_http: false`, then apply settings. Remove the generated HTTP access drop-in and
reload/restart the web unit to restore its original network allowlist. For HTTPS, set the
HTTPS public URL and disable `allow_http` after configuring the reverse proxy. A configured
HTTPS public URL continues to use Secure cookies and HSTS even when `allow_http` is true.

To inspect the interface before appliance or PostgreSQL setup, use the developer environment
described below and run:

```bash
netrescale web preview --port 8081
```

Open http://127.0.0.1:8081. **Preview is anonymous, uses isolated sample data, and cannot
contact appliances or send notifications. It is not live monitoring.** Stop it with Ctrl+C.

## Administer the Platform

The monitoring daemon must be running for administrative actions. It serves a local,
peer-authenticated control socket; the browser process never receives the vault master key.

| Screen | Administrative functions |
|---|---|
| Settings | Add/edit/remove devices and HA pairs; edit collection intervals, syslog allowlists, notification channels, retention, database connection, and web settings |
| Users | Create accounts, assign administrator/operator/viewer roles, disable/delete accounts, and reset passwords |
| Credentials | Add, rotate, and delete vault entries; test referenced NITRO credentials; inspect blocked status. Existing passwords/private keys are never returned |
| Operations / Monitor | Pause/resume scheduled monitoring and initialize missing database schema |
| Devices | Click a device name to edit its settings; use the actions under its IP for probe, config poll, exposure assessment and TLS inspection |
| Health | Device collection diagnostics, recent action failures, host/process resource counters, database totals and notification delivery status |
| Detection | Fetch logs through read-only NITRO, run hunts, review persistent history, manage custom hunt rules, import script-derived templates, and compare config text |
| Configuration | View redacted snapshots and unified DIFFs against a selected historical snapshot |
| Operations / Archive | Search retained raw logs and verify integrity against an optional external chain head |
| Operations / Vault | Download a passphrase-encrypted backup and restore credentials under the current host key |
| Operations / Host setup | Generate appliance commands, rsyslog configuration, and firewall rules for an administrator to review/apply |
| Operations / Audit trail | Inspect requested/completed/failed administration operations without secret payloads |
| My account | Change your own password; changing it invalidates existing sessions |

**Device management:** device-name links open the matching inventory settings; the separate
configuration icon opens snapshot history. HA pair members are selected from the device
inventory, not entered as text. Row actions show progress, disable duplicate clicks for that
device, and retain the latest result. A page-level indicator stays visible while you navigate
within the dashboard. TLS inspection still requires explicit fingerprint confirmation.

**Health** has Platform and Devices tabs. Platform shows CPU count/load, free physical memory,
disk capacity, host/daemon uptime, daemon CPU and memory, database record counts and size,
notification retries, and unavailable measurements. Devices shows NITRO polling, exposure
checks and syslog ingestion, with last attempts/successes/failures, counters and error details.
Recent actions include redacted reasons, response codes, durations and request IDs. Old audit
records without diagnostics remain labeled as such. Missing/stale daemon samples are never
treated as current health. These are monitoring-host metrics, not ADC hardware telemetry.

**Device-log hunts:** open **Detection / Device logs**, select an applied device and log files,
then **Fetch selected logs** and **Hunt selected logs**. The daemon reads only the fixed
`/var/log/` files for `nslog`, `bashlog`, `shlog`, `httperror`, `httpaccess`, `httpaccess-vpn`,
`notice`, and `auth` through NITRO `GET systemfile`. This does not enable SSH, run shell commands,
or change the appliance. The account must be permitted to read those files; missing files,
unsupported downloads, and permission failures are reported, not silently treated as clean logs.
Downloads are limited to 16 MiB per file; the latest 1 MiB / 10,000 lines are retained
for each source and device. Partial captures are marked. Only current files are fetched;
rotated/compressed logs still require export and the existing CLI hunt workflow. Captures are
private local data under `state_dir/device-logs`, replaced on the next successful fetch.
Hunts run against these captures without contacting the appliance or queuing notifications.
The UI supports log search, finding details, severity filters, and result export. Uploads remain
available when NITRO file access is unavailable. No matches is not a clean-host verdict.

**Persistent hunt history:** captured-log and uploaded-log hunts are saved automatically in
PostgreSQL, including zero-match and failed runs. **Detection / History** filters by device,
source and time, reopens finding details, and exports the complete run. Each run records its
operator, timestamps, input fingerprint, capture metadata, exact rule definitions and rule-set
fingerprint. Replacing a capture or editing/deleting a rule does not alter previous results.
History follows `retention.findings_days`; manual hunt findings do not enter the notification
queue or the live Findings page. Older, unsaved hunts cannot be recovered automatically.

**Custom hunt rules:** administrators use **Detection / Rules** to create, test, edit, enable,
disable, delete, import and export YAML/JSON rules. Positive and negative test vectors must pass
before save. Custom rule IDs start with `custom-`; bundled rules are read-only. Changes affect
the next manual hunt, not continuous syslog rules, and require no service restart. Definitions
are kept in private `state_dir/hunt-rules.json` with an atomic backup, outside the installed
package. Operators can review rules and run hunts but cannot modify definitions.

**Templates** offers 17 opt-in log-only adaptations of the supplied `ctx697096_check.sh` v1.13
by Thomas Poppelgaard. They cover selected poisoning, request, shell-history and crash signals,
with negative tests and source attribution. They do not execute the script, implement its full
IOC lists, perform filesystem/process/memory sweeps, or make build/patch-time compromise
verdicts. Community indicators and advisory mappings are not independently verified; review
templates and local false positives before enabling them. These templates do not modify
Exposure's firmware advisory data.

An upgrade through `deploy/install.sh` creates the new `hunt_runs` table via `db init`, preserving
existing data. Manual package upgrades also require `sudo -u netrescale netrescale db init`
before restarting both services.

**Local-auth device setup:** the device editor shows name, management IP, a stored-credential
dropdown, TLS verification settings, and the optional CA bundle. Choose a vault entry by its name and username, or keep
the configured default. The plus button creates a credential without discarding an unfinished
device. SSH-key-only entries are not offered for NITRO password login. Uncommon overrides are
under **Advanced**; inactive SSH/mode settings are hidden without deleting existing values.
Local appliance authentication still uses verified HTTPS; it does not remove TLS verification.

**Disable SPKI pinning:** in **Settings / Devices**, uncheck **Use TLS key fingerprint (SPKI)**,
then save. The saved fingerprint is retained but ignored until pinning is
re-enabled. HTTPS then validates the certificate against the device's CA bundle, the default
CA bundle, or the server's system CA trust store. A custom bundle is a PEM file on the monitoring
server readable by the service user. The certificate must be trusted, unexpired, and valid for
the configured management IP (NSIP). For YAML configuration, set `spki_pinning: false` on that
device. This is not an insecure/skip-verification mode; untrusted self-signed certificates still
need a verified pin or suitable CA trust. Pinning is enabled by default and requires no special
appliance feature or NITRO permission.

**Self-signed ADC certificates are supported.** An HTTPS portal with a browser certificate
warning still presents a certificate whose public key can be pinned. No publicly trusted
certificate is required. Polling uses NITRO HTTPS, not SSH; SSH host keys are unrelated to
SPKI. The internal HTTP option for this dashboard does not enable HTTP polling of appliances.
An ADC exposing only plain HTTP needs a working management HTTPS endpoint before this client
can poll it; certificate verification is not silently disabled.

The monitoring service and dashboard have separate systemd network allowlists. After adding
or changing appliance management IPs, grant only the configured ADC addresses with:

```bash
sudo netrescale device allow-network --restart
```

This writes a managed drop-in for `netrescale.service`, retaining its default deny and all
existing custom drop-ins. It allows only each configured management IP (`/32` or `/128`),
not syslog source addresses or an entire subnet, and does not change UFW or ADC configuration.
Then use **Devices / Inspect TLS key**, verify the fingerprint independently,
then save it. Poll failures now distinguish missing/mismatched pins,
certificate checks, TLS handshake errors, connectivity/allowlist issues, and command-policy denial.

**Empty inventory is supported.** Removing a device that belongs to an HA pair asks for
confirmation and removes that pair definition, not its peer device. Removing all devices then
saving leaves the daemon in an **idle** state with no appliance requests. Stored
credentials and historical records are retained; invalid HA references are still rejected.

**Save settings** validates the complete configuration, rejects stale edits, and atomically
writes a backup plus the new configuration, then activates it in the same request. There is
no separate Apply step. Retention, credential-age policy, digest time and syslog silence
thresholds update in place without resetting workers or health counters. Inventory, TLS,
collection-engine and notification-transport changes still refresh monitoring workers, but
the web app and browser session remain running. The browser stays on the settings form.

Web access/session settings or a database connection change rebuild the web app and trigger
a reconnect; web security changes still require a fresh sign-in. PostgreSQL and host firewall
rules are not restarted or changed. A new public URL/port may require reopening that address.
Invalid pins or unavailable dependencies remain visible as setup errors. If activation fails
after the file is saved, the error is shown and Save can retry using the current revision.

Administrators manage settings/users/credentials and maintenance. Operators view monitoring
data and run read-only appliance/investigation tools. Viewers have read-only dashboard access.
Mutating administrative operations require a login/password verification within ten minutes.
The last enabled administrator cannot be deleted, disabled, or demoted. A legacy `admin`
account becomes the bootstrap administrator; if absent, the first legacy account does.
Other legacy accounts become operators. Review roles after upgrading.

**Host-managed boundaries:** storage paths and the OS administrator group are visible but
require a coordinated migration outside the UI. Initial vault bootstrap, sealed master-key
rekey, OS package installation, systemd egress policy, firewall application, and TLS proxy setup
still require a host administrator. The UI does not expose a root shell. Backup restore pauses
monitoring, verifies every entry, preserves the current host key, and leaves monitoring paused
for review. Backups missing referenced credentials are rejected.

Upgrade an existing installation to enable the administration socket and permissions:

```bash
cd /opt/netrescale
sudo bash deploy/install.sh
sudo systemctl daemon-reload
sudo systemctl restart netrescale netrescale-web
```

The installer preserves unit customizations, changing only the previous exact
`ReadOnlyPaths=/etc/netrescale` directive to `ReadWritePaths=/etc/netrescale` in the monitoring
unit. The web unit remains read-only to configuration/state and still has no vault key.

## Quick start: Ubuntu 24.04

Use a complete release checkout on a clean or existing Ubuntu 24.04 server. The installer is
idempotent: it upgrades the Python environment and database schema, preserves
`/etc/netrescale/config.yaml`, the vault, state, and customized units, and does not start
monitoring.

```bash
cd /path/to/netrescale-release
sudo bash deploy/install.sh
```

The final `CLI, config, units, and database verified` line confirms package installation,
configuration parsing, systemd unit syntax, and PostgreSQL peer access. Re-run that read-only
gate at any time from the same release checkout:

```bash
sudo bash deploy/install.sh --verify-only
```

The installer creates the virtual environment, service account, local PostgreSQL 16
database/schema, and monitoring/dashboard systemd units. It requires the included hash-pinned
dependency lock. On upgrade it keeps an existing monitoring unit and writes the current
template to `/etc/systemd/system/netrescale.service.packaged` for review.

Complete these gates in order:

1. **Edit `/etc/netrescale/config.yaml`.** Fill in the devices, HA pairs and notification
  sinks. Remove example sinks you do not use. Set `syslog.admin_networks` and
  `syslog.admin_users` to enable the corresponding allowlist rules. Also edit
  `/etc/systemd/system/netrescale.service.d/egress.conf`: add `IPAddressAllow=` entries for
  appliance management, DNS where needed, and notification destinations. Webhook/CDN IPs
  may change; prefer an internal relay when maintaining a strict egress allowlist.
2. **Create the vault.** Store the escrow file offline (password manager or safe), then
   delete it from the server:
   ```bash
   sudo netrescale bootstrap --escrow-out /root/netrescale-escrow.json
   ```
3. **Pin each appliance's management TLS key.** Compare the fingerprint with the appliance
   before you accept it, then paste `spki_pin` into the config:
   ```bash
   sudo netrescale device pin 10.0.0.10
   ```
4. **Create the SCALAR accounts and the syslog target on the NetScaler.** On HA pairs,
   apply the printed commands on the primary only:
   ```bash
   sudo netrescale snippets ns-gw-01 --server-ip <this-server-ip>
   ```
5. **Store and test the credentials.** Passwords are prompted for, never passed as arguments:
   ```bash
   sudo netrescale cred set nr_nitro
   sudo netrescale cred test nr_nitro
   ```
6. **Run the first checks:**
   ```bash
   sudo netrescale config validate
   sudo netrescale probe ns-gw-02
   sudo netrescale exposure
   sudo netrescale device test ns-gw-01
   ```
  `probe` only reads NITRO resources. It does not enable SSH or verify every on-box log format.
7. **Activate syslog ingestion:**
   ```bash
   sudo netrescale rsyslog-config | sudo tee /etc/rsyslog.d/60-netrescale.conf >/dev/null
   sudo rsyslogd -N1
   sudo systemctl restart rsyslog
   sudo netrescale rsyslog-config --nft
   ```
  Review and persist the printed firewall rules in your existing nftables configuration.
  Do not replace an existing firewall policy. Allow TCP/514 only from inventory NSIPs/SNIPs.
  Confirm the generated directories are `syslog:netrescale`, mode `0770`, so acknowledged
  source logs can be cleaned up after `syslog.source_days` (default two days).
8. **Start and verify:**
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now netrescale
   sudo bash deploy/install.sh --verify-only
   sudo systemctl is-active netrescale
   sudo -u netrescale netrescale status
   sudo -u netrescale netrescale notify test
   sudo journalctl -u netrescale -n 50 --no-pager
   ```
   Wait for the first poll and forwarded logs before requiring `status` to report `healthy`.
   Confirm actual receipt through every enabled notification sink. A queued test is not proof
   of delivery. `status` exits nonzero for not-running, stale, unavailable, or degraded
   monitoring, including pending notification deliveries. Review disabled-rule warnings before
   rollout.

The installation is complete only when `--verify-only` passes, the service is active,
`status` is healthy after the first poll, and each configured test notification arrives.
The dashboard is optional; create its first user and start it as described in
**Access the Web UI**.

To test before installing system-wide (no root, no systemd):

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q
netrescale exposure --version-string "NetScaler NS14.1: Build 47.46.nc"
```

New devices stay in `mode: observe`: read-only NITRO plus passive syslog. Save activates inventory
or TLS pin changes automatically; password rotation is picked up automatically.
The dashboard can run before the monitoring daemon; it will show the stopped/unconfigured
state. Starting the dashboard does not start appliance polling.

## Offline forensic analysis (no service or appliance access)

```bash
netrescale config diff ns.conf.old ns.conf.new        # risk-scored, redacted diff
netrescale config diff ns.conf.old ns.conf.new --json > config-diff.json
netrescale hunt ns.log ns.log.0.gz --device ns-gw-01 --admin-networks 10.20.0.0/16
netrescale hunt ns.log --device ns-gw-01 --json > hunt.jsonl
netrescale hunt bash.log --source bashlog
netrescale exposure --version-string "NetScaler NS14.1: Build 47.46.nc"
netrescale exposure --version-string "NetScaler NS14.1: Build 47.46.nc" --json > exposure.json
netrescale rules list
```

Expect `config diff` to report a count, highest severity, risk-rule reasons, and a redacted
before/after view; no output object changes means `No configuration changes.` Its JSON is one
array. `hunt` prints matched rule/session findings and a final count; its JSON is one
ECS-aligned object per line, suitable for `jq -s`. Pass the correct `--source`, `--date-format`,
admin networks, and admin users or format/allowlist-dependent rules may not match and disabled
rules are reported on stderr. A zero-finding result means no bundled rule matched the supplied
lines, not that the appliance is uncompromised.

`exposure` exits with code 2 when a device needs action and code 1 when a device could not
be assessed. The bundled advisory table is not a live vulnerability feed; review its
verification/staleness warnings and check vendor bulletins before making patch decisions.
Offline version assessment has no live feature detection, so feature-gated results may be less
specific than a deployed assessment.

## Deployed forensic analysis

Run database and archive reads as the service account:

```bash
sudo -u netrescale netrescale findings --days 7 --min-severity medium --json > findings.json
sudo -u netrescale netrescale config history ns-gw-01
sudo -u netrescale netrescale config history ns-gw-01 --show 3
sudo -u netrescale netrescale search CMD_EXECUTED ns-gw-01 --days 7 > archive-hits.jsonl
sudo -u netrescale netrescale archive verify ns-gw-01 --days 30
```

`findings --json` emits one JSON array. `search` emits JSON Lines containing a scrubbed raw
line and archive reference; no output means no retained line matched. `config history` lists
recorded snapshots, and `--show N` compares entry N with its predecessor. `archive verify`
checks retained bytes and the local hash chain; use `--expected-head` with a separately
preserved digest to detect local history rewriting. Local verification alone cannot defeat a
privileged attacker who can rewrite both archives and manifests.

Findings are detections, not proof of compromise or attribution. Snapshot polling can miss
changes reverted between polls, retained searches cover only ingested/non-expired data, parser
coverage depends on the actual appliance log format, and redaction reduces accidental exposure
but does not make exports non-sensitive. Preserve originals, timestamps, the external chain
head, and command output under your incident-handling procedure.

## Day-2 commands

```bash
sudo -u netrescale netrescale status --json
sudo -u netrescale netrescale findings --days 7 --min-severity medium
sudo -u netrescale netrescale config history ns-gw-01
sudo -u netrescale netrescale config history ns-gw-01 --show 3
sudo -u netrescale netrescale search CMD_EXECUTED ns-gw-01 --days 7
sudo -u netrescale netrescale archive verify ns-gw-01
sudo netrescale config show ns-gw-01 --drift   # live unsaved changes
sudo netrescale cred list                      # names, usernames, age, users; never passwords
sudo netrescale cred rotate nr_nitro           # store the new password and test it everywhere
sudo netrescale vault backup /root/netrescale-vault.bak
```

Local PostgreSQL uses peer authentication: database commands run as `netrescale`, while
vault administration and live credential checks run as root. Raw archives and config
snapshots contain sensitive appliance data and are protected by service-user permissions.
Back up PostgreSQL, state, configuration, and vault escrow; see [docs/operations.md](docs/operations.md).

## Remaining Limitations

- No SSH pulls, SSH host sweeps (processes, setuid files, content grep), telemetry thresholds,
  or raw-event forwarding to SIEM. NITRO file-integrity monitoring is opt-in, and its command
  policy and path coverage are marked VERIFY until the feasibility probe has run on 13.1 and 14.1.
- Session and threshold correlation windows are in memory and restart with the daemon.
  Raw logs, pending findings, notification jobs, and input checkpoints are durable.
- Audit attribution identifies recent successful command candidates; it is not proof of who
  caused a change. HA checks compare normalized configurations, not post-failover history.
- Polling can miss a change that is reversed between polls. Forwarded audit events provide
  complementary coverage. Validate actual appliance response/log formats during the pilot.
- PostgreSQL uses indexed tables with retention deletion, not the roadmap's partitioned/COPY
  ingestion. Size disk for the actual estate and benchmark sustained throughput before broad rollout.
- Root-only CLI vault bootstrap/rekey remains direct. Web administration uses the daemon's
  bounded local control socket. SSH safety gates and active collection are not implemented.

## Security model (short version)

The full version is in [docs/threat-model.md](docs/threat-model.md).

- **Vault protection:** the vault key is sealed with `systemd-creds`. This server has no TPM,
  so the seal uses the host key (`/var/lib/systemd/credential.secret`, root-only). **Root on
  this server, or a full disk image, can recover every NetScaler credential.** Limit the
  blast radius with the least-privilege `nr_nitro` account (custom `netrescale_ro` command
  policy) and management ACLs. Do not provision an SSH superuser for this release.
- **Credential handling:** secrets never appear in logs, notifications or CLI arguments.
  Every outbound payload is checked against the decrypted secret values before sending.
- **Lockout guard:** within a daemon lifetime, a rejected credential is blocked until its
  value changes. Re-saving the same password does not unblock it. A restart or separate CLI
  process has a fresh guard; do not repeatedly restart or test a known-rejected credential.
- **Pinning:** TLS connections are key-pinned. A changed key stops polling and raises a
  critical finding.

## Development

```bash
python -m venv .venv && . .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest                       # emulator-backed tests; no NetScaler needed
mypy                         # strict
ruff check src tests
```

The release lock is included. To regenerate it on Python 3.12/Ubuntu 24.04 after dependency
changes:

```bash
pip-compile --generate-hashes --allow-unsafe --all-build-deps --strip-extras \
  --no-emit-index-url --no-emit-trusted-host -o requirements.lock pyproject.toml
```

CI also runs storage tests against PostgreSQL 16. Set `NETRESCALE_TEST_DATABASE_URL` to a
disposable PostgreSQL database to run those tests locally; tests create and remove isolated
schemas. Never point that variable at production.

Design and roadmap: [docs/design.md](docs/design.md).
# scalar
