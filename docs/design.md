# SCALAR: NetScaler log/telemetry collector, IOC detector and config-change monitor

## Context
This document is the full product roadmap. Release 0.4 adds role-based browser administration
and a peer-authenticated daemon control socket to observe-mode NITRO, live syslog detection,
PostgreSQL indexing, daily raw archives and durable notifications.
The README's release scope and remaining limitations describe shipped behavior; SSH,
host sweeps, telemetry, partitioned ingestion and the privileged control socket remain planned.

This is a new project (it started from an empty repository).

SCALAR is a self-hosted service on an **Ubuntu 24.04 server with no TPM**. The server reaches a **medium/large NetScaler estate** (10+ ADC/Gateway appliances, HA pairs, 13.1/14.1, busy Gateways) over the management network. The service will:
1. **Collect and store logs and telemetry.** Logs arrive by syslog push and by scheduled SSH pull. Telemetry comes from NITRO.
2. **Detect indicators of compromise** from four sources:
   - log rules
   - session-hijack correlation
   - on-box webshell and persistence sweeps
   - checks for vulnerable or end-of-life firmware
3. **Alert on any ns.conf or running-config change.** Each alert carries a diff, who made the change, and a risk rating.
4. **Keep NetScaler credentials in an encrypted local vault on the server.** Bitwarden Secrets Manager isn't available today, so it is sidelined. The vault sits behind a provider interface so an external secrets manager can be added later.

**Decisions made with the user:**
- **Language:** Python 3.12.
- **Credentials:** **local encrypted vault only** in v1. Bitwarden is a future add-on.
- **Shell access:** SSH superuser-shell sweeps are allowed.
- **Alerts:** SMTP, plus **CrowdStrike NG-SIEM via Cribl**, plus a generic or Slack webhook.
- **Interface:** **authenticated web dashboard + CLI + systemd daemon**. The dashboard is
  a separate, local-first process without a vault master key. Routine administration goes
  through the daemon's role-checked local control socket; host bootstrap/rekey remain CLI tasks.
- **Storage:** **PostgreSQL 16**.
- **Log ingest:** **syslog push + SSH pull**.
- **Retention:** **1 year raw, 90 days indexed**.
- **No lab appliance.** Everything is validated with emulators and fixtures first, then on **production, read-only, secondary node first**.

## Design principles
- **Read-only toward NetScalers.**
  - The NITRO client refuses everything except GET, login and logout.
  - SSH sweeps use a code-level allowlist of read-only FreeBSD commands. They never upload scripts.
  - Appliance setup (accounts, cmdPolicy, syslogAction, mgmt ACLs) is **printed as snippets** for an admin to apply.
- **Safe-by-default on production.** A new device starts in `observe` mode, which allows only NITRO config polling and stats. SSH pulls and sweeps are enabled per device only after `scalar probe <device>` passes.
  - Sweeps are niced and time-boxed.
  - They run on the HA secondary first.
  - They never run concurrently on both nodes of a pair.
- **The daemon is the only process holding secrets and the only writer.** The CLI is a thin client over a unix socket.
- **The raw log archive is the system of record.** PostgreSQL holds the indexed security-relevant subset.
- **Silence is a signal.** SCALAR alerts when:
  - a syslog feed goes quiet
  - a TLS or SSH pin changes
  - a change has no attribution
  - logs are truncated

  It also sends a daily all-quiet digest.

## Architecture
```
NetScalers ──syslog TCP──▶ rsyslog (imtcp, disk queue) ──▶ /var/log/scalar/syslog/<nsip>/YYYY-MM-DD.log
   ▲  ▲                                                        │ tail (sha256(first 4KB)+offset checkpoints)
   │  └── SSH: persistent PTY shell, sentinel framing ◀── log puller / host sweeps
   └───── NITRO HTTPS: GET-only, SPKI-pinned, reused session ◀── config poller / telemetry / sessions
                                │
              scalard (one asyncio daemon, sandboxed systemd unit, sd_notify watchdog)
   parse ─▶ rule stream ─▶ findings ─▶ notifications_outbox ─▶ SMTP | Cribl (syslog-TLS JSON/CEF or HTTP) | webhook
     ├─▶ raw archive (daily zstd per node + sha256 hash chain, 1y)
     └─▶ PostgreSQL 16 (indexed events 90d, config blobs, telemetry, findings, baselines)
   /run/scalar/control.sock ◀── `scalar` CLI (SO_PEERCRED, group scalar-admin, audited)
```

## Repository layout
```
pyproject.toml  requirements.lock (pip-compile --generate-hashes)  README.md
src/scalar/
  config.py            pydantic models for /etc/scalar/config.yaml
  cli/                 Typer thin client + root-only offline cmds (bootstrap, db upgrade, vault rekey, restore)
  control/             JSON-lines RPC over unix socket, SO_PEERCRED authz, audit_log
  daemon/              supervisor, per-node loops (jitter, backoff, semaphore), observe/active modes
  secrets/             SecretProvider protocol; vault.py, systemd_creds.py, resolver.py (future: bitwarden.py)
  inventory/           devices, HA pairs, current-primary tracking (hanode)
  transport/nitro.py   httpx; GET-only guard; session reuse + re-login on 354/401; SPKI pin
  transport/ssh.py     asyncssh; host-key pin; PTY shell `__NR_<nonce>_BEGIN/END $?`; SFTP→`tail -c +N` fallback
  collect/             config_poller, syslog_tail, log_puller, sweep, telemetry, sessions
  parse/               nslog, nsconf (tokenizer/normalizer/redactor), bashlog, httplog, version
  detect/              rule_engine, sessions, config_risk, exposure, sweep_eval, ip_iocs, self_suppress
  store/               SQLAlchemy Core + Alembic, events_writer (COPY), archive, partitions
  notify/              router, outbox, smtp, siem (RFC5424/6587 TLS; JSON-ECS or CEF), webhook, redact
  data/                rules/*.yaml, config_risk.yaml, cve_builds.yaml, iocs/*.yaml, sweep_paths.yaml
deploy/   install.sh, scalar.service, tmpfiles.d, rsyslog template (generated), nftables, appliance-snippets/
docs/     operations.md, threat-model.md, appliance-setup.md, cribl-ngsiem.md
tests/    unit/, fixtures/{nsconf,nitro,nslog,sweep}/, rules/, integration/, emulator/
```

## Credentials (encrypted local vault)
- **Two NetScaler accounts per device.** `scalar snippets <device>` prints the commands to create them.
  - **`sc_nitro`:**
    - Uses a custom `scalar_ro` cmdPolicy. The built-in read-only policy can't run `show ns runningConfig`, `ns.conf` or `system user`.
    - Allows `show`/`stat` and those objects. Denies `shell|save|set|add|rm|bind|unset|kill|reboot`.
    - `-allowedManagementInterface API`.
  - **`sc_sweep`:**
    - Superuser, because shell access requires it.
    - `-allowedManagementInterface CLI`.
    - Decrypted **just-in-time** for each sweep or pull, then dropped from memory.
  - Both accounts are limited to this server's IP by management ACL.
- **Refs in config:**
  - Format: `local:<name>`. Several devices can share one entry, for example a fleet-wide `sc_nitro`.
  - The ref syntax and the `SecretProvider` protocol allow a later `bitwarden:` provider (Secrets Manager or the `bw` CLI) to be added without touching device config, but none is built in v1.
- **Vault file** (`/var/lib/scalar/vault`, mode 0600, owner `scalar`):
  - Versioned JSON: a header holding `format_version` and `key_id`, then one entry per name.
  - Each entry holds `nonce`, `ciphertext`, `created`, `updated` and `rotated_by`.
  - The plaintext value is JSON: `{"username","password","ssh_private_key"?}`.
  - Encryption: AES-256-GCM with a fresh 96-bit nonce on every write (`cryptography`). AAD is `nrv1|<key_id>|<name>`, so moving or renaming ciphertext fails authentication.
  - Writes are atomic: write a temp file, fsync it, then rename it into place. Keep the previous file as `vault.bak`.
- **Master key:**
  - 32 random bytes, generated by `scalar bootstrap`.
  - Sealed with `systemd-creds encrypt --with-key=host --name=scalar.vault-key` into `/etc/credstore.encrypted/`. With no TPM, the host key is `/var/lib/systemd/credential.secret`, readable only by root.
  - The unit loads it with `LoadCredentialEncrypted=`. The daemon reads it from `$CREDENTIALS_DIRECTORY`, which is ramfs readable only by the service, and holds it in memory only.
- **Managing credentials:**
  - Commands: `scalar cred set|list|rm|test|rotate`.
  - Secrets are read with `getpass`, or `--stdin` for scripts, and **never taken as CLI arguments**.
  - They go to the daemon over the control socket. The daemon is the only process that ever decrypts.
  - `cred list` shows names, usernames, which devices use each entry, and age. Never passwords.
  - `cred test` performs a login against each device that uses the entry.
- **Rotation hygiene:**
  - A low-severity finding fires when an entry is older than `max_credential_age_days` (default 90).
  - `cred rotate` updates the value and immediately runs `cred test` on all devices that use it.
- **Escrow and backup:**
  - `bootstrap` and `vault rekey` write a recovery file: the master key wrapped with an **Argon2id-derived** passphrase key (`argon2-cffi`), for offline storage.
  - `vault backup` writes the vault plus a wrapped key bundle.
  - `restore` rebuilds a server from the backup plus the passphrase. The host-key seal does not survive a server rebuild, so the vault is lost without this.
- **Rekey:** `vault rekey` (root, daemon stopped) generates a new master key, re-encrypts every entry under a new `key_id`, reseals the key, and writes a new escrow file.
- **Lockout guard:** after one authentication rejection from a NetScaler, stop using that credential on that device and raise a finding. Don't retry into an account lockout.
- **Documented limitation (threat-model.md):**
  - With no TPM, root on this server, or a full disk image that includes `/var/lib/systemd/credential.secret`, can recover every NetScaler credential.
  - Mitigations:
    - lock down root on this server
    - least-privilege `sc_nitro`
    - mgmt ACLs pinning both accounts to this server's IP
    - `sc_sweep` decrypted only during sweeps

## Config-change monitoring (lands first; highest value)
1. **Probe `GET /nitro/v1/config/nsconfig` every 60s.** It returns `lastconfigchangedtime`, `lastconfigsavetime` and `configchanged`. Fetch `nsrunningconfig` and `nssavedconfig` only when those values move, or every 6h as a safety net.
2. **Store content-addressed.** Configs go into `config_blobs` (zstd, sha256 key). `config_snapshots` holds one row per node per kind (running or saved). `config export` writes a git-friendly tree.
3. **Tokenize, normalize and redact, then diff.**
   - The CLI tokenizer handles quotes and `\"` escapes.
   - Strip node-specific lines (NSIP, HA node, rpcNode, hostname).
   - Replace `-encrypted` values and hashes with `sha256[:8]` fingerprints.
4. **Score risk from `config_risk.yaml`.**
   - **Critical/high:**
     - system user and cmdPolicy changes
     - SSH keys
     - audit syslog/nslog changes
     - rewrite and responder policies, especially JS injected into the login page
     - `ns extension`
     - mgmtAccess/restrictAccess
     - ACLs
     - authentication and SAML actions
     - certificates
     - NTP, `system parameter`
5. **Attribute** each change to `CMD_EXECUTED` audit events (user, remote IP, interface). An unattributed change is escalated.
6. **Findings:**
   - running ≠ saved drift
   - **saved-config tampering:** saved changed with no running change and no `save config`
   - **HA sync broken:** the secondary doesn't converge within the sync window
   - **post-failover divergence:** after a failover, the new primary is compared with the last logical config

## Log collection and storage
- **Push:**
  - Snippet: `add audit syslogAction sc_syslog <server> -serverPort 514 -transport TCP -logLevel ALL -dateFormat YYYYMMDD -timeZone GMT_TIME -managementlog ALL` + policy + global bind. Whether `-managementlog` forwards shell and access logs is checked by the probe.
  - rsyslog `imtcp` with a disk-assisted queue writes per-`$fromhost-ip` daily files. Unknown sources go to quarantine.
  - nftables allows 514/tcp only from inventory NSIPs and SNIPs.
- **Pull** every 15 min over SSH. NITRO `systemfile` is capped at 32 MB from 13.1-56, so it isn't used.
  - Files: `ns.log*`, `bash.log`, `sh.log`, `notice.log`, `auth.log`, `httperror.log*`, `httpaccess.log`, `httpaccess-vpn.log`.
  - Checkpoints are `(fingerprint, offset)` per file, walking rotated `.N.gz`.
  - **A file that shrinks while keeping the same fingerprint raises a log-tampering finding.**
- **Dedup across push and pull:** key on (node, boot_id, PPE, event, seq, sha256(body)), with `ON CONFLICT DO NOTHING`.
- **Silence detection:** if NITRO shows a node as up but no syslog has arrived for N minutes, raise a high finding. SCALAR's own NITRO login `CMD_EXECUTED` doubles as a heartbeat.
- **Archive:**
  - Daily zstd per node, kept 1 year, with an `archive_manifest` sha256 chain.
  - The daily chain head goes to the SIEM as an external anchor.
  - `scalar search` greps the archive by time range.
  - `status` reports daily volume per node and the projected 1-year disk footprint, so the archive volume can be sized during M3.
- **PostgreSQL contents (90d, daily partitions):**
  - Security-relevant event classes: CMD_EXECUTED, UI/AAA login success and fail, auth rejects, shell commands, HA/EVENT, nsppe/pitboss/core, SSL/cert.
  - `session_observations` upserts.
  - 5-minute `event_rollups`.
  - Rule hits with `raw_ref`.
  - High-volume classes (SSLVPN TCPCONNSTAT/HTTPREQUEST/ICA*, TCP, ACL) go to archive and rollups only, after passing through the rule stream.
  - Indexes: BRIN on `ts`; B-tree on `(device_id, event_type, ts)`; partial indexes on user and client_ip.
  - Findings and config history are kept 400+ days.

## IOC catalogue (shipped as data, each entry carries source URL + confidence)
**Exposure check:**
- Parse `nsversion`, including the FIPS/NDcPP variants. Compare against `cve_builds.yaml`, gated on config: Gateway/AAA vservers, SAML IdP, IPv6 LB, and so on.
- Also flag end-of-maintenance trains.
- Warn if the data file is more than 30 days stale.
- Fixed builds to seed (re-verify against the Citrix bulletins at implementation time):

| CVE | Bulletin | 14.1 fixed | 13.1 fixed | 13.1-FIPS/NDcPP | Gate |
|---|---|---|---|---|---|
| 2023-3519 | CTX561482 | n/a | 49.13 | 37.159 | Gateway/AAA |
| 2023-4966 | CTX579459 | 8.50 | 49.15 | 37.164 | Gateway/AAA |
| 2025-5777 | CTX693420 | 43.56 | 58.32 | 37.235 | Gateway/AAA |
| 2025-6543 | CTX694788 | 47.46 | 59.19 | 37.236 | Gateway/AAA |
| 2025-7775 | CTX694938 | 47.48 | 59.22 | 37.241 | Gateway/AAA, IPv6 LB, HDX CR |
| 2026-3055 | CTX696300 | 66.59 (60.58 on one branch) | 62.23 | 37.262 | SAML IdP |
| 2026-8451 | CTX696604 | 72.61 | 63.18 | 37.272 | SAML IdP |
| 2026-8452 | CTX696604 | 72.61 | 63.18 | 37.272 | Gateway/AAA |
| 2026-19490 (also 19489) | CTX696939 | 73.32 | 63.21 | 37.277 | Gateway/AAA or SAML |
| 2026-88771/88772 | CTX697096 | 73.37 | 64.23 | 37.279 | default config / DTLS |
| 2026-88779 | CTX697174 | 73.41 | 64.28 | 37.282 | SAML SP or IdP |
| 2026-107406 | CTX697191 | 73.46 | 64.29 | 37.283 | SAML SP or IdP |

Minimum safe builds (every advisory above fixed): **14.1-73.46**, **13.1-64.29**, **13.1-FIPS/NDcPP 37.283**. `src/scalar/data/cve_builds.yaml` is the source of truth; this table is a summary.

**Log rules** (YAML; each rule must carry positive and negative test vectors):
- **CVE-2025-5777:** `AAA Message … Authentication is rejected for` containing bytes `\x80-\xff`.
- **Session IP mismatch (CVE-2023-4966/2025-5777):**
  - `Client_ip` differs from the TCPCONNSTAT source IP.
  - One SessionId is seen from multiple IPs.
  - `/logon/LogonPoint/Authentication/GetUserName` called with a scripted User-Agent before a real login.
- **CVE-2023-3519:** `\.sh` or `\.php` in `httperror.log`.
- **Key theft:** `/flash/nsconfig/keys` in `sh.log`/`bash.log`.
- **Shell-history patterns** (Mandiant):
  - `whoami$`
  - `cat /flash/nsconfig/keys`
  - `ldapsearch`
  - `chmod +x /tmp`
  - `openssl des3`
  - `cp /bin/sh`
  - `chmod +s /var`
  - `echo <?php`
  - curl, wget, nc, base64, `python -c`
- **CVE-2026-88771/88772:**
  - A command after `NSPPE;` in ns.log login-failure lines.
  - `pitboss PPE missed too many heartbeats`.
  - A base64 dropper in the User-Agent in `httpaccess-vpn.log`.
- **Generic:**
  - `CMD_EXECUTED` by an unexpected user or from an unexpected IP, or with high-risk verbs
  - brute force or spray
  - audit or syslog disabled
  - clock changes
  - HA failover
  - nsppe crash
- **IP IOCs:** imported lists such as Unit 42's, matched against client IPs and session observations.

**Host sweep** (FreeBSD read-only allowlist, both HA nodes, every 6h or on demand with `scan <device>`):
- **Webshell paths:**
  - `/netscaler/ns_gui/vpn/`, `/netscaler/ns_gui/epa/scripts/`
  - `/var/vpn/` (incl. `theme/.theme.php`, `themes/*.js`)
  - `/var/netscaler/logon/` (incl. `LogonPoint/uiareas`, `LogonPoint/custom/.ctxs.receiver`)
  - `/var/python/`, `/var/tmp/`, `/tmp/`, `/var/nstmp/`
  - `/netscaler/portal/templates/`, `/var/tmp/netscaler/portal/templates/`
- **NCSC-NL checks:**
  - `find /var/netscaler -type f \( -name '*.php' -o -name '*.xhtml' \)`, excluding `gui/admin_ui`.
  - Look for "twin" files that share a name with a legitimate file but have a different extension.
- **Fixed IOC paths:**
  - `/var/tmp/{the,npc}`, `/var/tmp/conf/{npc,multi_account}.conf`
  - `/var/netscaler/.ns_suidcmd`, `/var/tmp/sh`
  - `/netscaler/ns_monuploadd_err.pl` (hash compared to the baseline)
- **Setuid:**
  - `find / -xdev -type f -perm -4000 -user root` diffed against the stock list for that build.
  - `find /var \( -perm -4001 -o \( -perm -4010 -group nobody \) \) -user root`.
  - `/bin/sh` setuid bit.
- **Persistence:**
  - `/flash/nsconfig/rc.netscaler` (python), `nsbefore.sh`, `nsafter.sh`
  - `/var/cron/tabs/*` (especially `nobody`)
  - `/etc/httpd.conf`: php handlers, or `Require all denied` / `php_flag engine off` commented out
  - SSH `authorized_keys`
- **Content grep** on files under 10 MB in the sweep paths only:
  - `eval($_POST`, `base64_decode($_POST`, `@eval(`, `hex2bin(substr(`, `str_rot13(`
  - `openssl_public_decrypt`, `#nssecret#`, `chmod u+s`
  - `ligolo-ng`, `ehang.io/nps`, `passwd_hook`, UPX headers
- **Processes and other checks:**
  - Processes run by `nobody` other than httpd, or executing from `/var/tmp`.
  - Unexpected `sockstat -4l` listeners.
  - `NSPPE*` cores in `/var/core/`.
  - Files owned by `nobody` with group 0.
  - Known-bad SHA-256 list.
- **Baselines per firmware build:**
  - Because there's no lab, **fleet consensus** is the main source: a hash present on every node of build X is accepted, and outliers are findings.
  - It is backed by the IOC lists and by `baseline review`, where the admin acknowledges entries.
  - A TOFU baseline is marked *unreviewed* and is never trusted silently.
- **Self-noise:** every sweep or pull is logged in `tool_runs` (account, source IP, window, nonce), and the nonce is echoed into bash.log. Suppression requires **all** of these to match, never the account name alone.

## Telemetry
- **Sources:** NITRO `stat` every 60s: `ns`, `system` (CPU, mem, `/var` and `/flash` disk), `lbvserver`, `vpnvserver`, `aaa`, `ssl`, `hanode`, interfaces, plus `config/aaasession`.
- **Storage:** a narrow partitioned `telemetry` table.
- **Thresholds:**
  - CPU, mem and disk
  - session spikes
  - HA state change
  - nsppe restart, detected from boot_id or uptime

## Notifications
- **Delivery:** a transactional `notifications_outbox` with retries.
- **Router:** routes by severity, dedups on `dedup_key` with suppression windows, and rolls low-severity findings into a digest. A daily all-quiet digest also goes out.
- **Sinks:**
  - **SMTP** over STARTTLS.
  - **Webhook:** JSON, with a Slack formatter.
  - **SIEM (Cribl → CrowdStrike NG-SIEM):**
    - Transport: RFC 5424 over TLS with RFC 6587 octet-counting, or an HTTP POST to a Cribl HTTP/HEC source.
    - Format: **ECS-aligned JSON** by default, so Cribl can map it to CrowdStrike's parsing standard with little pipeline work. CEF is an option.
    - Content: findings, plus optional forwarding of all indexed events.
    - `docs/cribl-ngsiem.md` documents the field map and a sample Cribl route.
- **Outbound safety:** diffs are redacted, and every payload is scanned against the loaded secret values before it is sent.

## Data model (key tables)
| Area | Tables |
|---|---|
| Inventory | `ha_pairs`, `devices` (nsip, mode observe/active, refs, spki_pin, ssh_hostkey, log_tz/datefmt, build, boot_id) |
| Config | `config_blobs`, `config_snapshots`, `config_changes` (changes jsonb, attribution, unattributed, peer_converged) |
| Logs | `events` (daily partitions), `event_rollups`, `session_observations`, `checkpoints`, `archive_manifest` |
| Detection | `findings` (dedup_key, severity, state new/ack/resolved, evidence, suppressed_until), `sweep_runs`, `file_observations`, `baselines` (build, path, sha256, mode, source, reviewed_by) |
| Ops | `telemetry`, `notifications_outbox`, `tool_runs`, `audit_log` |

## CLI (v1)
- **Devices and credentials:**
  - `device add|list|test|pin|mode` (`add` pins the TLS SPKI and SSH host key after confirmation)
  - `cred set|list|rm|test|rotate`
  - `probe <device>`
  - `snippets <device>`
- **Config:** `config history|diff|show|export`.
- **Findings and scanning:**
  - `findings list|show|ack|resolve`
  - `scan <device>`
  - `exposure`
  - `search`
  - `status`
- **Rules and baselines:** `rules validate|test`, `baseline review`, `ioc import`.
- **Root-only, with the daemon stopped:** `bootstrap`, `db upgrade`, `vault rekey|backup`, `restore`.

## Hardening and deployment
- **Install (`install.sh`):**
  - Creates the `scalar` user and the `scalar-admin` group.
  - Builds a venv in `/opt/scalar` from hash-pinned dependencies.
  - Sets up PostgreSQL 16 on a local socket with peer auth.
  - Installs the rsyslog drop-in, the nftables rules and the tmpfiles entry.
- **systemd unit:**
  - `ProtectSystem=strict`, `ReadWritePaths=/var/lib/scalar /var/log/scalar`
  - `NoNewPrivileges`, empty `CapabilityBoundingSet`, `PrivateTmp`
  - `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`
  - `LoadCredentialEncrypted=scalar.vault-key`, `WatchdogSec=`
  - Target: `systemd-analyze security` < 2.0.
  - Test `MemoryDenyWriteExecute` with `cryptography` and `argon2-cffi` before enabling it.
  - Egress: there is no cloud secrets dependency, so `IPAddressDeny=any` with `IPAddressAllow=` covering only the NetScaler mgmt subnets, the SMTP relay, Cribl, localhost and DNS.
- **Logging:** SCALAR's own logs pass through a redacting filter.

## Milestones (each ends with something testable)
- **M0 – Skeleton and emulator.**
  - Repo, pyproject, ruff, `mypy --strict`, pytest CI.
  - **NetScaler emulator for tests:**
    - respx serving NITRO JSON, including errorcodes 354/444.
    - An asyncssh server with the CLI prompt, ` Done`, `shell`, FreeBSD output and rotating logs over SFTP.
  - `scalar probe`, strictly read-only. It reports:
    - SSH exec vs PTY behavior
    - SFTP availability for non-nsroot superusers
    - cmdPolicy endpoint coverage
    - whether `-managementlog` forwards shell logs
    - log date format and timezone
    - HA config differences
  - *Exit:* the probe passes against the emulator, and is then run on **one production secondary node** in a change window. The report is reviewed and the emulator is adjusted to match reality.
- **M1 – Credentials, inventory and service.**
  - Vault (AES-GCM, atomic writes, rekey, backup and restore), systemd-creds bootstrap, Argon2id escrow, `SecretProvider` resolver, lockout guard, control socket.
  - `device add` with pinning, `cred set|test|rotate`, **exposure check** (a NITRO `nsversion` read, so it's an early win), sandboxed unit.
  - *Exit:* on a 24.04 VM:
    - `bootstrap`, then `cred set`, then a daemon restart, then `cred test` works.
    - `vault backup`, a wipe of the VM, then `restore` with the passphrase recovers every entry.
    - A swapped cert or host key is refused.
    
    On production, `exposure` lists the vulnerable or EoM nodes.
- **M2 – Config-change alerts.**
  - Poller, snapshots, tokenizer, diff, risk scoring, outbox, SMTP, webhook and SIEM sinks, drift and tampering detection, HA convergence and failover handling.
  - *Exit:* fixture replays produce the expected findings. A real, approved, harmless prod change (e.g., a comment on a test object) alerts in under 2 minutes.
- **M3 – Syslog pipeline and core rules.**
  - rsyslog generation, tailer, parsers, archive hash chain, COPY writer, rollups, rule pack, session-reuse correlation, CMD_EXECUTED attribution (wired back into M2), silence and canary detection, Cribl JSON.
  - *Exit:* a 10M-line replay runs at 5k lines/s or more. Events show up in NG-SIEM via Cribl. The volume projection is used to size the 1-year archive disk.
- **M4 – SSH log pulls.**
  - Fingerprint checkpoints, dedup, truncation detection, additional logs.
  - *Exit:* hypothesis rotate/truncate simulations pass. On production, a deliberate syslog gap (filtered on the server side) is back-filled.
- **M5 – Host sweeps and IOC catalogue.**
  - Allowlist, sweep paths and content rules, fleet-consensus baselines, IOC hash and IP import.
  - *Exit:* emulator scenarios for each IOC fire. The first production sweep runs on a secondary node; its baseline is reviewed with `baseline review`, then sweeps are enabled fleet-wide.
- **M6 – Telemetry and polish.**
  - Stats, thresholds, partition and archive retention jobs, digests, security score, docs.
  - *Exit:* 7 days of stable operation, with `systemd-analyze security` < 2.0.

## Verification
- **Unit:**
  - Parser fixtures cover 13.1 and 14.1 line formats and all date formats and timezones.
  - Hypothesis property tests cover the nsconf tokenizer round-trip and the checkpoint state machine.
- **Rules:** pytest parametrizes over each rule's embedded vectors, and CI fails when a rule lacks positive or negative vectors. Add a corpus built from the published CitrixBleed/CitrixBleed 2/CVE-2026-88771 indicators.
- **Emulator end-to-end:** each IOC scenario is planted in the fake SSH filesystem and must fire. The same goes for each config-change class, HA failover with no false positives, session reuse, syslog silence and log truncation.
- **Integration:**
  - pytest-postgresql (PG16): Alembic up and down, partition lifecycle.
  - Outbox delivery to aiosmtpd, a TLS syslog sink and a webhook sink.
- **Security:**
  - Seeded secrets must never appear in logs or outbound payloads.
  - **Vault:**
    - Swapping entries (AAD), flipping bits, using a wrong `key_id`, or a truncated file must all fail.
    - Nonces must be unique across 10k writes.
    - A crash during a write must leave the old vault intact (atomic rename).
    - Rekey must preserve every entry.
    - A wrong escrow passphrase must be rejected.
    - Hypothesis round-trip tests.
  - Pin mismatches are refused.
  - The GET-only guard holds.
  - Self-suppression can't be triggered by account name alone.
- **System:** an Ubuntu 24.04 VM (Multipass, LXD or WSL2) runs `install.sh`. Check the security score, credential loading and the watchdog.
- **Production rollout:**
  1. `observe` mode on all nodes (NITRO only).
  2. `probe` on one secondary.
  3. Pulls on the secondary nodes.
  4. Sweeps on the secondary nodes.
  5. Then the primary nodes, one pair at a time.
- **Development:** code is written on Windows. Tests needing systemd or PostgreSQL run in WSL2 Ubuntu 24.04 or the VM.

## Deferred (not in v1)
- **Bitwarden provider.** Implement it as `secrets/bitwarden.py` behind the existing `SecretProvider` protocol, using refs like `bitwarden:<id>`.
  - **Secrets Manager:** the `bitwarden-sdk` package with a read-only machine-account token, sealed via systemd-creds the same way as the vault key.
  - **Password Manager:** `bw` CLI with API key login and unlock.
  - Add `cred migrate` to move `local:` entries over, and allow `local:` as an ordered fallback.
- **Web dashboard** and a **Prometheus endpoint**.
