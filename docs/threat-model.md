# netrescale threat model

## What we protect

| Asset | Where | Why it matters |
|---|---|---|
| NetScaler credentials (`nr_nitro`, `nr_sweep`) | `/var/lib/netrescale/vault` (AES-256-GCM) | `nr_sweep` is a superuser on every appliance |
| Vault master key | `/etc/credstore.encrypted/netrescale.vault-key` (systemd-creds, host key) | It decrypts the vault |
| Escrow / backup files | Offline (operator's custody) | With the passphrase, they recover the vault on any host |
| Config history | `/var/lib/netrescale/configs` (raw, 0600) | Forensic record. Contains NetScaler-encrypted secrets and password hashes |
| Findings | PostgreSQL findings/outbox, SIEM, email | Incident evidence |
| Raw syslog | `/var/lib/netrescale/archive`, daily zstd frames and manifests | Unredacted forensic data; treat backups as sensitive |
| Web login hashes | `/var/lib/netrescale/web-users.json` (Argon2id, 0600) | Authorizes browser access to monitoring evidence |

## Trust boundaries

1. **NetScaler → netrescale.** The appliances may be compromised, which is the reason this
   tool exists. Everything they return is untrusted input: parsers never execute it, and
   log lines are matched with regexes and never evaluated.
2. **netrescale → NetScaler.** netrescale is read-only: the NITRO client allows only GET and
   login/logout, and appliance changes are printed for a human to apply. TLS keys are
   pinned, so a man-in-the-middle can't collect credentials.
3. **Root on the netrescale server.** Root is trusted. Without a TPM, root can unseal the
   vault key and read every credential. This is the main residual risk; see below.
4. **Outbound notifications.** Email, webhooks and the SIEM receive redacted diffs and
   findings, never secrets. Payloads are checked against the in-memory secret values before
   sending, and a hit blocks the send.
5. **Browser access.** The separate dashboard uses local accounts, bounded Argon2 verification,
   login throttling, opaque HttpOnly/SameSite sessions, host/origin validation and CSRF checks.
   It has no vault key or appliance client. It is loopback-only by default; network access
   normally uses HTTPS, Secure cookies and a trusted local reverse proxy. Explicit
   `web.allow_http` opt-in supports trusted internal HTTP with a restricted client allowlist.
   In that mode, passwords, session cookies, submitted credentials and monitoring data are
   exposed to on-path observers; the network is part of the trust boundary. Authentication,
   CSRF and origin checks remain active. Local administrator,
   operator, and viewer roles are enforced by both the web API and daemon control socket.
   Mutations require recent authentication and produce administration audit records.
   SSO and MFA are not built in. Settings saved from the browser cannot change appliance
   addresses, TLS trust files, credential references, new appliances or notification
   destinations (`web.allow_sensitive_settings`, host-managed and false by default), so a
   compromised administrator session cannot redirect vault credentials to another host.

## Threats and mitigations

| Threat | Mitigation |
|---|---|
| Server compromise (root) exposes every NetScaler credential | Harden and monitor this server. `nr_nitro` is least-privilege (show/stat only). Restrict NSIP management access by ACL. Rotate credentials (`cred rotate`; an age finding fires after 90 days). Revisit when a TPM is available (`--with-key=host+tpm2`) |
| Stolen disk or backup of the server | The vault is useless without `/var/lib/systemd/credential.secret`. A full disk image includes it, so treat server backups as sensitive |
| Lost server, no recovery path | Passphrase escrow file and `vault backup`/`restore`. Test the restore on a VM |
| Credential spraying locks out NetScaler accounts | Lockout guard: one rejection blocks that credential on that device until it is rotated |
| MITM on the management network | SPKI pinning, checked before any HTTP bytes (and credentials) are sent. A pin change is a critical finding and polling stops |
| Attacker hides changes from the monitor | Independent running/saved config checks, recoverable findings, audit-command candidates when the feed is fresh, HA config comparison, and syslog-silence alerts. Polling can miss transient changes |
| Attacker tampers with logs | Ingest truncation detection and a raw archive whose hash-chain head is included in the daily digest. SSH pull cross-checks remain unimplemented |
| Secrets leak through logs or alerts | `Credential` objects never print secrets. A redacting log filter runs on all output. Outbound payloads are checked before sending. CLI arguments never carry passwords |
| Malicious config content (e.g. huge or odd quoting) | The tokenizer is bounded per line and rejects unterminated quotes. Diffs are capped in alerts |
| Vault file tampering or corruption | AES-GCM authentication with AAD binding each entry to its name and key id. A key-check block detects a wrong key. Writes are atomic, with a `.bak` copy |
| netrescale itself is exploited | Hardened systemd unit (no capabilities, `ProtectSystem=strict`, syscall filter, private users/tmp/devices, egress IP allowlist). Hash-pinned dependencies |

## Known gaps (tracked in design.md)

- **NetScaler formats:** log line formats and some NITRO response shapes come from
   documentation and public research. `netrescale probe` confirms read-only NITRO access,
   not all log formats. Inspect actual archived events on one production HA secondary
   before expanding the rollout.
- **Local trust:** PostgreSQL peer authentication and the local control socket trust the
   service OS user. The daemon checks the named account's role but a compromise of that OS
   identity is inside the local trust boundary. Root CLI bootstrap/rekey remains direct.
- **Configuration administration:** the daemon can atomically replace application config;
   the web sandbox cannot. Host-managed paths and OS group changes require offline migration.
   A web administrator can change monitoring targets or suppress monitoring by configuration,
   so administrator accounts must be limited to trusted operators.
- **Lockout state:** process-local, so restarts and independent CLI commands can retry
   rejected credentials. Do not rely on the guard across process lifetimes.
- **Restart correlation:** session and threshold windows are in memory. Pending records,
   input offsets, config comparisons, archive data and notification jobs survive restarts.
- **Per-account source restriction:** NetScaler has none, so management ACLs affect all
  administrators.
- **Bitwarden provider:** deferred. Only the local vault exists in v1.
