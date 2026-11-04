# Feature Spec: NetScaler Appliance Forensics Module

## Context

This module grew out of an IR effort after the September 2026 NetScaler ADC/Gateway zero-days (CVE-2026-88771 plus related CVEs, patched around 2026-09-27). Public reporting states that these were exploited for weeks before disclosure, and that post-exploitation activity included webshells, credential theft, and lateral movement.

The investigation started with one question: **once the appliances have been patched, are NetScaler system backups still useful for forensics?**

The answer, which this module should put into practice:

- **Appliance backups are a baseline, not a log source.** `create system backup` archives capture config and customization state, but they do not contain runtime logs.
- **Patching does not erase most evidence.** Upgrades replace binaries and reboot the appliance, but `/var` and `/flash` generally persist. Logs, dropped files, and config changes usually survive. Memory-only artifacts do not.
- **Investigations need three evidence legs:** a pre-compromise backup (baseline), live appliance collection (logs and current state), and off-box logs such as SIEM/syslog (the tamper-resistant copy).

### Confidence legend

The markers below appear throughout this spec. Items marked INFERRED or VERIFY must be confirmed against real appliances or vendor documentation before the logic depends on them.

- **VERIFIED:** observed directly in a sample backup during analysis.
- **INFERRED:** reasoned from general NetScaler/FreeBSD behavior. Not confirmed for this CVE or build.
- **VERIFY:** CLI syntax or vendor behavior that must be tested before shipping.

---

## Component 1: Backup Ingestion and Inventory

### Input

A NetScaler system backup `.tgz`. The naming pattern observed was `Backup_<ip_with_underscores>_<DDMMYYYY>.tgz`.

### Observed archive structure (VERIFIED, single sample, NS13.1-63.18)

- All paths are rooted at `backup/`.
- The sample contained 330 entries.
- `backup/nsbackup.txt` holds the backup metadata: name, a level or type field, the creating user, the NetScaler version, and a Unix epoch timestamp. The exact field schema is not confirmed, so parse it tolerantly and log any unknown fields.
- `backup/nsconfig/` contains:
  - `ns.conf` and rotated history (`ns.conf.0` through `ns.conf.4`)
  - per-upgrade config snapshots
  - `ssl/`, which holds certs, private keys, and the F1/F2 KEK files
  - SSH host keys
  - `loginschema/`
  - `htmlinjection/ens/prebody.js`, `postbody.js`
  - `rc.netscaler`, `nsafter.sh`
- `backup/var/` contains:
  - `netscaler/logon/themes/`
  - `vpn/themes/`
  - `nslog/asl/` (see below)
  - `metrics_conf/*.json`
  - `nstemplates/*.json`
- `backup/var/nslog/` contains only `asl/`:
  - `total_xml_requests.db`: SQLite, table `t1(key, count_value)`
  - `dp_meta_data_v1.db`: SQLite, table `dl_meta_data(id, violation_id, url, field, alert_time, profile_name)`
  - `total_sessions`: a plain-text counter

  In the sample, both databases had 0 rows and 0 freelist pages, and the counter was `0`. The schema suggests these belong to an app-security or WAF analytics feature (INFERRED).
- **No runtime logs are present.** There are no `newnslog*`, `ns.log*`, `httpaccess.log*`, `messages*`, or `notice.log*` files.
- **All member mtimes are normalized to backup creation time.** File timestamps inside the backup carry no forensic value.

### Requirements

1. **Hash on ingest.** Compute a SHA-256 of the archive before anything else and store it with ingest time and operator (chain of custody).
2. **Stream, don't extract.** Enumerate and read members straight from the archive. Never extract onto shared storage, because archives contain private keys.
3. **Build a full member inventory:** path, size, mode, owner, and type.
4. **Classify log presence exhaustively.** Match the directory prefixes `var/nslog/`, `var/log/`, and every known log filename pattern. Do not rely on substring guesses.
   - *Lesson learned:* an early ad-hoc grep for `/log/` and `newnslog` missed the `var/nslog/` path entirely.
   - For every classification, report both the patterns checked and the matches found.
5. **Flag timestamp normalization.** If all mtimes are identical, or fall within a few seconds of the `nsbackup.txt` timestamp, emit a warning that the archive cannot support timeline analysis.
6. **Report a backup verdict:** `baseline-capable: yes/no` and `log-capable: yes/no`, with reasons.
7. **Assess the baseline window.** Compare the backup timestamp against a user-supplied earliest-suspected-compromise date. Label the backup `pre-window` (clean baseline candidate), `in-window` (suspect; never restore; treat as evidence), or `post-window`.
8. **Inspect SQLite artifacts.** Open member databases read-only (`file:...?mode=ro`) and report tables, row counts, and freelist page count. A freelist count greater than 0 means deleted pages may be carvable.
9. **Verify uploaded members.** When a user uploads individual files claiming to come from a backup, hash-compare them against the archive members and report MATCH or DIFF.

---

## Component 2: Configuration Analysis (single backup)

### Checks on `ns.conf`

1. **System users.** Parse `add system user` and `bind system user`, and resolve every command policy bound to each user or group.
2. **Command policy privilege analysis.** Flag any policy whose regex effectively grants a shell:
   - a plain `((shell))` or equivalent broad match counts as root-equivalent;
   - an unanchored `shell find` counts as root-equivalent, because `find -exec` allows arbitrary commands;
   - the same applies to other unanchored shell sub-commands that allow command execution (build a list of such binaries).
   - Emit a list of **superuser-equivalent accounts** for credential-rotation scoping.
3. **Malformed policy regexes.** Detect likely-broken alternations, such as a missing `|` between groups (observed in the sample), and report them as hygiene findings.
4. **Legacy password hash formats.** Flag users still on older hash formats (SHA1-era) as a hygiene finding. Confirm the exact format markers against a known build (VERIFY).
5. **Secret redaction in all output.** Redact any `-password` or `-encrypted` values and any key material. Never echo them.

### Persistence hook review

These files run at boot or are injected into user-facing pages. For each one, report its contents and a hash, and compare it against a known-clean reference hash for the same build when one is available. Don't judge them by reading alone.

- `nsconfig/rc.netscaler`
- `nsconfig/nsafter.sh`
- `nsconfig/htmlinjection/**`
- theme scripts under `var/netscaler/logon/themes/**` (for example, `*.pl` and `*.js`)

Maintain a reference-hash database keyed by NetScaler build.

### Sensitive-material flag

Detect unencrypted private keys (`*.key` without encryption headers) and KEK files, and show a prominent warning that the archive is secret-bearing. Include this in any exported report.

### Build exposure

Parse the version from `nsbackup.txt` and `ns.conf`, then compare it against a maintained table of CVE-affected build ranges. Flag builds that were exposed to other CVEs besides the one under investigation. The CVE-to-build data must come from vendor bulletins, not hardcoded guesses.

---

## Component 3: Baseline Diff (backup vs. live)

### Inputs

A pre-window backup and a current-state collection from the same appliance.

### Requirements

1. **Config diff.** Normalize both `ns.conf` files (strip comments and sort lines), then diff them. Categorize changes by risk:
   - **High:** new or changed `system user`/`group`/`cmdPolicy` bindings; `add responder`/`rewrite` policies (known exfil and persistence patterns); `add authentication` policies or LDAP/RADIUS server changes (credential capture); new `add ns ip`; management-access changes; new cert/key bindings.
   - **Medium/Low:** all other changes.
2. **File-tree diff.** Compare these trees:
   - `var/netscaler/logon/`
   - `var/vpn/`
   - `nsconfig/htmlinjection/`
   - `nsconfig/` boot hooks

   For each file, report whether it was added, removed, or changed (by hash). Files present only on the live side under web-served paths are the highest priority. Watch in particular for extensions such as `.php`, `.pl`, `.xhtml`, `.sh`, and `.py`.
3. **Handle rotation-only noise.** Recognize files that differ only because `ns.conf.N` rotated, and suppress them.

---

## Component 4: Live Collection Script Generator

The module generates per-appliance collection commands. The NetScaler shell is **FreeBSD**, so the Linux tooling assumptions that crept into the first draft must be avoided.

### Reference script (corrected version)

```sh
# From NetScaler CLI, type "shell" first
df -h /var
ls -laT /var/nslog/ /var/log/ | tee /var/tmp/loglist.txt
tar -czf /var/tmp/ir_logs_$(hostname)_$(date -u +%Y%m%dT%H%MZ).tgz \
  /var/nslog/newnslog* /var/log/ns.log* /var/log/httpaccess.log* \
  /var/log/messages* /var/log/notice.log*
sha256 /var/tmp/ir_logs_*.tgz /var/tmp/loglist.txt
```

Transfer the files off-box, re-hash them on the receiving side, compare the hashes, and delete them from `/var/tmp` once verified.

### Rationale by line

| Line | Purpose | Notes |
|---|---|---|
| `df -h /var` | Check free space first | The script writes to the evidence partition, and a full `/var` can destabilize the appliance. |
| `ls -laT ... \| tee` | Inventory existing files, sizes, and full timestamps before collection | `-T` gives the full timestamp on FreeBSD (VERIFY on build). Plain `-la` drops the year and seconds. |
| `tar -czf ...` | Bundle current and rotated logs | The filename carries hostname and UTC collection time. Globs pick up rotated `.gz` files. |
| `sha256 ...` | Hash at creation for chain of custody | FreeBSD uses `sha256`, not `sha256sum`. |

### Log sources and purpose

- `newnslog*`: binary event and counter log, read with `nsconmsg`.
- `ns.log*`: CLI and GUI command execution and auth events. Grep for command-execution markers such as `CMD_EXECUTED` (marker from prior incidents, VERIFY).
- `httpaccess.log*`: management web requests. Match these against the published 88771 request shape (see the watchTowr analysis).
- `messages*`: FreeBSD system log.
- `notice.log*`: additional system activity. The contents are not confirmed (VERIFY).

### Generator requirements

1. **Pre-flight disk check** with a configurable abort threshold.
2. **Warn on write contamination.** Writing to `/var` overwrites free space that could hold recoverable deleted files. Offer a **stream-to-remote mode**, e.g. `ssh nsroot@<nsip> "shell tar -czf - <paths>" > local.tgz`. How the NetScaler CLI passes quoted arguments to `shell` is untested (VERIFY per build before enabling).
3. **Treat non-matching globs as warnings.** A glob that matches nothing makes tar exit non-zero. Treat that as a warning, not a failure, and record which patterns matched nothing.
4. **Note active-file capture.** The current `ns.log` and `newnslog` may be captured mid-write, so the last entries can be partial.
5. **Generate reboot-urgency guidance.** Nodes not yet rebooted since patching may still hold memory-resident artifacts. Recommend imaging `/var` and `/flash` on those nodes immediately.

### Post-collection processing

1. **Report retention coverage.** Run `nsconmsg -K <file> -d setime` for each `newnslog` file to get its time range (VERIFY flag), and `-d event` for event dumps. Report whether retention reaches the start of the suspected exploitation window. If it doesn't, mark SIEM or syslog as the primary source.
2. **Always work on copies.** Never parse logs in place.

---

## Component 5: Disk-Image Path (VM-level backups)

This component applies when the appliance is a VPX with hypervisor-level backups or snapshots (e.g., Veeam, vSphere, Hyper-V, Azure).

1. Restore to an isolated environment only.
2. Mount read-only. The filesystem is FreeBSD UFS2, so something like `mount -t ufs -o ro,ufstype=ufs2 /dev/sdXN /mnt/...` on Linux should work. Identify the flash and var slices from the partition table; don't assume the mapping (INFERRED).
3. Hunt:
   - `find -newermt <window_start>` across `/var` and `/flash`
   - script and webshell extensions under `var/netscaler/logon`, `var/vpn`, `var/tmp`
   - `var/cron/tabs/*`
   - boot hooks
   - log greps as in Component 4
4. Unlike appliance backups, a disk image retains real mtimes, so timeline analysis is valid here.

---

## Component 6: Findings and Remediation Output

The report should include:

- **Evidence inventory** with hashes and timestamps.
- **Verdict per artifact:** baseline-capable, log-capable, and window position.
- **Superuser-equivalent account list** (from Component 2).
- **High-risk config and file diffs** (from Component 3).
- **Retention coverage gap statement** (from Component 4).
- **Recommended actions**, to trigger when RCE is confirmed or cannot be ruled out:
  - rotate every credential and secret present in config (admin accounts, LDAP/RADIUS bind accounts, and anything stored `-encrypted`);
  - reissue SSL certs and keys, and rotate the KEK;
  - kill active sessions, e.g. `kill aaa session -all` and `kill icaconnection -all` (VERIFY syntax per build);
  - check for vendor or community IOC scanners for the specific CVE before relying on custom logic;
  - **never restore an in-window backup.**
- **Upstream correlation pointers:** SIEM/syslog, NetScaler Console/ADM, and firewall egress logs from the NSIP/SNIP addresses.

---

## Test Fixtures and Acceptance Criteria

1. **Sample backup.** A synthetic backup that mirrors the observed structure (rooted at `backup/`, `nslog/asl` only, normalized mtimes). The module must:
   - report `log-capable: no` and `baseline-capable: yes`;
   - list the exact patterns it checked;
   - raise the timestamp-normalization warning.
2. **Backup with injected logs.** A variant that includes `var/nslog/newnslog.0`. The module must detect it, which is the regression test for the missed-path bug.
3. **Shell-grant policies.** A config with a `((shell))` policy and an unanchored `shell find` policy. Both must be flagged as superuser-equivalent.
4. **Live-only webshell.** A baseline/live pair where the live side has an extra `.php` under `var/netscaler/logon/`. It must be flagged High.
5. **Upload verification.** Individually uploaded files that match archive members must report MATCH, and altered files must report DIFF.
6. **Redaction.** No secret values should appear in any output. Assert this with a redaction scan over the generated reports.
7. **Generated scripts.** They must use `sha256` and `ls -laT`, never `sha256sum`.

## Data Handling Note

Real sample backups contain org-specific usernames, domains, and private keys. Use synthetic fixtures in the repo, and never commit a real backup or paste one into a prompt.
