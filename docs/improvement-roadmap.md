# SCALAR improvement roadmap

_Review date: 2026-10-13. Baseline: release 0.4.3 (commit b8f7979)._

## How this was produced

The source was reviewed from seven angles, all read-only:

- log detection
- config detection
- exposure intelligence and zero-day response
- collection reliability
- security of the monitor itself
- alerting and triage
- engineering and release agility

An adversarial verifier then re-checked each finding against the code, the Citrix bulletins and CISA KEV. Many findings were corrected or downgraded, and none were refuted outright. A final completeness critic added 8 gaps the first pass missed. That makes **76 verified findings**, which collapse to about 50 distinct improvements once duplicates are merged.

Severity in this document means: *how much does this improve early detection of a NetScaler compromise, or the trustworthiness of the monitor's "all clear"?*

### What is already strong (keep it)

- **Read-only toward the appliances.** The NITRO guard and SPKI pinning are sound, and appliance actions are only ever printed for an admin to run.
- **Careful exposure engine.** Tri-state feature gates, UNKNOWN is never shown as "fine", and FIPS/NDcPP variants are handled.
- **Crash-consistent ingest.** Data is written to a pending journal before the database, with a hash-chained raw archive, truncation and replacement detection, and a PostgreSQL outbox.
- **Tested rules.** Every packaged rule must carry positive and negative test vectors, and CI runs them.
- **Careful web tier.** No DOM XSS sinks, a strict CSP, CSRF and Origin checks, and Argon2id password hashing.
- **Sandboxed manual hunts.** Hunts run in a separate process with time and memory caps.

## Tier 0: false assurance, fix first (implemented in this change set)

Today each of these lets the monitor show "healthy / not exposed / no alert" while the opposite is true.

| # | Problem | Fix |
|---|---|---|
| 0.1 | **Advisory data misses the October 2026 bulletins.** CTX697174 (CVE-2026-88779, in KEV) and CTX697191 (CVE-2026-107406, CVSS 9.5) are absent. Appliances patched only to the CVE-2026-88771 fix (14.1-73.37 / 13.1-64.23 / 13.1-FIPS 37.279) that run SAML are reported clean. Some existing entries are also wrong: CVE-2026-8452 has the wrong gate, CVE-2026-3055 has the wrong 14.1 fix, and FIPS/NDcPP trains are missing. | Add and correct `data/cve_builds.yaml` against the bulletins and bump `data_version`. Add a regression test for "14.1-73.37 + SAML is actionable". Detect DBS IPv6 servers in `collect/features.py`. |
| 0.2 | **The live syslog path labels every line as `nslog` or `bashlog`.** The four `http.yaml` rules (CVE-2019-19781, CVE-2023-3519 webshell requests, CVE-2026-88771 User-Agent dropper, GetUserName probing) and all auth.log rules **never fire live**. The classifier is an unanchored search, so a username containing ` sh[1]:` reroutes a line away from the CVE-2026-88771 and CitrixBleed 2 rules. Field extraction takes the first match anywhere in a line, so username text can spoof `Client_ip`. | Add a header-position classifier (RFC 3164 and RFC 5424 framing) in `parse/nslog.py`, anchored header parsing, and order-preserving field extraction. Every rule vector now replays through the live envelope in tests. |
| 0.3 | **Dedup key `rule\|device` mutes different evidence for 6 h on every sink, including the SIEM.** For example, an admin's `cat /var/tmp/x.log` hides an attacker's `chmod +x /var/tmp/...` on the same box. | Include an evidence digest in the dedup key (User, source IP, command), add an optional `dedup_by:`, and never suppress SIEM delivery. |
| 0.4 | **One malformed line or a PostgreSQL restart can stop all monitoring silently.** A poison batch replays and crash-loops forever. On restart with the DB down, the daemon sits in setup-error mode and never retries, while the systemd watchdog stays green. | Isolate failures per line, quarantine a pending batch after 3 failed attempts and raise a CRITICAL finding, retry readiness with backoff, handle SQLAlchemy errors in the worker loops, write to the local findings log before the DB, and set StartLimit values in the unit. |
| 0.5 | **The daemon drops exposure warnings.** Stale data, EoM/EoL, and UNKNOWN on exploited CVEs (e.g. a train missing from the table) never reach a sink or `status.json`. | Add needs-attention, data-stale and lifecycle findings, put advisory data and per-device posture in status, and make the CLI exit 2 on UNKNOWN for exploited CVEs. |
| 0.6 | **A silent audit feed *lowers* config-change severity.** Attribution `None` is treated as "no audit source", so "cut syslog, then add a responder policy" scores only its base risk. | Add an explicit attribution status. "Feed expected but silent" escalates to at least HIGH. HA secondaries and nodes never observed are excluded. |
| 0.7 | **A failing notification sink is invisible.** Status stays "healthy" and nothing is sent anywhere else. | Raise a `notification-sink-failing` finding on the *other* sinks after 15 min, and report degraded status. |
| 0.8 | **Pausing monitoring or reducing coverage raises nothing.** | Emit `monitor-coverage-reduced` on pause, and when settings remove a device or sink, disable syslog, or raise the silence threshold. |
| 0.9 | **Per-source coverage is invisible.** `bash.log` and `sh.log` can be missing for good while the digest says "All devices polled OK". | Track last-seen per (device, source) in status and the digest. |

### Tier 0 build: status and loose ends

Tier 0 was implemented, adversarially reviewed and fixed.

- **Test results:** 949 passed and 23 skipped, against a baseline of 529 passed. The extra skips are PostgreSQL-parametrized tests, which run in CI. mypy strict is clean. ruff reports only the 7 errors that were already there.
- **Data:** every advisory build was checked against its Citrix bulletin by two independent agents.

Still to do:

- **Validate classifier framing on real appliances.** The syslog tag map and the RFC 5424 vs RFC 3164 framing are inferred from documentation. Capture archive samples per firmware (`scalar archive search`) and confirm them, especially for `nsppe` and other daemons.
- **Tune `dedup_by` for noisy rules.** Rules that match on message or raw text intentionally keep one notification per rule and device, because unauthenticated senders can vary that text. Shell and `Command` rules now get actor + command keys.
- **Handle devices that cannot export management logs.** Add a per-device opt-out or the `-managementlog` posture check. HA secondaries over TCP and 13.1 non-FIPS builds would otherwise show "log sources never received" in every digest.
- **Merge the new unit settings on upgrade.** Existing installs only get the new `StartLimit*` settings if an admin merges `scalar.service.packaged`; the upgrade notes are in `docs/operations.md`.
- **Expect one duplicate notification after upgrading.** The dedup key format changed, so each rule and device may notify once more.
- **Expect one repeat sink-failure alert after a restart.** The failure clock now survives restarts and reloads, but the "already alerted" flag does not, so a sink that is still failing is reported once more.

Closed since the review:

- **Slow regex fixed.** `cve-2026-88771-injected-command` now uses a linear `raw_regex` (about 10 ms on a 256 KiB line, down from 25 s). A property test checks it matches exactly what the quadratic form matched.
- **`log-field-injection` rule added** (`gateway.yaml`, HIGH). It fires on the parser's `Field_injection` marker, with one notification key per set of forged fields.
- **`ConfigPoller` takes an `audit_status` callable** and passes the status straight to `from_config_diff`. The post-tick rewrite in `service.py` is gone. Pending findings now keep their audit status across a restart; before, the escalation was lost.
- **`Database.sink_backlog()` added.** The sink-failure episode reads it on the first pass after a start or reload, so neither resets the 15-minute clock. A notification that was stuck before the restart stays stuck: it is not counted as an outage.
- **Status data is shown in the web UI.** Devices and Health show exposure posture and the minimum safe build. Health also shows per-source log coverage. Delivery and Health show sink health and the outbox backlog.
- **Exposure table in `docs/design.md` updated** to match `cve_builds.yaml`. A test now checks the two stay consistent.

## Tier 1: next, the biggest early-detection gains

Each item is high impact and roughly M effort. The order is the recommended build order.

1. **Read-only file-integrity monitoring over NITRO `systemfile`.** This is the single largest blind spot. Today there is no visibility of webshells, modified logon pages, `rc.netscaler`/`nsafter.sh`, crontabs, `authorized_keys`, or core dumps in `/var/core` and `/var/crash`. `NitroClient.system_file()` already exists but is only used for `/var/log`.
   - **First, a feasibility spike:** confirm on 13.1 and 14.1 which directories a listing-only account can read.
   - **Then build:** a Tier A path list checked every probe and hashed (boot hooks, crontabs, ssh keys, httpd.conf), and Tier B web roots walked every 5–15 min. Alert on new script files or changed hashes.
   - **Account design:** use a *separate* listing-only account, so that `sc_nitro` can be narrowed to `/var/log` (see 1.7). Where NITRO refuses a path, NetScaler Console FIM or opt-in SSH sweeps are the fallback.
   - *(config-fim-systemfile, gap-collect-crash-artifacts)*
   - **Status: built against the emulator, not yet validated on an appliance.** The code is in `collect/fim.py`, with `NitroClient.list_files`/`walk_files`, `fim_loop` in the daemon, the opt-in `devices[].fim.enabled` and `defaults.fim`, and the `sc_fim` account snippet. Operator notes are in `docs/operations.md` under "File-integrity monitoring". The feasibility spike is the `prod_probe` test `tests/prod/test_fim_feasibility.py`; run it before enabling FIM on any device. An adversarial review found 8 defects: content that went unverified silently, lost or mis-graded changes, and gaps in the SSH-key deny list. All 8 were fixed and each has a regression test in `tests/unit/test_fim.py`. Known limit: symlinks inside watched directories cannot be told apart through NITRO. See "Needs validation on a real appliance" below.
2. **Assess the first baseline instead of trusting it.** The first poll silently accepts a config that may already be compromised. Run the forensic state checks on the baseline, emit a `baseline-inventory` finding (users, cmdPolicies, page-injection actions, auth servers, syslog destinations, management IPs), and add `scalar config approve`. *(config-baseline-unassessed)*
3. **Self-audit canary.** The monitor's own NITRO `show` calls should appear as `CMD_EXECUTED` in the forwarded audit log. Arm the check per device once it has been seen. Alert when it disappears, which means audit logging or forwarding was altered while other traffic still flows. Also alert when the monitor's own account is used from another IP. *(pipeline-self-audit-canary)*
4. **Appliance telemetry poller.** Poll `stat ns`, `hanode` and `nsversion` every `intervals.stats` seconds (the setting exists but is unused). Detect reboots (and force a full config fetch), HA failovers, degraded nodes, disk pressure, firmware upgrades and downgrades, and unmonitored HA peers. Feed a boot id into `SessionTracker` to stop false session-reuse findings after reboots. Print post-patch session-kill reminders once every node is fixed. *(pipeline-appliance-telemetry-missing, zeroday-post-patch-verification)*
5. **Zero-day content agility.**
   - Add a validated `content_dir` override for `cve_builds.yaml`, rules and config-risk data, so an emergency advisory or rule needs no reinstall. Add `scalar content status`, and record `data_version` and content hash in finding evidence.
   - Add a KEV + CVE.org (NetScaler CNA) watcher as a separate egress-allowed oneshot. It produces draft YAML only, never auto-activated.
   - Emit a "new or changed advisory affects devices X, Y" finding.
   - Build a chunked retro-hunt over the 365-day raw archive whenever a new advisory or CVE-tagged rule lands.
   - *(zeroday-signed-content-pack-updates, zeroday-kev-bulletin-watcher, zeroday-new-advisory-alert-and-retrohunt, eng-no-live-emergency-rule-path)*
6. **Promote behavior-based rules to live monitoring.** Today they exist only as manual hunts or are missing entirely:
   - commands run by the web user (`nobody`);
   - any write into the web roots, not only `.php`;
   - `perl -pi` edits of `httpd.conf`;
   - shell syntax in the CVE-2026-88779 username;
   - validated rules from the 39-rule compromise pack.

   Use a live path that is safe against slow regexes (bounded patterns or a timeout guard). *(logdet-exploit-agnostic-shell-behaviors, logdet-2026-signals-safe-live-promotion)*
7. **Make the monitor's privilege separation real.** The web UI and the daemon run as the same user. The control socket trusts a self-asserted `actor` and exposes `vault.backup`, which exports the vault master key. One phished dashboard password (there is no MFA) therefore yields every NetScaler credential. To fix:
   - run the web UI as its own `scalar-web` user with a read-mostly DB role;
   - remove `vault.backup`/`vault.restore` from the web (the root CLI keeps them);
   - hash-chain `administration.jsonl`;
   - send tamper findings through the *pre-change* sinks;
   - narrow the printed `scalar_ro` policy so `show system file` covers only `/var/log`;
   - have the daemon verify its own account's bindings.
   - *(sec-web-daemon-privsep-nominal, sec-monitor-tamper-not-alerted, sec-nitro-account-overbroad-unverified)*
8. **HA secondaries send no management logs.** NetScaler does not export management logs (shell, access, auth) from HA secondaries over TCP by default, and the printed snippet uses TCP. Add a posture check that the `auditsyslogaction` pointing here includes SHELL and ACCESS for this firmware, partition and HA role. Also add a scheduled read-only NITRO log pull from secondaries to reconcile against syslog, which also catches logs wiped on the box. *(gap-collect-nitro-log-pull-reconciliation, logdet-per-source-coverage-blindness)*

## Tier 2: strengthen detection and triage

**Log and session detection**
- Harden session correlation: persist sessions across daemon restarts, detect one IP using many session IDs, and tell roaming apart from hijacking (subnet/ASN and user-agent continuity). *(logdet-session-correlation-hardening)*
- First-seen baselines (admin source IP, user agent, admin user, off-hours) and multi-event sequences on one device. *(logdet-baselines-and-sequences)*
- Threat-intel watchlists for published exploitation IPs, applied live and retroactively. *(gap-logdet-ioc-watchlists)*
- Printed, log-only responder "tripwires" for exploit endpoints that leave no native log line, with a matching live rule. *(gap-logdet-appliance-request-tripwires)*
- Tune the predictable false positives in several HIGH/CRITICAL rules. *(logdet-rule-false-positive-tuning)*

**Config detection**
- Credential-exfiltration channels: `HTTP.REQ.USER.PASSWD`/body reads in callouts, rewrite and message actions; HTTP callouts; AppFlow; responder htmlpage. *(config-credential-exfil-channels)*
- Certificate content swaps, e.g. the SAML IdP signing cert. Compare `certkeydigest` from `GET sslcertkey`. *(config-certkey-content-drift)*
- Effective-privilege graph for cmdPolicies. This replaces the `.*` heuristic, which false-positives on SCALAR's own policy and misses `^shell` grants. *(config-cmdpolicy-privilege-graph)*
- Inventory outbound destinations (auth servers, syslog targets, callouts) and alert when one appears or changes. *(config-egress-trust-allowlist)*
- Per-feature semantics for `enable ns feature`, so that disabling AppFw or Bot is visible. *(config-feature-list-semantics)*
- Wire `config_intelligence.yaml` into one data-driven state engine. *(config-intelligence-unwired)*
- Shorter latency for on-disk `ns.conf` edits (currently up to 6 h) and for changes reverted between polls. *(config-out-of-band-latency)*

**Exposure data model**
- Per-train affected ranges and per-range gates; bulletin metadata (published, KEV date, references). *(zeroday-schema-affected-ranges)*
- Data-driven feature gates, including absence/negation semantics. *(zeroday-data-driven-feature-gates)*
- Lifecycle dates and a CI content lint for missing trains and cross-file CVE consistency. *(zeroday-lifecycle-dates-and-content-lint)*

**Appliance state over NITRO**
- Live Gateway/AAA sessions (`aaasession`). *(gap-collect-gateway-live-state)*
- Appliance connection table, to spot reverse tunnels, C2 egress and backdoor listeners. *(gap-collect-egress-listener-visibility)*
- Import results from IOC scanners such as the NCSC-NL and Mandiant tooling. *(gap-detect-ioc-scanner-import)*
- Capture volatile evidence automatically when a critical finding fires. *(gap-alert-triggered-volatile-capture)*

**Triage and response**
- **Missing `findings ack`:** the email footer tells responders to run it, but it does not exist. Add an ack/assign/resolve/false-positive/suppress lifecycle on top of the existing RBAC and audit trail. *(alert-no-triage-lifecycle)*
- A per-device compromise assessment status, *clean / unknown / suspicious*, with "unknown" whenever telemetry is missing, plus per-device compound escalation. *(alert-no-compromise-assessment, alert-no-compound-escalation)*
- Response guidance: post-patch session kills, "preserve evidence before patching" (CISA 2026-09-27 and CTX694799), and IR evidence bundles with archive hash-chain references. *(alert-response-guidance-gaps, alert-evidence-bundle)*
- Stateful findings (exposure, health) should send "resolved" instead of re-paging CRITICAL every day. *(alert-stateful-findings-repage)*
- ECS/OCSF entity fields and MITRE tags; PagerDuty/Teams formats; escalation for unacknowledged criticals. *(alert-siem-schema-mitre, alert-paging-channels)*

**Collection**
- Silence per source with episode-scoped alerts and a "gap closed" report; ingest lag and backpressure metrics; clock-skew checks; finer NITRO failure classes; a scheduled archive hash-chain verification.
- Off-host heartbeat to the SIEM, and a watchdog that only pings when collection is actually progressing. *(pipeline-dead-mans-switch)*

## Tier 3: engineering for fast, safe updates

- **Real-log regression corpus.** Sanitized lines from each firmware family and HA role, a false-positive budget, and a format-drift alert when the parse rate drops. All current vectors are synthetic. *(eng-synthetic-vectors-no-corpus, logdet-real-format-test-corpus)*
- Apply the strict `RuleSpec` schema to the packaged rules as well. *(eng-bundled-rule-schema-lenient)*
- **CI parity with production.** Install from the hashed `requirements.lock`, pin actions by SHA, add `pip-audit` and Dependabot. *(eng-ci-artifact-parity)*
- Record the rule-pack version and hash in every finding. *(eng-version-and-rule-fingerprint)*
- Database migrations (Alembic is declared but unused). *(eng-db-schema-evolution)*
- Replace the 43-branch admin dispatcher with a registry. *(eng-admin-dispatch-registry)*
- **Repo hygiene.** `venv/` (~2,900 files, Linux binaries) is committed, and the documented upgrade path runs it, which bypasses `--require-hashes`. Untrack it, build the venv fresh in `install.sh`, and remove the untracked root copies (`rules.py`, `hunt_rules.py`, `hunt_templates.yaml`, `design.md`, `README copy.md`) that invite editing the wrong file during an incident. *(sec-supply-chain-committed-venv, eng-repo-hygiene-duplicates)*

## Needs validation on a real appliance

- **Syslog framing per firmware.** 14.1-29+ exports management logs as RFC 5424. Capture samples from the raw archive and confirm the classifier's tag map.
- **File-integrity monitoring (Tier 1.1).** Run `tests/prod/test_fim_feasibility.py` (marker `prod_probe`) on an HA secondary of 13.1, 13.1-FIPS and 14.1, as `sc_fim` and once as `sc_nitro`, and confirm:
  - **Paths:** which watched directories each account can list and read; whether `/nsconfig`, `/var/pubkey`, `/var/cron/tabs` and `/etc` are listable through NITRO at all; and whether firmware restricts `systemfile` to a fixed set of locations.
  - **Listing shape:** the fields, the `filemode` values (array vs string, `DIRECTORY`), the `filesize` type, and whether a listing ever carries `filecontent`.
  - **Missing directories:** the HTTP status, errorcode and message for a directory that does not exist. `collect/fim.py` `_absent()` assumes 404, "no such file" or "does not exist"; anything else shows up as a permanent coverage gap.
  - **Command policy:** the exact command text NITRO `GET systemfile` is matched against (argument order, `-fileLocation` quoting); whether `\x22` in a cmdSpec matches a double quote; the maximum cmdSpec length; and that `sc_fim` is refused `/nsconfig/ssl`, `/nsconfig/keys` and `ns.conf`. These are the VERIFY lines in `appliance.py`.
  - **Reboots and upgrades:** whether a reboot re-extracts `/netscaler/ns_gui` or `/var/netscaler/logon` with new mtimes, and how many files a firmware upgrade changes. Tune `max_hashes`, `max_entries` and `walk_seconds` from these counts and the walk times.
  - **Audit-log noise:** how many `CMD_EXECUTED` lines one Tier A probe (about 6 listings) and one Tier B pass add to ns.log. This matters for the self-audit canary (Tier 1.3).
- **Management-log export behaviour.** Confirm whether HA secondaries export over TCP and UDP, and whether 13.1 non-FIPS builds can export at all.
- **Telemetry details.** Confirm whether `stat ns` `starttime` moves on PPE-only restarts, and whether pre-upgrade Gateway sessions survive HA failover (needed before alerting on "kill commands not run").
