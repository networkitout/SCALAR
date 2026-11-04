# netrescale

Self-hosted, **read-only** monitor for Citrix/NetScaler ADC/Gateway appliances: config-change
alerting (risk-scored diffs, drift/tamper detection), firmware CVE exposure checks, IOC hunting
in NetScaler logs, an encrypted local credential vault, and multi-channel notifications
(SMTP, webhook, SIEM). Python 3.12, deployed as a systemd daemon on Ubuntu 24.04. See
`docs/design.md` for the full design doc and `README.md` for the admin-facing CLI workflow.

## Build, test, lint

```bash
python -m venv .venv && . .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest -q --timeout 120      # full suite (emulator-backed; no real NetScaler needed)
ruff check src tests
mypy                          # strict; mypy_path=src, platform=linux even on Windows
```

Run a single test: `pytest tests/unit/test_nitro.py::test_login_rejects_bad_credentials -q`
(or `pytest tests/unit/test_nitro.py -k name`).

CI (`.github/workflows/ci.yml`) runs, in order: `ruff check src tests`, `mypy`,
`pytest -q --timeout 120`, and `bash -n deploy/install.sh`. Match this locally before pushing.

Pytest markers (see `pyproject.toml`): `linux` (requires systemd-creds/unix sockets/SO_PEERCRED
— skip or guard on non-Linux dev machines) and `prod_probe` (hits a real NetScaler; never runs
in CI).

## Architecture

```
NetScalers ──syslog──▶ rsyslog ──▶ per-node log files ──▶ log puller / host sweeps (SSH)
   └── NITRO HTTPS: GET-only, SPKI-pinned ◀── config poller / telemetry (src/netrescale/transport/nitro.py)
                 │
         parse ─▶ rule stream ─▶ findings ─▶ notifications (SMTP | SIEM/Cribl | webhook)
           ├─▶ raw archive (zstd, hash-chained)
           └─▶ findings/snapshot store
```

- `transport/nitro.py` — the only path to appliances. A request hook (`_enforce_read_only`)
  refuses any HTTP method except GET, plus POST to `/nitro/v1/config/login|logout`. Never add a
  code path that issues a mutating NITRO call; add emulator coverage instead
  (`tests/emulator/nitro.py` is a stateful `httpx.MockTransport` fake mirroring real
  login/logout/session-expiry/permission-denied behavior).
- `secrets/` — `SecretProvider` protocol (`base.py`) with `vault.py` (AES-256-GCM, versioned
  JSON, atomic write + `.bak`), `systemd_creds.py` (key sealing), `resolver.py` (`local:<name>`
  refs). Credentials are decrypted just-in-time and registered with `redact.py`'s
  `SecretRegistry` so they're scrubbed from logs/outbound payloads even if a call site forgets.
  Never pass secrets as CLI arguments or log them directly — always go through the registry.
  A credential rejected by the appliance is never retried (lockout guard); see
  `AuthRejected`/`on_auth_rejected` in `nitro.py`.
- `detect/` — config diff/risk scoring, CVE exposure assessment (gated on whether the
  vulnerable feature is actually configured), rule engine for log-based IOC hunting, session
  correlation.
- `parse/` — tokenizers/normalizers for `ns.conf` (`nsconf.py`), NetScaler logs (`nslog.py`),
  firmware version strings (`version.py`).
- `collect/` — config polling and feature detection against live devices.
- `daemon/` — the long-running service (`service.py`), systemd watchdog integration
  (`sdnotify.py`).
- `cli/main.py` — Typer CLI. Currently a thin-but-direct client (imports vault/detect/parse
  modules directly); the docs describe an eventual unix-socket control-plane split where the
  daemon is the only process holding secrets — keep new privileged logic daemon-side-ready.
- `data/*.yaml` — rule packs, CVE/build data, risk-scoring config; packaged via
  `tool.setuptools.package-data` in `pyproject.toml`.

## Conventions

- **Read-only toward NetScalers is a hard invariant**, enforced in code (not just by convention)
  in the NITRO transport. Any new appliance-facing feature must go through the same guard or
  print commands for an admin to run manually (see `appliance.py` / `netrescale snippets`).
- Devices default to `mode: observe` (NITRO only); SSH log pulls/host sweeps are opt-in per
  device only after `netrescale probe` passes.
- Secrets: register every decrypted value with `netrescale.redact.registry`; use
  `RedactingFilter` on loggers that might see secret-adjacent data.
- Ruff config (`pyproject.toml`) ignores `S101` (assert) and relaxes `S`/`B`/`E501` for
  `tests/**` (test vectors are real, unwrapped log/config lines) and `E501` for
  `appliance.py` (printed NetScaler CLI snippets must stay on one line). Don't "fix" those
  intentionally long/unsafe-looking lines.
- `mypy` runs in `strict` mode with `platform = "linux"` even when developing on
  Windows/macOS — don't rely on Windows-only stdlib behavior.
- Tests live in `tests/unit/` (pytest, `asyncio_mode = "auto"`) and `tests/emulator/` (fake
  NITRO server for integration-style tests without real hardware). Prefer extending the
  emulator over mocking `httpx` ad hoc when testing NITRO interactions.
