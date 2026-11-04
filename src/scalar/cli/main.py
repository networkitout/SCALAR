"""scalar command-line interface.

Until the daemon's control socket lands, admin commands that need secrets run directly
(as root): the vault key is unsealed with systemd-creds, and writes are atomic renames the
daemon picks up automatically.
"""

from __future__ import annotations

import asyncio
import getpass
import gzip
import json
import logging
import os
import socket
import sys
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, NoReturn, cast, get_args

import typer
from sqlalchemy.exc import SQLAlchemyError

from scalar import __version__
from scalar.appliance import device_snippet
from scalar.collect.features import detect_features
from scalar.config import DEFAULT_CONFIG_PATH, Config, Device, load_config
from scalar.daemon.service import run_service
from scalar.detect.config_diff import diff_configs, diff_lines
from scalar.detect.config_forensics import analyze_config
from scalar.detect.config_risk import load_risk_rules
from scalar.detect.exposure import (
    DeviceFeatures,
    ExposureReport,
    Status,
    assess,
    load_cve_data,
)
from scalar.detect.findings import Finding, from_rule_hit, from_session_reuse
from scalar.detect.rules import ListMatcher, RuleEngine, load_rules
from scalar.detect.sessions import SessionTracker
from scalar.detect.severity import Severity
from scalar.notify.formats import to_ecs
from scalar.parse.nsconf import config_lines, redact_config
from scalar.parse.nslog import DateFormat, parse_line
from scalar.parse.version import parse_version
from scalar.redact import RedactingFilter, registry
from scalar.rsyslog import nftables_conf, rsyslog_conf
from scalar.runtime import Runtime, default_key_loader
from scalar.secrets.base import Credential, CredentialError, validate_entry_name
from scalar.secrets.escrow import (
    check_passphrase_strength,
    make_backup,
    restore_backup,
    write_escrow,
)
from scalar.secrets.resolver import CredentialRef, stale_entries
from scalar.secrets.systemd_creds import seal_key, unseal_key
from scalar.secrets.vault import Vault, atomic_write, generate_key
from scalar.store.archive import RawArchive
from scalar.store.database import Database
from scalar.store.snapshots import FileSnapshotStore
from scalar.transport.nitro import NitroError
from scalar.transport.tls import fetch_peer_cert

app = typer.Typer(no_args_is_help=True, add_completion=False,
                  help="NetScaler log/IOC/config-change monitor.")
config_app = typer.Typer(no_args_is_help=True, help="Configuration files and config diffs.")
cred_app = typer.Typer(no_args_is_help=True, help="Encrypted local credential vault.")
vault_app = typer.Typer(no_args_is_help=True, help="Vault backup, restore and rekey (root).")
device_app = typer.Typer(no_args_is_help=True, help="Device pinning and connectivity.")
rules_app = typer.Typer(no_args_is_help=True, help="Detection rules.")
db_app = typer.Typer(no_args_is_help=True, help="PostgreSQL schema management.")
notify_app = typer.Typer(no_args_is_help=True, help="Notification delivery checks.")
archive_app = typer.Typer(no_args_is_help=True, help="Raw archive integrity.")
web_app = typer.Typer(no_args_is_help=True, help="Browser dashboard and local web accounts.")
app.add_typer(config_app, name="config")
app.add_typer(cred_app, name="cred")
app.add_typer(vault_app, name="vault")
app.add_typer(device_app, name="device")
app.add_typer(rules_app, name="rules")
app.add_typer(db_app, name="db")
app.add_typer(notify_app, name="notify")
app.add_typer(archive_app, name="archive")
app.add_typer(web_app, name="web")

ConfigOpt = Annotated[Path, typer.Option("--config", "-c", help="Path to config.yaml")]

_state: dict[str, Any] = {"config_path": DEFAULT_CONFIG_PATH}


@app.callback()
def _main(config: ConfigOpt = DEFAULT_CONFIG_PATH) -> None:
    _state["config_path"] = config


def _cfg() -> Config:
    path: Path = _state["config_path"]
    try:
        return load_config(path)
    except FileNotFoundError:
        _fail(f"config not found: {path} (use --config)")
    except Exception as exc:  # noqa: BLE001 - show validation problems plainly
        _fail(f"invalid config {path}:\n{exc}")


def _runtime(cfg: Config | None = None) -> Runtime:
    cfg = cfg or _cfg()
    return Runtime(cfg, _state.get("key_loader") or default_key_loader(cfg),
                   config_path=_state["config_path"])


def _database(cfg: Config) -> Database:
    return Database(cfg.database_url)


def _fail(msg: str, code: int = 1) -> NoReturn:
    typer.echo(f"error: {msg}", err=True)
    raise typer.Exit(code)


def _actor() -> str:
    user = os.environ.get("SUDO_USER") or getpass.getuser()
    return f"{user}@{socket.gethostname()}"


def _prompt_secret(prompt: str, confirm: bool = True) -> str:
    value = getpass.getpass(prompt)
    if confirm and getpass.getpass("Repeat: ") != value:
        _fail("values did not match")
    if not value:
        _fail("empty value")
    return value


@web_app.command("user-set")
def web_user_set(username: str,
                 service_user: Annotated[str, typer.Option()] = "scalar") -> None:
    """Create/reset a web user; prompt for a password, never accept it as an argument."""
    from scalar.web.auth import AuthenticationError, set_password

    cfg = _cfg()
    password = _prompt_secret("Web password (16+ characters): ")
    path = cfg.paths.state_dir / "web-users.json"
    try:
        set_password(path, username, password)
    except AuthenticationError as exc:
        _fail(str(exc))
    _chown_service(path, service_user)
    _chown_service(path.with_suffix(".lock"), service_user)
    typer.echo(f"Web account {username!r} saved. Existing sessions for this user are invalidated.")


@web_app.command("serve")
def web_serve() -> None:
    """Serve the dashboard with configured HTTPS or explicitly enabled internal HTTP access."""
    from scalar.web.server import serve

    cfg = _cfg()
    typer.echo(f"Dashboard: {cfg.web.public_url or f'http://{cfg.web.host}:{cfg.web.port}'}")
    serve(_state["config_path"])


@web_app.command("allow-http")
def web_allow_http(
    host: Annotated[str, typer.Option("--host", help="Specific server IPv4 address to listen on")],
    allow_network: Annotated[list[str], typer.Option(
        "--allow-network", help="Permitted client IP/CIDR; repeatable")],
    port: Annotated[int | None, typer.Option(min=1024, max=65535)] = None,
    restart: Annotated[bool, typer.Option(
        "--restart", help="Reload systemd and restart both services")] = False,
) -> None:
    """Explicitly allow internal HTTP and specified clients in the web unit (root only)."""
    import subprocess

    from scalar.web.server import configure_http

    if os.geteuid() != 0:
        _fail("run this host-configuration command with sudo")
    try:
        url = configure_http(_state["config_path"], host, allow_network, port=port)
    except (OSError, ValueError) as exc:
        _fail(f"HTTP configuration failed: {exc}")
    typer.echo(f"Configured dashboard: {url}")
    typer.echo("WARNING: HTTP sends login and credential data without encryption.")
    typer.echo("Allowed client networks: " + ", ".join(allow_network))
    typer.echo("Existing firewall rules and appliance TLS settings were not changed.")
    if restart:
        try:
            subprocess.run(["/usr/bin/systemctl", "daemon-reload"], check=True)
            subprocess.run(["/usr/bin/systemctl", "restart", "scalar", "scalar-web"],
                           check=True)
        except subprocess.CalledProcessError:
            _fail("settings saved, but a service restart failed; check systemctl status")
    else:
        typer.echo("Activate with: sudo systemctl daemon-reload && "
                   "sudo systemctl restart scalar scalar-web")


@web_app.command("preview")
def web_preview(port: Annotated[int, typer.Option(min=1024, max=65535)] = 8081) -> None:
    """Open an isolated sample-data UI on localhost; no credentials or appliances are accessed."""
    import uvicorn

    from scalar.web.demo import preview_app

    typer.echo(f"Preview only (sample data): http://127.0.0.1:{port}")
    uvicorn.run(preview_app(), host="127.0.0.1", port=port, access_log=False, proxy_headers=False)


@app.command()
def version() -> None:
    """Print the scalar version."""
    typer.echo(__version__)


# ---- config ---------------------------------------------------------------------------------


@config_app.command("validate")
def config_validate() -> None:
    """Validate config.yaml."""
    cfg = _cfg()
    typer.echo(f"OK: {len(cfg.devices)} device(s), {len(cfg.ha_pairs)} HA pair(s)")


@config_app.command("diff")
def config_diff(
    old: Annotated[Path, typer.Argument(help="Older ns.conf / running config")],
    new: Annotated[Path, typer.Argument(help="Newer ns.conf / running config")],
    peer: Annotated[bool, typer.Option(help="Ignore node-specific lines (HA peers)")] = False,
    limit: Annotated[int, typer.Option(help="Max changes to print")] = 500,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Risk-scored diff of two config files (secrets redacted). Works offline."""
    d = diff_configs(old.read_text("latin-1"), new.read_text("latin-1"), load_risk_rules(),
                     for_peer_compare=peer)
    if as_json:
        typer.echo(json.dumps([{
            "op": c.op, "severity": str(c.severity), "object": c.object, "name": c.name,
            "before": c.before, "after": c.after, "rules": list(c.rule_ids),
            "reasons": list(c.reasons)} for c in d.by_severity()], indent=2))
        return
    if d.empty:
        typer.echo("No configuration changes.")
        return
    typer.echo(f"{len(d.changes)} change(s), highest severity: {d.max_severity}  {d.counts()}")
    typer.echo(d.render(limit=limit))


@config_app.command("show")
def config_show(
    device: str,
    drift: Annotated[bool, typer.Option(help="Show running-vs-saved differences")] = False,
) -> None:
    """Fetch a device's running config over NITRO (redacted), or its unsaved changes."""
    rt = _runtime()
    d = _device(rt.cfg, device)

    async def run() -> None:
        async with rt.nitro_client(d) as c:
            running = await c.running_config()
            if not drift:
                typer.echo(redact_config(running))
                return
            saved = await c.saved_config()
            diff = diff_configs(saved, running, load_risk_rules())
            typer.echo("No unsaved changes." if diff.empty else diff.render())

    _run_async(run())


def _format_forensic_json(report: Any) -> dict[str, Any]:
    changed_users = [{
        "username": delta.username,
        "change": delta.change,
        "before": list(delta.before),
        "after": list(delta.after),
    } for delta in report.user_changes]
    exceptional = [{
        "kind": delta.kind,
        "object": delta.object,
        "name": delta.name,
        "severity": str(delta.severity),
        "rule_ids": list(delta.rule_ids),
        "before": delta.before,
        "after": delta.after,
    } for delta in report.exceptional_deltas]
    checks = [{
        "id": check.id,
        "severity": str(check.severity),
        "title": check.title,
        "summary": check.summary,
        "remediation": check.remediation,
        "evidence": list(check.evidence),
        "references": list(check.references),
        "mitre": list(check.mitre),
        "cves": list(check.cves),
    } for check in report.checks]
    critical = sum(1 for check in report.checks if check.severity.value >= 4)
    return {
        "summary": {
            "finding_count": len(report.checks),
            "critical_findings": critical,
            "highest_severity": str(report.max_severity),
            "normalized_line_count": report.normalized_line_count,
            "changed_management_users": len(report.user_changes),
            "exceptional_delta_count": len(report.exceptional_deltas),
            "changed_management_user_summary": [
                {
                    "username": delta.username,
                    "change": delta.change,
                }
                for delta in report.user_changes
            ],
            "exceptional_delta_summary": [
                {"kind": delta.kind, "object": delta.object, "name": delta.name,
                 "severity": str(delta.severity), "rule_ids": list(delta.rule_ids)}
                for delta in report.exceptional_deltas
            ],
        },
        "checks": checks,
        "user_changes": changed_users,
        "exceptional_deltas": exceptional,
    }


def _render_forensic_report(report: Any) -> str:
    critical = [check for check in report.checks if check.severity.value >= 4]
    lines: list[str] = []
    lines.append(
        f"Config forensic summary: {len(report.checks)} finding(s), highest severity "
        f"{report.max_severity}, critical={len(critical)}, "
        f"normalized lines={report.normalized_line_count}"
    )

    if report.user_changes:
        lines.append(
            "Changed management users: " + ", ".join(
                f"{delta.username}:{delta.change}" for delta in report.user_changes
            )
        )
    else:
        lines.append("Changed management users: none")

    if report.exceptional_deltas:
        lines.append(
            "Exceptional deltas: " + ", ".join(
                f"{delta.object}:{delta.kind}" for delta in report.exceptional_deltas
            )
        )
    else:
        lines.append("Exceptional deltas: none")
    lines.append("")

    if not report.checks:
        lines.append(
            "No forensic findings. The configuration is clean for the current "
            "offline checks."
        )
        return "\n".join(lines)

    if critical:
        lines.append("CRITICAL findings:")
        for check in critical:
            lines.append(f"  - {check.severity.name.upper()}: {check.title} ({check.id})")
            lines.append(f"    {check.summary}")
            if check.evidence:
                lines.append(f"    Evidence: {check.evidence[0]}")
            if check.remediation:
                lines.append(f"    Remediation: {check.remediation}")
        lines.append("")

    remaining = [check for check in report.checks if check not in critical]
    if remaining:
        lines.append("Other findings:")
        for check in remaining:
            lines.append(f"  - {check.severity.name.upper()}: {check.title} ({check.id})")
            if check.summary:
                lines.append(f"    {check.summary}")
    return "\n".join(lines)


@config_app.command("forensic")
def config_forensic(
    config: Annotated[Path, typer.Argument(help="NetScaler config file to inspect")],
    previous: Annotated[
        Path | None,
        typer.Option("--previous", "-p", help="Optional previous config for change comparison"),
    ] = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Offline forensic review of a NetScaler config (no secrets or appliance access required)."""
    try:
        text = config.read_text("latin-1")
        previous_text = previous.read_text("latin-1") if previous else None
    except OSError as exc:
        _fail(f"unable to read config: {exc}")

    report = analyze_config(text, previous_text=previous_text, device=config.stem)
    if as_json:
        typer.echo(json.dumps(_format_forensic_json(report), indent=2))
        return
    typer.echo(_render_forensic_report(report))


# ---- credentials ----------------------------------------------------------------------------

def _open_vault(rt: Runtime) -> Vault:
    try:
        return rt.provider.vault
    except CredentialError as exc:
        _fail(str(exc))


@app.command()
def bootstrap(
    escrow_out: Annotated[Path, typer.Option(help="Where to write the passphrase-wrapped "
                                                 "recovery key (move it offline afterwards)")],
    service_user: Annotated[str, typer.Option(help="Owner of the vault file")] = "scalar",
) -> None:
    """Create the vault and its master key (root, once per server)."""
    cfg = _cfg()
    if cfg.paths.vault.exists() or cfg.paths.sealed_vault_key.exists():
        _fail("vault or sealed key already exists; use `vault rekey` or `vault restore`")
    typer.echo("Choose an escrow passphrase (16+ characters). Without it, a rebuilt server "
               "cannot recover the vault.")
    passphrase = _prompt_secret("Escrow passphrase: ")
    try:
        check_passphrase_strength(passphrase)
    except CredentialError as exc:
        _fail(str(exc))
    key = generate_key()
    vault = Vault.create(cfg.paths.vault, key)
    seal_key(key, cfg.paths.sealed_vault_key)
    write_escrow(escrow_out, key, vault.key_id, passphrase)
    _chown_service(cfg.paths.vault, service_user)
    typer.echo(f"Vault created at {cfg.paths.vault} (key id {vault.key_id})")
    typer.echo(f"Sealed key: {cfg.paths.sealed_vault_key}")
    typer.echo(f"Escrow file: {escrow_out}  <-- store it offline, then delete it here")


def _chown_service(path: Path, user: str) -> None:
    try:
        import grp
        import pwd

        pw = pwd.getpwnam(user)
        os.chown(path, pw.pw_uid, grp.getgrgid(pw.pw_gid).gr_gid)
    except (ImportError, KeyError, PermissionError) as exc:
        typer.echo(f"warning: could not chown {path} to {user}: {exc}", err=True)


@cred_app.command("set")
def cred_set(
    name: str,
    username: Annotated[str | None, typer.Option(help="NetScaler username (default: NAME)")]
    = None,
    stdin: Annotated[bool, typer.Option("--stdin", help="Read the password from stdin")]
    = False,
    ssh_key_file: Annotated[Path | None, typer.Option(help="Optional SSH private key")] = None,
) -> None:
    """Add or replace a credential. The password is never accepted as an argument."""
    try:
        validate_entry_name(name)
    except CredentialError as exc:
        _fail(str(exc))
    rt = _runtime()
    vault = _open_vault(rt)
    password = sys.stdin.readline().rstrip("\n") if stdin else _prompt_secret("Password: ")
    key_text = ssh_key_file.read_text() if ssh_key_file else None
    vault.set(name, Credential(username or name, password, key_text), actor=_actor())
    rt.guard.clear(CredentialRef("local", name))
    users = rt.cfg.credential_users().get(f"local:{name}", [])
    typer.echo(f"Stored {name!r}" + (f" (used by: {', '.join(users)})" if users else
                                     " (not referenced by any device yet)"))


@cred_app.command("list")
def cred_list() -> None:
    """List credentials (never shows passwords)."""
    rt = _runtime()
    vault = _open_vault(rt)
    users = rt.cfg.credential_users()
    stale = {m.name for m in stale_entries(vault, rt.cfg.max_credential_age_days)}
    rows = [("NAME", "USERNAME", "UPDATED", "BY", "USED BY")]
    for m in vault.list_meta():
        rows.append((m.name + (" (stale)" if m.name in stale else ""), vault.get(m.name).username,
                     m.updated.strftime("%Y-%m-%d"), m.rotated_by,
                     ",".join(users.get(f"local:{m.name}", [])) or "-"))
    _table(rows)
    missing = sorted(r for r in users if r.startswith("local:") and r[6:] not in vault)
    if missing:
        typer.echo(f"\nReferenced but missing: {', '.join(missing)}", err=True)


@cred_app.command("rm")
def cred_rm(name: str, yes: Annotated[bool, typer.Option("--yes")] = False) -> None:
    """Delete a credential."""
    rt = _runtime()
    vault = _open_vault(rt)
    users = rt.cfg.credential_users().get(f"local:{name}", [])
    if users and not yes:
        _fail(f"{name} is used by {', '.join(users)}; pass --yes to delete anyway")
    vault.delete(name)
    typer.echo(f"Deleted {name!r}")


@cred_app.command("test")
def cred_test(name: str) -> None:
    """Log in with a credential on every device that uses it (NITRO, read-only)."""
    rt = _runtime()
    ref = f"local:{name}"
    devices = [rt.cfg.device(n) for n in rt.cfg.credential_users().get(ref, [])
               if ref in (rt.cfg.nitro_ref(rt.cfg.device(n)), rt.cfg.fim_ref(rt.cfg.device(n)))]
    if not devices:
        _fail(f"no device uses {ref} for NITRO (SSH credentials are tested by `probe`)")

    async def run() -> int:
        bad = 0
        for d in devices:
            try:
                async with rt.nitro_client(d, credential=ref) as c:
                    v = await c.version_string()
                typer.echo(f"OK    {d.name:<20} {v}")
            except (NitroError, OSError, CredentialError) as exc:
                bad += 1
                typer.echo(f"FAIL  {d.name:<20} {exc}")
        return bad

    if _run_async(run()):
        raise typer.Exit(1)


@cred_app.command("rotate")
def cred_rotate(name: str) -> None:
    """Store a new password, then immediately test it on every device that uses it."""
    cred_set(name)
    cred_test(name)


# ---- vault (root) ---------------------------------------------------------------------------


@vault_app.command("backup")
def vault_backup(out: Path) -> None:
    """Write a passphrase-protected, self-contained vault backup."""
    rt = _runtime()
    vault = _open_vault(rt)
    passphrase = _prompt_secret("Backup passphrase (16+ chars): ")
    atomic_write(out, make_backup(vault, rt.provider.key, passphrase))
    typer.echo(f"Backup written to {out} ({len(vault.names())} entries)")


@vault_app.command("restore")
def vault_restore(backup: Path,
                  service_user: Annotated[str, typer.Option()] = "scalar") -> None:
    """Restore a backup on this host and seal its key with this host's key."""
    cfg = _cfg()
    if cfg.paths.vault.exists():
        _fail(f"{cfg.paths.vault} exists; move it away first")
    passphrase = _prompt_secret("Backup passphrase: ", confirm=False)
    try:
        vault, key = restore_backup(backup.read_bytes(), passphrase, cfg.paths.vault)
    except CredentialError as exc:
        _fail(str(exc))
    seal_key(key, cfg.paths.sealed_vault_key)
    _chown_service(cfg.paths.vault, service_user)
    typer.echo(f"Restored {len(vault.names())} entries; key sealed for this host.")


@vault_app.command("rekey")
def vault_rekey(escrow_out: Path) -> None:
    """Replace the master key, re-encrypt every entry, write a new escrow file."""
    cfg = _cfg()
    old_key = unseal_key(cfg.paths.sealed_vault_key)
    vault = Vault.open(cfg.paths.vault, old_key)
    passphrase = _prompt_secret("New escrow passphrase (16+ chars): ")
    check_passphrase_strength(passphrase)
    new_key = generate_key()
    new_vault = vault.rekey(new_key)
    seal_key(new_key, cfg.paths.sealed_vault_key)
    write_escrow(escrow_out, new_key, new_vault.key_id, passphrase)
    typer.echo(f"Rekeyed to key id {new_vault.key_id}. Restart scalar. "
               f"Old escrow files no longer work; store {escrow_out} offline.")


# ---- devices --------------------------------------------------------------------------------


@device_app.command("allow-network")
def device_allow_network(
    restart: Annotated[bool, typer.Option(
        "--restart", help="Reload systemd and restart monitoring")]
    = False,
) -> None:
    """Allow configured ADC management IPs through the monitoring service's egress guard (root)."""
    import subprocess

    from scalar.appliance import allow_appliance_network

    if os.geteuid() != 0:
        _fail("run this host-configuration command with sudo")
    try:
        addresses = allow_appliance_network(_cfg())
    except (OSError, ValueError) as exc:
        _fail(str(exc))
    typer.echo("Allowed appliance management addresses: " + ", ".join(addresses))
    typer.echo("Read-only NITRO, TLS pinning, firewall rules, and web access are unchanged.")
    if restart:
        try:
            subprocess.run(["/usr/bin/systemctl", "daemon-reload"], check=True)
            subprocess.run(["/usr/bin/systemctl", "restart", "scalar"], check=True)
        except subprocess.CalledProcessError:
            _fail("network settings saved, but monitoring restart failed; check systemctl status")
    else:
        typer.echo("Activate with: sudo systemctl daemon-reload && "
               "sudo systemctl restart scalar")


@device_app.command("pin")
def device_pin(host: str, port: Annotated[int, typer.Option()] = 443,
               yes: Annotated[bool, typer.Option("--yes")] = False) -> None:
    """Show a management certificate and print its SPKI pin for config.yaml (TOFU).

    Compare the fingerprint with what you see in the NetScaler GUI (Traffic Management >
    SSL > Certificates) or `show ssl certKey ns-server-certificate` before trusting it.
    """
    try:
        info = fetch_peer_cert(host, port)
    except OSError as exc:
        _fail(f"cannot connect to {host}:{port}: {exc}")
    typer.echo(f"Subject:     {info.subject}")
    typer.echo(f"Issuer:      {info.issuer}{'  (self-signed)' if info.self_signed else ''}")
    typer.echo(f"Valid:       {info.not_before:%Y-%m-%d} .. {info.not_after:%Y-%m-%d}")
    typer.echo(f"SPKI sha256: {info.spki_sha256}")
    if info.not_after < datetime.now(UTC):
        typer.echo("note: certificate is expired; the key pin still works", err=True)
    if not yes and not typer.confirm("Does this match the appliance's certificate?"):
        raise typer.Exit(1)
    typer.echo(f'\n    spki_pin: "{info.spki_sha256}"')


@device_app.command("test")
def device_test(device: str) -> None:
    """NITRO login and version check for one device."""
    rt = _runtime()
    d = _device(rt.cfg, device)

    async def run() -> None:
        async with rt.nitro_client(d) as c:
            typer.echo(await c.version_string())
            state = await c.config_state()
            typer.echo(f"last config change: {state.get('lastconfigchangedtime')}; "
                       f"last save: {state.get('lastconfigsavetime')}; "
                       f"unsaved changes: {state.get('configchanged')}")
            for node in await c.ha_nodes():
                typer.echo(f"HA node {node.get('id')}: {node.get('ipaddress')} "
                           f"{node.get('state')} {node.get('hastatus', '')}")

    _run_async(run())


@app.command()
def probe(device: str) -> None:
    """Read-only NITRO readiness check; does not enable SSH or change the appliance."""
    rt = _runtime()
    target = _device(rt.cfg, device)

    async def run() -> None:
        async with rt.nitro_client(target) as client:
            version = await client.version_string()
            await client.config_state()
            running = await client.running_config()
            saved = await client.saved_config()
            await client.ha_nodes()
            await detect_features(client)
        typer.echo(f"OK {target.name}: {version}")
        typer.echo("Running/saved configuration readable "
               f"({len(running)} / {len(saved)} characters)")
        typer.echo("NITRO observe-mode checks passed. SSH collection is not enabled.")

    _run_async(run())


# ---- exposure -------------------------------------------------------------------------------


@app.command()
def exposure(
    device: Annotated[list[str] | None, typer.Option(help="Limit to these devices")] = None,
    version_string: Annotated[str | None, typer.Option(
        "--version-string", help="Assess a version string offline instead of polling")] = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Check firmware builds against the bundled CVE table. Exit code 2 if action is needed,
    including when exposure to an exploited advisory cannot be determined."""
    data = load_cve_data()
    reports: list[ExposureReport] = []
    failed = 0
    if version_string:
        reports.append(assess("(offline)", parse_version(version_string), DeviceFeatures(),
                              data))
    else:
        rt = _runtime()
        targets = [_device(rt.cfg, n) for n in device] if device else rt.cfg.devices

        async def run() -> None:
            nonlocal failed
            for d in targets:
                try:
                    async with rt.nitro_client(d) as c:
                        v = parse_version(await c.version_string(), d.firmware_variant)
                        feats = await detect_features(c)
                    reports.append(assess(d.name, v, feats, data))
                except (NitroError, OSError, CredentialError, ValueError) as exc:
                    failed += 1
                    typer.echo(f"{d.name}: cannot assess: {exc}", err=True)

        _run_async(run())
    if as_json:
        typer.echo(json.dumps([_report_json(r) for r in reports], indent=2))
    else:
        for r in reports:
            _print_report(r)
    if failed or not reports:
        raise typer.Exit(1)
    if any(r.actionable or r.needs_attention for r in reports):
        raise typer.Exit(2)


def _report_json(r: ExposureReport) -> dict[str, Any]:
    return {"device": r.device, "version": str(r.version), "lifecycle": r.lifecycle_status,
            "lifecycle_note": r.lifecycle_note, "worst": str(r.worst),
            "data_version": r.data_version.isoformat() if r.data_version else None,
            "min_safe_build": str(r.min_safe_build) if r.min_safe_build else None,
            "needs_attention": [x.advisory.id for x in r.needs_attention],
            "warnings": r.warnings,
            "results": [{"cve": x.advisory.id, "status": str(x.status),
                         "fixed_in": str(x.fixed_in) if x.fixed_in else None,
                         "gate": x.gate_detail, "exploited": x.advisory.exploited,
                         "bulletin": x.advisory.bulletin, "verified": x.advisory.verified,
                         "post_patch_actions": list(x.advisory.post_patch_actions)}
                        for x in r.results]}


def _print_report(r: ExposureReport) -> None:
    typer.echo(f"\n{r.device}: {r.version}  [{r.lifecycle_status}]  -> {r.worst}")
    for w in r.warnings:
        typer.echo(f"  ! {w}")
    if r.needs_attention:
        typer.echo(f"  ! cannot determine exposure to {len(r.needs_attention)} advisory(ies) "
                   f"(train {r.version.train} not in advisory data); treat as exposed until "
                   "checked against the bulletins")
    if r.min_safe_build:
        typer.echo(f"  minimum safe build on {r.version.train}: {r.min_safe_build}")
    for x in r.results:
        if x.status in (Status.NOT_AFFECTED, Status.FIXED):
            continue
        fix = f"fixed in {x.fixed_in}" if x.fixed_in else "no fix on this train"
        gate = f" [{x.gate_detail}]" if x.gate_detail else ""
        typer.echo(f"  {x.status:<22} {x.advisory.id:<16} {fix}{gate}")


# ---- hunting / rules ------------------------------------------------------------------------


@app.command()
def hunt(
    files: Annotated[list[Path], typer.Argument(help="Log files (plain or .gz)")],
    source: Annotated[str, typer.Option(help="nslog|bashlog|shlog|httperror|httpaccess|"
                                              "httpaccess-vpn|notice|auth")] = "nslog",
    device: Annotated[str, typer.Option(help="Device name to attribute events to")] = "unknown",
    date_format: Annotated[str, typer.Option(help="MMDDYYYY|DDMMYYYY|YYYYMMDD")] = "YYYYMMDD",
    admin_networks: Annotated[list[str] | None, typer.Option(
        help="CIDR allowed for management (repeatable)")] = None,
    admin_users: Annotated[list[str] | None, typer.Option(help="Known admin (repeatable)")]
    = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Run the detection rules over exported log files (offline IOC hunt)."""
    lists = {}
    if admin_networks:
        lists["admin_networks"] = ListMatcher(admin_networks)
    if admin_users:
        lists["admin_users"] = ListMatcher(admin_users)
    if date_format not in get_args(DateFormat):
        _fail(f"--date-format must be one of {', '.join(get_args(DateFormat))}")
    fmt = cast(DateFormat, date_format)
    engine = RuleEngine(load_rules(), lists)
    tracker = SessionTracker()
    findings = []
    for path in files:
        opener = gzip.open if path.suffix == ".gz" else open
        with opener(path, "rb") as fh:
            for raw in fh:
                ev = parse_line(source, raw.decode("latin-1"), device, fmt)
                findings += [from_rule_hit(h) for h in engine.evaluate(ev)]
                findings += [from_session_reuse(s) for s in tracker.observe(ev)]
    if as_json:
        for f in findings:
            typer.echo(json.dumps(to_ecs(f), default=str))
    else:
        for f in findings:
            typer.echo(f"[{f.severity}] {f.observed_at:%Y-%m-%d %H:%M:%S} {f.rule_id}: "
                       f"{f.summary}")
            line = f.evidence.get("line")
            if line:
                typer.echo(f"    {line[:300]}")
        if engine.disabled:
            typer.echo("\nRules skipped (pass --admin-networks/--admin-users to enable): "
                       + ", ".join(sorted(engine.disabled)), err=True)
        typer.echo(f"\n{len(findings)} finding(s)", err=True)


@rules_app.command("list")
def rules_list() -> None:
    """List the bundled detection rules."""
    rows = [("ID", "SEVERITY", "SOURCES", "CVE")]
    for r in load_rules():
        rows.append((r.id, str(r.severity), ",".join(sorted(r.sources)) or "*",
                     ",".join(r.cve) or "-"))
    _table(rows)


@app.command()
def snippets(device: str, server_ip: Annotated[str, typer.Option(
        help="This server's IP as the NetScalers reach it (syslog target)")]) -> None:
    """Print the NetScaler commands to create scalar's accounts and syslog target."""
    cfg = _cfg()
    typer.echo(device_snippet(cfg, _device(cfg, device), server_ip))


@app.command("rsyslog-config")
def rsyslog_config(port: Annotated[int, typer.Option()] = 514,
                   nft: Annotated[bool, typer.Option("--nft", help="Print nftables rules")]
                   = False) -> None:
    """Print the rsyslog drop-in (or nftables rules) for the configured devices."""
    cfg = _cfg()
    typer.echo(nftables_conf(cfg, port) if nft else rsyslog_conf(cfg, port))


# ---- service, findings, history -------------------------------------------------------------


@db_app.command("init")
def database_init() -> None:
    """Initialize the PostgreSQL schema (run as the scalar service user)."""
    database = _database(_cfg())
    try:
        database.initialize()
        typer.echo("Database schema is ready.")
    except (SQLAlchemyError, ValueError) as exc:
        _fail(f"database initialization failed: {type(exc).__name__}")
    finally:
        database.close()


@app.command()
def status(as_json: Annotated[bool, typer.Option("--json")] = False) -> None:
    """Show daemon freshness, device/feed health, and pending notifications."""
    cfg = _cfg()
    path = cfg.paths.state_dir / "status.json"
    try:
        doc = json.loads(path.read_bytes())
        updated = datetime.fromisoformat(doc["updated_at"])
        if datetime.now(UTC) - updated > timedelta(seconds=60):
            doc["state"] = "stale"
    except FileNotFoundError:
        doc = {"state": "not-running", "warnings": ["No daemon status is available"]}
    except (OSError, ValueError, KeyError):
        doc = {"state": "unavailable", "warnings": ["Cannot read daemon status"]}
    database = _database(cfg)
    try:
        doc["database"] = database.counts()
        if doc["database"]["pending_notifications"] and doc["state"] == "healthy":
            doc["state"] = "degraded"
    except SQLAlchemyError:
        doc["database"] = {"error": "PostgreSQL is unavailable or uninitialized"}
        doc["state"] = "degraded"
    finally:
        database.close()
    if as_json:
        typer.echo(json.dumps(doc, indent=2, default=str))
    else:
        typer.echo(f"Service: {doc['state']}")
        for warning in doc.get("warnings", []):
            typer.echo(f"Warning: {warning}")
        for name, health in doc.get("devices", {}).items():
            nitro = health["nitro"]
            feed = health["syslog"]
            typer.echo(f"{name}: last poll={nitro['last_ok'] or 'never'}; "
                       f"failures={nitro['failures']}; syslog={feed['last_received'] or 'never'}; "
                       f"lines={feed['lines']}")
            if feed.get("missing_sources"):
                typer.echo(f"  log sources never received: {', '.join(feed['missing_sources'])}")
            posture = (health.get("exposure") or {}).get("posture")
            if posture:
                attention = posture.get("needs_attention") or []
                typer.echo(f"  exposure: {posture.get('worst')} on {posture.get('version')} "
                           f"[{posture.get('lifecycle')}]"
                           + (f"; undetermined: {', '.join(attention)}" if attention else ""))
        typer.echo(f"Database: {json.dumps(doc['database'])}")
    if doc["state"] != "healthy":
        raise typer.Exit(1)


@notify_app.command("test")
def notify_test() -> None:
    """Queue a test alert through the daemon's durable delivery pipeline."""
    cfg = _cfg()
    targets = [name for name in ("smtp", "siem", "webhook") if getattr(cfg.notify, name)]
    if not targets:
        _fail("no notification sinks configured")
    database = _database(cfg)
    try:
        database.save_finding(Finding(
            f"notification-test|{uuid.uuid4()}", "notification-test", "SCALAR delivery test",
            Severity.CRITICAL, "health", None, "Operator-requested notification delivery test"),
            targets)
    except SQLAlchemyError as exc:
        _fail(f"cannot queue test notification: {type(exc).__name__}")
    finally:
        database.close()
    typer.echo("Queued for " + ", ".join(targets) + ". The running daemon will deliver it.")


@archive_app.command("verify")
def archive_verify(device: str, expected_head: str | None = None,
                   days: Annotated[int, typer.Option(min=1)] = 365) -> None:
    """Verify retained raw payloads and the manifest chain, optionally against a SIEM anchor."""
    cfg = _cfg()
    _device(cfg, device)
    archive = RawArchive(cfg.paths.state_dir / "archive")
    try:
        count = archive.verify(device, since=(datetime.now(UTC) - timedelta(days=days)).date(),
                               expected_head=expected_head)
    except (OSError, ValueError) as exc:
        _fail(str(exc))
    typer.echo(f"Verified {count} retained batch(es); head={archive.head(device)}")


@app.command()
def search(text: str, device: str,
           days: Annotated[int, typer.Option(min=1)] = 7,
           limit: Annotated[int, typer.Option(min=1, max=10000)] = 100) -> None:
    """Search retained raw archive lines; output JSON lines with archive references."""
    cfg = _cfg()
    _device(cfg, device)
    archive = RawArchive(cfg.paths.state_dir / "archive")
    manifest = cfg.paths.state_dir / "archive" / device / "manifest.jsonl"
    if not manifest.exists():
        _fail(f"no archived syslog for {device}")
    since = datetime.now(UTC) - timedelta(days=days)
    seen: set[str] = set()
    count = 0
    with manifest.open("rb") as stream:
        for line in stream:
            doc = json.loads(line)
            location = f"{doc['path']}#{doc['offset']}+{doc['compressed_size']}"
            if datetime.fromisoformat(doc["stored_at"]) < since or location in seen:
                continue
            seen.add(location)
            raw = archive.read(doc["path"], doc["sha256"], doc["size"],
                               offset=doc["offset"], length=doc["compressed_size"])
            for entry in raw.decode("latin-1").splitlines():
                if text.casefold() in entry.casefold():
                    typer.echo(json.dumps({"raw_ref": location, "line": registry.scrub(entry)}))
                    count += 1
                    if count >= limit:
                        return


@app.command()
def daemon(verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False) -> None:
    """Run the monitoring service in the foreground (systemd runs this)."""
    handler = logging.StreamHandler()
    handler.addFilter(RedactingFilter())
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, handlers=[handler])
    logging.getLogger("httpx").setLevel(logging.WARNING)
    run_service(_runtime())


@app.command("findings")
def findings_list(
    days: Annotated[int, typer.Option(help="Look back this many days")] = 7,
    min_severity: Annotated[str, typer.Option(help="info|low|medium|high|critical")] = "low",
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """List recent findings recorded by the service."""
    cfg = _cfg()
    floor = Severity.parse(min_severity)
    since = datetime.now(UTC) - timedelta(days=days)
    database = _database(cfg)
    try:
        docs = database.recent_findings(since, floor)
    except SQLAlchemyError as exc:
        _fail(f"cannot read findings: {type(exc).__name__}; run as the scalar database user")
    finally:
        database.close()
    if as_json:
        typer.echo(json.dumps(docs, indent=2))
        return
    for d in docs:
        typer.echo(f"{d['observed_at'][:19]}  {d['severity']:<8} {d.get('device') or '-':<14} "
                   f"{d['rule_id']}: {d['summary']}")
    typer.echo(f"\n{len(docs)} finding(s) in the last {days} day(s)", err=True)


@config_app.command("history")
def config_history(device: str,
                   kind: Annotated[str, typer.Option(help="running|saved")] = "running",
                   show: Annotated[int | None, typer.Option(
                       help="Diff entry N against the one before it")] = None) -> None:
    """List recorded config snapshots for a device, or diff one against its predecessor."""
    cfg = _cfg()
    store = FileSnapshotStore(cfg.paths.state_dir / "configs")
    hist = store.history(device, kind)
    if not hist:
        _fail(f"no {kind} snapshots recorded for {device}")
    if show is None:
        for i, s in enumerate(hist):
            typer.echo(f"{i:>4}  {s.at:%Y-%m-%d %H:%M:%S}  {s.sha256[:12]}  "
                       f"changed={s.meta.get('lastconfigchangedtime', '?')}")
        return
    if not 0 < show < len(hist):
        _fail(f"pick an entry between 1 and {len(hist) - 1}")
    old = config_lines(store.content(hist[show - 1].sha256))
    new = config_lines(store.content(hist[show].sha256))
    typer.echo(diff_lines(old, new, load_risk_rules()).render())


# ---- helpers --------------------------------------------------------------------------------


def _device(cfg: Config, name: str) -> Device:
    try:
        return cfg.device(name)
    except KeyError:
        _fail(f"no device named {name!r} in the config")


def _run_async(coro: Any) -> Any:
    try:
        return asyncio.run(coro)
    except KeyError as exc:
        _fail(str(exc))
    except (NitroError, CredentialError, OSError, ValueError) as exc:
        _fail(str(exc))


def _table(rows: Sequence[Sequence[str]]) -> None:
    widths = [max(len(str(r[i])) for r in rows) for i in range(len(rows[0]))]
    for r in rows:
        typer.echo("  ".join(str(c).ljust(w) for c, w in zip(r, widths, strict=True)).rstrip())


if __name__ == "__main__":
    app()
