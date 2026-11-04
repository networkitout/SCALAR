"""Wire formats for findings: ECS-aligned JSON, CEF, RFC 5424 syslog, email text, Slack."""

from __future__ import annotations

import json
import socket
from datetime import UTC, datetime
from typing import Any

from netrescale import __version__
from netrescale.detect.findings import Finding
from netrescale.detect.severity import Severity

_ECS_SEVERITY = {Severity.INFO: 1, Severity.LOW: 25, Severity.MEDIUM: 50, Severity.HIGH: 75,
                 Severity.CRITICAL: 99}
_CEF_SEVERITY = {Severity.INFO: 1, Severity.LOW: 3, Severity.MEDIUM: 5, Severity.HIGH: 8,
                 Severity.CRITICAL: 10}
# RFC 5424 severities: 2 crit, 3 err, 4 warning, 5 notice, 6 info
_SYSLOG_SEVERITY = {Severity.INFO: 6, Severity.LOW: 5, Severity.MEDIUM: 4, Severity.HIGH: 3,
                    Severity.CRITICAL: 2}
FACILITY_LOCAL4 = 20


def to_ecs(f: Finding) -> dict[str, Any]:
    """ECS-style field names, so Cribl can map to CrowdStrike's parsing standard easily."""
    doc: dict[str, Any] = {
        "@timestamp": f.observed_at.astimezone(UTC).isoformat(),
        "message": f.summary,
        "event": {
            "kind": "alert",
            "category": ["intrusion_detection"] if f.category != "config_change"
            else ["configuration"],
            "type": ["change"] if f.category == "config_change" else ["indicator"],
            "severity": _ECS_SEVERITY[f.severity],
            "id": f.dedup_key,
            "dataset": f"netrescale.{f.category}",
            "module": "netrescale",
            "reason": f.title,
        },
        "rule": {"id": f.rule_id, "name": f.title, "reference": list(f.references)},
        "observer": {"vendor": "NetScaler", "product": "ADC", "hostname": f.device},
        "host": {"name": f.device},
        "netrescale": {"severity": str(f.severity), "category": f.category,
                       "evidence": f.evidence, "version": __version__},
    }
    if f.cve:
        doc["vulnerability"] = {"id": list(f.cve)}
    if f.mitre:
        doc["threat"] = {"framework": "MITRE ATT&CK", "technique": {"id": list(f.mitre)}}
    return doc


def to_json(f: Finding) -> str:
    return json.dumps(to_ecs(f), separators=(",", ":"), default=str, ensure_ascii=False)


def _cef_header(s: str) -> str:
    return s.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def _cef_ext(s: str) -> str:
    return (s.replace("\\", "\\\\").replace("=", "\\=").replace("\r\n", "\\n")
            .replace("\n", "\\n").replace("\r", "\\n"))


def to_cef(f: Finding) -> str:
    ext = {
        "rt": str(int(f.observed_at.timestamp() * 1000)),
        "dvchost": f.device or "",
        "msg": f.summary,
        "cat": f.category,
        "externalId": f.dedup_key,
        "cs1Label": "cve", "cs1": ",".join(f.cve),
        "cs2Label": "mitre", "cs2": ",".join(f.mitre),
        "cs3Label": "evidence", "cs3": json.dumps(f.evidence, default=str)[:3800],
    }
    header = "|".join(_cef_header(x) for x in (
        "CEF:0", "netrescale", "netrescale", __version__, f.rule_id, f.title,
        str(_CEF_SEVERITY[f.severity])))
    return header + "|" + " ".join(f"{k}={_cef_ext(v)}" for k, v in ext.items() if v != "")


def rfc5424(msg: str, severity: Severity, *, msgid: str = "FINDING",
            hostname: str | None = None, timestamp: str | None = None) -> bytes:
    pri = FACILITY_LOCAL4 * 8 + _SYSLOG_SEVERITY[severity]
    ts = timestamp or datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    host = (hostname or socket.gethostname())[:255] or "-"
    return f"<{pri}>1 {ts} {host} netrescale - {msgid} - {msg}".encode()


def octet_frame(payload: bytes) -> bytes:
    """RFC 6587 octet counting, safe for messages that contain newlines."""
    return str(len(payload)).encode() + b" " + payload


def email_subject(f: Finding) -> str:
    subject = f"[netrescale][{str(f.severity).upper()}] {f.device or 'fleet'}: {f.title}"
    return " ".join(subject.split())[:200]  # no CR/LF: a header must stay one line


def email_body(f: Finding) -> str:
    lines = [f.summary, "", f"Severity:  {f.severity}", f"Device:    {f.device or '-'}",
             f"Rule:      {f.rule_id}", f"Observed:  {f.observed_at.isoformat()}",
             f"Dedup key: {f.dedup_key}"]
    if f.cve:
        lines.append(f"CVE:       {', '.join(f.cve)}")
    if f.mitre:
        lines.append(f"MITRE:     {', '.join(f.mitre)}")
    diff = f.evidence.get("diff")
    if diff:
        lines += ["", "Changes (secrets redacted):", diff]
    rest = {k: v for k, v in f.evidence.items() if k != "diff"}
    if rest:
        lines += ["", "Evidence:", json.dumps(rest, indent=2, default=str)]
    if f.references:
        lines += ["", "References:", *f.references]
    lines += ["", "Acknowledge with: netrescale findings ack " + f.dedup_key]
    return "\n".join(lines)


def _slack(text: str) -> str:
    """Slack treats <...> as mentions and links (<!channel>, <https://x|label>); log-derived
    text must not trigger them. &, < and > are the only characters Slack asks to escape."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def slack_payload(f: Finding) -> dict[str, Any]:
    text = f"*[{str(f.severity).upper()}]* {_slack(f.title)}\n{_slack(f.summary)}"
    diff = f.evidence.get("diff")
    if diff:
        text += "\n```" + _slack(diff[:2500]).replace("```", "'''") + "```"
    return {"text": text}
