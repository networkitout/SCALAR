"""High-signal forensic inspection of NetScaler configuration.

The engine intentionally consumes only the normalized, redacted representation produced by
``parse.nsconf``. It reports dangerous state in a single snapshot and security-significant
deltas when a previous snapshot is available.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from typing import Literal, cast
from urllib.parse import urlsplit, urlunsplit

from scalar.detect.config_diff import LineChange, diff_configs
from scalar.detect.config_risk import load_risk_rules
from scalar.detect.severity import Severity
from scalar.parse.nsconf import Command, config_lines, parse_many, unquote
from scalar.redact import registry

UserChangeKind = Literal["added", "removed", "changed"]
DeltaKind = Literal["added", "removed", "modified"]

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_EXTERNAL_URL_RE = re.compile(r"\b(?:https?|ftp)://", re.IGNORECASE)
_SCRIPT_RE = re.compile(
    r"(?:<script\b|javascript:|document\.|eval\s*\(|atob\s*\(|fromcharcode|"
    r"\bonload\s*=|xmlhttprequest|\bfetch\s*\()",
    re.IGNORECASE,
)
_COMMAND_RE = re.compile(
    r"(?:^|[\s;|&\"'])(?:curl|wget|powershell|pwsh|cmd(?:\.exe)?|bash|sh|nc|netcat|"
    r"python\d?|perl|php)\b|(?:/bin/(?:ba)?sh|/dev/tcp/)",
    re.IGNORECASE,
)
_ENCODED_RE = re.compile(
    r"(?:\b(?:base64|frombase64string|certutil\s+-decode)\b|"
    r"\b[A-Za-z0-9+/]{96,}={0,2}\b)",
    re.IGNORECASE,
)
_SUSPICIOUS_USER_RE = re.compile(
    r"(?:backdoor|breakglass|hacker|support\d*|temp(?:orary)?|test(?:admin)?|"
    r"admin\d+|svc[_-]?(?:admin|root))",
    re.IGNORECASE,
)
_DISABLED = frozenset({"disable", "disabled", "no", "off", "none", "0"})
_ENABLED = frozenset({"enable", "enabled", "yes", "on", "1"})
_PROTECTIVE_OBJECT_PREFIXES = (
    "audit ",
    "appfw ",
    "bot ",
    "ns acl",
    "ns simpleacl",
    "ssl profile",
    "authentication ",
)
_EXCEPTIONAL_RULE_IDS = frozenset({
    "authentication",
    "gateway-global",
    "logging-disabled",
    "logging-tamper",
    "mgmt-access",
    "mgmt-acl",
    "mgmt-group-or-policy",
    "mgmt-user-binding",
    "ns-extension",
    "page-injection",
    "security-feature-off",
    "system-parameters",
    "tls-binding",
})


@dataclass(frozen=True, slots=True)
class ForensicCheck:
    """One actionable forensic issue."""

    id: str
    severity: Severity
    title: str
    summary: str
    evidence: tuple[str, ...]
    remediation: str
    dedup_material: str
    cves: tuple[str, ...] = ()
    mitre: tuple[str, ...] = ()
    references: tuple[str, ...] = ()

    @property
    def dedup_key(self) -> str:
        digest = hashlib.sha256(self.dedup_material.encode()).hexdigest()[:20]
        return f"config-forensics|{self.id}|{digest}"


@dataclass(frozen=True, slots=True)
class UserDelta:
    username: str
    change: UserChangeKind
    before: tuple[str, ...] = ()
    after: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ExceptionalDelta:
    kind: DeltaKind
    object: str
    name: str | None
    severity: Severity
    rule_ids: tuple[str, ...]
    before: str | None
    after: str | None


@dataclass(frozen=True, slots=True)
class ConfigForensicReport:
    device: str | None
    checks: tuple[ForensicCheck, ...]
    user_changes: tuple[UserDelta, ...]
    exceptional_deltas: tuple[ExceptionalDelta, ...]
    normalized_line_count: int

    @property
    def max_severity(self) -> Severity:
        return max((check.severity for check in self.checks), default=Severity.INFO)


def _values(command: Command, option: str) -> tuple[str, ...]:
    return tuple(unquote(value) for value in (command.option(option) or ()))


def _first_value(command: Command, option: str) -> str | None:
    values = _values(command, option)
    return values[0] if values else None


def _is_enabled(value: str | None) -> bool:
    return value is not None and value.lower() in _ENABLED


def _is_disabled(value: str | None) -> bool:
    return value is not None and value.lower() in _DISABLED


def _safe_url(match: re.Match[str]) -> str:
    value = match.group(0)
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname or ""
        port = f":{parsed.port}" if parsed.port is not None else ""
        netloc = f"{hostname}{port}"
        if parsed.username is not None or parsed.password is not None:
            netloc = f"<redacted>@{netloc}"
        query = "<redacted>" if parsed.query else ""
        fragment = "<redacted>" if parsed.fragment else ""
        return urlunsplit((parsed.scheme, netloc, parsed.path, query, fragment))
    except ValueError:
        return "<redacted-url>"


def _safe_evidence(line: str | None) -> str | None:
    if line is None:
        return None
    scrubbed = str(registry.scrub_value(line))
    return _URL_RE.sub(_safe_url, scrubbed)


def _identity(command: Command) -> str:
    return command.name or command.object


def _dedup_material(rule_id: str, device: str | None, identity: str) -> str:
    return "|".join((rule_id, device or "-", identity.lower()))


def _make_check(
    *,
    rule_id: str,
    severity: Severity,
    title: str,
    summary: str,
    evidence: tuple[str, ...],
    remediation: str,
    device: str | None,
    identity: str,
    cves: tuple[str, ...] = (),
    mitre: tuple[str, ...] = (),
    references: tuple[str, ...] = (),
) -> ForensicCheck:
    safe_evidence = tuple(value for line in evidence if (value := _safe_evidence(line)) is not None)
    return ForensicCheck(
        id=rule_id,
        severity=severity,
        title=title,
        summary=summary,
        evidence=safe_evidence,
        remediation=remediation,
        dedup_material=_dedup_material(rule_id, device, identity),
        cves=cves,
        mitre=mitre,
        references=references,
    )


def _management_ip(command: Command) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if command.object not in {"ns ip", "ns ip6"} or command.name is None:
        return None
    try:
        return ipaddress.ip_address(command.name)
    except ValueError:
        return None


def _is_externally_routable(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_unspecified
        or address.is_reserved
    )


def _inspect_command(command: Command, device: str | None) -> list[ForensicCheck]:
    checks: list[ForensicCheck] = []
    identity = _identity(command)
    raw_lower = command.raw.lower()

    if (
        command.object == "system user"
        and command.name
        and _SUSPICIOUS_USER_RE.search(command.name)
    ):
        checks.append(_make_check(
            rule_id="suspicious-management-user",
            severity=Severity.HIGH,
            title="Suspicious management account name",
            summary=f"Management account {command.name!r} has a name commonly associated with "
                    "temporary, disguised, or unauthorized access.",
            evidence=(command.raw,),
            remediation="Confirm the account owner and business purpose; remove or disable it if "
                        "it is not explicitly authorized, then rotate affected credentials.",
            device=device,
            identity=command.name,
            mitre=("T1136.001",),
        ))

    if command.verb == "bind" and command.object == "system user" and command.name:
        binding = " ".join(command.positional).lower()
        policy = (_first_value(command, "policyName") or "").lower()
        if "superuser" in binding or policy == "superuser":
            checks.append(_make_check(
                rule_id="management-superuser-grant",
                severity=Severity.CRITICAL,
                title="Management user has superuser privileges",
                summary=f"Management account {command.name!r} is directly bound to the superuser "
                        "command policy.",
                evidence=(command.raw,),
                remediation="Remove the superuser binding unless it is strictly required and bind "
                            "a least-privilege command policy instead.",
                device=device,
                identity=command.name,
                mitre=("T1098",),
            ))

    if command.verb == "bind" and command.object == "system group" and command.name:
        binding = " ".join(command.positional).lower()
        policy = (_first_value(command, "policyName") or "").lower()
        if "superuser" in binding or policy == "superuser":
            checks.append(_make_check(
                rule_id="management-group-superuser-grant",
                severity=Severity.CRITICAL,
                title="Management group has superuser privileges",
                summary=f"Management group {command.name!r} is bound to the superuser command "
                        "policy.",
                evidence=(command.raw,),
                remediation=(
                    "Remove the superuser binding unless every group member requires it and use a "
                    "least-privilege command policy."
                ),
                device=device,
                identity=command.name,
                mitre=("T1098",),
            ))

    if command.object == "system cmdpolicy":
        expression = " ".join(command.positional)
        if re.search(r"\ballow\b", expression, re.IGNORECASE) and re.search(
            r"(?:\.\*|\^\.\*\$|true)", expression, re.IGNORECASE
        ):
            checks.append(_make_check(
                rule_id="unrestricted-command-policy",
                severity=Severity.CRITICAL,
                title="Command policy permits unrestricted administration",
                summary=f"Command policy {identity!r} appears to allow every CLI command.",
                evidence=(command.raw,),
                remediation="Replace the catch-all expression with an allowlist covering only the "
                            "commands required by the assigned role.",
                device=device,
                identity=identity,
                mitre=("T1098",),
            ))

    log_level = _first_value(command, "logLevel")
    if command.object.startswith("audit ") and (
        command.verb == "disable" or _is_disabled(log_level)
    ):
        checks.append(_make_check(
            rule_id="audit-logging-disabled",
            severity=Severity.CRITICAL,
            title="Audit or syslog collection is disabled",
            summary="The configuration disables a NetScaler audit logging control and can blind "
                    "change attribution and incident response.",
            evidence=(command.raw,),
            remediation="Enable audit logging, restore the approved syslog/nslog action and global "
                        "binding, and verify delivery at the collector.",
            device=device,
            identity=identity,
            mitre=("T1562.002",),
        ))

    if command.object in {"rewrite action", "responder action", "rewrite policy",
                          "responder policy"}:
        if _SCRIPT_RE.search(command.raw):
            checks.append(_make_check(
                rule_id="response-script-injection",
                severity=Severity.CRITICAL,
                title="Rewrite or responder rule injects active script",
                summary=f"{command.object.title()} {identity!r} contains browser-executable "
                        "content associated with credential theft.",
                evidence=(command.raw,),
                remediation=(
                    "Disable and preserve the rule for investigation, compare it with the approved "
                    "baseline, and review Gateway clients and logs for compromise."
                ),
                device=device,
                identity=identity,
                mitre=("T1056.003", "T1189"),
            ))
        elif _EXTERNAL_URL_RE.search(command.raw):
            checks.append(_make_check(
                rule_id="external-rewrite-destination",
                severity=Severity.HIGH,
                title="Rewrite or responder rule references an external URL",
                summary=f"{command.object.title()} {identity!r} sends or loads content using an "
                        "absolute external URL.",
                evidence=(command.raw,),
                remediation=(
                    "Verify the destination and rule purpose against the approved baseline; remove "
                    "unexpected redirects or externally hosted content."
                ),
                device=device,
                identity=identity,
                mitre=("T1189",),
            ))

    if command.object.startswith("ns extension"):
        checks.append(_make_check(
            rule_id="ns-extension-present",
            severity=Severity.CRITICAL,
            title="NetScaler packet-engine extension is configured",
            summary=f"Extension {identity!r} can execute custom Lua logic in the packet engine.",
            evidence=(command.raw,),
            remediation=(
                "Verify the extension source and hash from a trusted administrative record; remove "
                "and investigate any extension that is not explicitly approved."
            ),
            device=device,
            identity=identity,
            mitre=("T1505",),
        ))

    if command.object.startswith(("authentication saml", "authentication oauth")):
        unsafe_options = tuple(
            option for option in ("samlSigningCertName", "samlRejectUnsignedAssertion",
                                  "signatureAlg", "digestMethod")
            if _is_disabled(_first_value(command, option))
        )
        if unsafe_options or "sha1" in raw_lower:
            checks.append(_make_check(
                rule_id="unsafe-federated-authentication",
                severity=Severity.HIGH,
                title="Federated authentication weakens assertion validation",
                summary=f"Authentication object {identity!r} disables a signature control or uses "
                        "the obsolete SHA-1 algorithm.",
                evidence=(command.raw,),
                remediation="Require signed SAML assertions/responses and use SHA-256 or stronger "
                            "signature and digest algorithms.",
                device=device,
                identity=identity,
                mitre=("T1556",),
            ))

    address = _management_ip(command)
    management_enabled = _is_enabled(_first_value(command, "mgmtAccess"))
    insecure_service = next(
        (option for option in ("telnet", "ftp") if _is_enabled(_first_value(command, option))),
        None,
    )
    if address is not None and management_enabled and _is_externally_routable(address):
        checks.append(_make_check(
            rule_id="public-management-access",
            severity=Severity.CRITICAL,
            title="Management access is enabled on a public IP",
            summary=f"NetScaler management services are exposed on publicly routable address "
                    f"{address}.",
            evidence=(command.raw,),
            remediation="Disable management access on public-facing addresses and restrict NSIP "
                        "administration to a dedicated private management network and ACL.",
            device=device,
            identity=str(address),
            mitre=("T1190",),
        ))
    if address is not None and insecure_service is not None:
        checks.append(_make_check(
            rule_id="cleartext-management-service",
            severity=Severity.HIGH,
            title="Cleartext management service is enabled",
            summary=f"{insecure_service.upper()} management access is enabled on {address}.",
            evidence=(command.raw,),
            remediation=f"Disable {insecure_service.upper()} and use an authenticated, encrypted "
                        "management channel from a restricted network.",
            device=device,
            identity=f"{address}|{insecure_service}",
            mitre=("T1040",),
        ))

    if command.object in {"ns acl", "ns simpleacl"} and command.verb == "add":
        source = " ".join(_values(command, "srcIP") + _values(command, "srcIPv6"))
        action = " ".join(command.positional).lower()
        if "allow" in action and (
            "0.0.0.0-255.255.255.255" in source
            or source in {"0.0.0.0/0", "::/0"}
        ):
            checks.append(_make_check(
                rule_id="allow-any-management-acl",
                severity=Severity.HIGH,
                title="Management ACL permits every source",
                summary=f"ACL {identity!r} contains an unrestricted source range.",
                evidence=(command.raw,),
                remediation="Restrict the ACL to explicit administrative source networks and deny "
                            "all other management traffic.",
                device=device,
                identity=identity,
                mitre=("T1190",),
            ))

    if command.object in {"ssl parameter", "ssl profile", "ssl vserver", "ssl service"}:
        weak_protocols = tuple(
            option for option in ("ssl3", "tls1", "tls11")
            if _is_enabled(_first_value(command, option))
        )
        if weak_protocols:
            checks.append(_make_check(
                rule_id="legacy-tls-enabled",
                severity=Severity.HIGH,
                title="Legacy SSL/TLS protocol is enabled",
                summary=f"TLS object {identity!r} enables obsolete protocol(s): "
                        f"{', '.join(weak_protocols)}.",
                evidence=(command.raw,),
                remediation="Disable SSLv3, TLS 1.0, and TLS 1.1; require TLS 1.2 or TLS 1.3 with "
                            "approved cipher suites.",
                device=device,
                identity=identity,
                cves=("CVE-2014-3566",),
                references=("https://datatracker.ietf.org/doc/rfc8996/",),
            ))

    if command.object in {"system parameter", "ns param"} and (
        _is_disabled(_first_value(command, "strongpassword"))
        or _is_disabled(_first_value(command, "strongPassword"))
    ):
        checks.append(_make_check(
            rule_id="strong-password-policy-disabled",
            severity=Severity.HIGH,
            title="Strong password policy is disabled",
            summary="Local management accounts are not protected by the appliance strong-password "
                    "policy.",
            evidence=(command.raw,),
            remediation="Enable strong password enforcement and rotate local administrative "
                        "credentials that do not meet policy.",
            device=device,
            identity=identity,
            mitre=("T1110",),
        ))

    if (
        command.verb == "disable"
        and command.object == "ns feature"
        and command.name
        and command.name.lower() in {"appfw", "bot", "aaa", "rewrite", "responder"}
    ):
        checks.append(_make_check(
            rule_id="security-feature-disabled",
            severity=Severity.HIGH,
            title="Security feature is explicitly disabled",
            summary=f"NetScaler feature {command.name!r} is disabled in the configuration.",
            evidence=(command.raw,),
            remediation=(
                "Confirm the feature is intentionally disabled; restore it and its approved "
                "policies if this change reduced a required protection."
            ),
            device=device,
            identity=command.name,
            mitre=("T1562.001",),
        ))

    if command.object.startswith("dns ") and (
        _is_enabled(_first_value(command, "recursion"))
        or _is_disabled(_first_value(command, "dnssec"))
    ):
        checks.append(_make_check(
            rule_id="unsafe-dns-setting",
            severity=Severity.MEDIUM,
            title="DNS security setting is unsafe",
            summary=f"DNS object {identity!r} enables unrestricted recursion or disables DNSSEC.",
            evidence=(command.raw,),
            remediation="Restrict recursion to trusted clients and enable DNSSEC validation where "
                        "supported by the deployment.",
            device=device,
            identity=identity,
        ))

    if command.object.startswith("ntp ") and command.verb == "set" and (
        _is_disabled(_first_value(command, "authentication"))
    ):
        checks.append(_make_check(
            rule_id="ntp-authentication-disabled",
            severity=Severity.MEDIUM,
            title="NTP authentication is disabled",
            summary="Unauthenticated time updates can undermine log timelines and token validity.",
            evidence=(command.raw,),
            remediation="Use approved internal NTP sources and enable authenticated time "
                        "synchronization where supported.",
            device=device,
            identity=identity,
            mitre=("T1565.001",),
        ))

    if command.verb in {"shell", "install"} or _COMMAND_RE.search(command.raw):
        checks.append(_make_check(
            rule_id="embedded-system-command",
            severity=Severity.CRITICAL,
            title="Configuration contains an operating-system command",
            summary=f"Configuration object {identity!r} references a shell or download command "
                    "that is not expected in declarative appliance configuration.",
            evidence=(command.raw,),
            remediation="Preserve the line as evidence, validate it against authorized change "
                        "records, and investigate the appliance filesystem and process history.",
            device=device,
            identity=identity,
            mitre=("T1059", "T1105"),
        ))
    if _ENCODED_RE.search(command.raw) and "<redacted:" not in command.raw:
        checks.append(_make_check(
            rule_id="encoded-config-payload",
            severity=Severity.HIGH,
            title="Configuration contains an encoded payload",
            summary=f"Configuration object {identity!r} contains encoding syntax or a long encoded "
                    "blob that may conceal executable content.",
            evidence=(command.raw,),
            remediation="Decode the value in an isolated analysis environment, verify its purpose, "
                        "and remove it if it is not part of an approved configuration.",
            device=device,
            identity=identity,
            mitre=("T1027",),
        ))

    return checks


def _users(commands: tuple[Command, ...]) -> dict[str, tuple[str, ...]]:
    result: dict[str, list[str]] = {}
    for command in commands:
        if command.object == "system user" and command.name:
            safe = _safe_evidence(command.raw)
            if safe is not None:
                result.setdefault(command.name, []).append(safe)
    return {name: tuple(sorted(lines)) for name, lines in result.items()}


def _user_deltas(
    previous: tuple[Command, ...],
    current: tuple[Command, ...],
) -> tuple[UserDelta, ...]:
    before = _users(previous)
    after = _users(current)
    deltas: list[UserDelta] = []
    for username in sorted(before.keys() | after.keys(), key=str.lower):
        if username not in before:
            deltas.append(UserDelta(username, "added", after=after[username]))
        elif username not in after:
            deltas.append(UserDelta(username, "removed", before=before[username]))
        elif before[username] != after[username]:
            deltas.append(UserDelta(username, "changed", before[username], after[username]))
    return tuple(deltas)


def _is_protective_removal(change: LineChange) -> bool:
    return change.op == "removed" and (
        change.object.startswith(_PROTECTIVE_OBJECT_PREFIXES)
        or "security-feature-off" in change.rule_ids
    )


def _exceptional_deltas(previous_text: str, text: str) -> tuple[ExceptionalDelta, ...]:
    diff = diff_configs(previous_text, text, load_risk_rules())
    result = []
    for change in diff.by_severity():
        if not (
            change.severity >= Severity.HIGH
            and (set(change.rule_ids) & _EXCEPTIONAL_RULE_IDS or _is_protective_removal(change))
        ):
            continue
        result.append(ExceptionalDelta(
            kind=cast(DeltaKind, change.op),
            object=change.object,
            name=change.name,
            severity=change.severity,
            rule_ids=change.rule_ids,
            before=_safe_evidence(change.before),
            after=_safe_evidence(change.after),
        ))
    return tuple(result)


def _delta_checks(
    device: str | None,
    users: tuple[UserDelta, ...],
    deltas: tuple[ExceptionalDelta, ...],
) -> list[ForensicCheck]:
    checks: list[ForensicCheck] = []
    for user in users:
        if user.change == "added":
            checks.append(_make_check(
                rule_id="management-user-added",
                severity=Severity.CRITICAL,
                title="New management account added",
                summary=f"Management account {user.username!r} was not present in the previous "
                        "configuration.",
                evidence=user.after,
                remediation=(
                    "Verify the account against an approved change and owner; remove it and rotate "
                    "privileged credentials if unauthorized."
                ),
                device=device,
                identity=user.username,
                mitre=("T1136.001",),
            ))
        elif user.change == "removed":
            checks.append(_make_check(
                rule_id="management-user-removed",
                severity=Severity.HIGH,
                title="Management account removed",
                summary=f"Management account {user.username!r} was removed since the previous "
                        "configuration.",
                evidence=user.before,
                remediation=(
                    "Confirm the removal was authorized and ensure access remains available "
                    "through approved least-privilege accounts."
                ),
                device=device,
                identity=user.username,
                mitre=("T1070",),
            ))
        else:
            checks.append(_make_check(
                rule_id="management-user-changed",
                severity=Severity.CRITICAL,
                title="Management account changed",
                summary=f"Management account {user.username!r} changed since the previous "
                        "configuration, including a possible credential or access-mode change.",
                evidence=(*user.before, *user.after),
                remediation="Validate the account change and credential rotation against the "
                            "approved record; investigate and rotate credentials if unauthorized.",
                device=device,
                identity=user.username,
                mitre=("T1098",),
            ))

    for delta in deltas:
        if delta.kind != "removed" or not delta.object.startswith(_PROTECTIVE_OBJECT_PREFIXES):
            continue
        identity = delta.name or delta.object
        checks.append(_make_check(
            rule_id="protective-control-removed",
            severity=max(Severity.HIGH, delta.severity),
            title="Protective configuration control removed",
            summary=f"{delta.object} {identity!r} was removed from the configuration.",
            evidence=tuple(value for value in (delta.before,) if value is not None),
            remediation="Confirm the removal was authorized and restore the approved logging, "
                        "access-control, authentication, or application-protection control.",
            device=device,
            identity=f"{delta.object}|{identity}",
            mitre=("T1562.001",),
        ))
    return checks


def analyze_config(
    text: str,
    *,
    previous_text: str | None = None,
    device: str | None = None,
) -> ConfigForensicReport:
    """Inspect a NetScaler configuration without retaining or returning raw secrets."""
    normalized = tuple(config_lines(text))
    commands = tuple(parse_many(normalized))
    checks = [check for command in commands for check in _inspect_command(command, device)]

    user_changes: tuple[UserDelta, ...] = ()
    exceptional_deltas: tuple[ExceptionalDelta, ...] = ()
    if previous_text is not None:
        previous_commands = tuple(parse_many(config_lines(previous_text)))
        user_changes = _user_deltas(previous_commands, commands)
        exceptional_deltas = _exceptional_deltas(previous_text, text)
        checks.extend(_delta_checks(device, user_changes, exceptional_deltas))

    unique = {(check.id, check.dedup_material): check for check in checks}
    ordered_checks = tuple(sorted(
        unique.values(),
        key=lambda check: (-check.severity, check.id, check.dedup_material),
    ))
    return ConfigForensicReport(
        device=device,
        checks=ordered_checks,
        user_changes=user_changes,
        exceptional_deltas=exceptional_deltas,
        normalized_line_count=len(normalized),
    )
