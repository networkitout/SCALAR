"""Parse NetScaler log lines (ns.log, and shell/http logs) into structured events.

ns.log body (after any syslog prefix):
    <date>:<time> <TZ> <host> <n>-PPE-<n> : [partition] <FEATURE> <EVENT> <seq> <n> : <message>
Date formats depend on the syslogAction -dateFormat: MMDDYYYY (default), DDMMYYYY or
YYYYMMDD. The format is configured per device, because 05/10/2026 is ambiguous.

Forwarded lines are classified from their headers only (classify_syslog): the rsyslog
envelope, <PRI>, then an RFC 5424 header or an RFC 3164 / on-box header read by position.
Text after the header (usernames, URLs, User-Agents) never decides the source, and the
ns.log header is only accepted at the header position, never searched for in the line.

Lines are handled as str decoded with latin-1 (one char per byte, lossless) so detections
can look for raw high bytes, such as the memory garbage CitrixBleed 2 leaks into logs.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta, timezone
from typing import Literal
from zoneinfo import ZoneInfo

DateFormat = Literal["MMDDYYYY", "DDMMYYYY", "YYYYMMDD"]
SyslogSource = Literal["nslog", "bashlog", "shlog", "httperror", "httpaccess", "httpaccess-vpn",
                       "notice", "auth", "unknown"]

# Program tag (RFC 3164 TAG or RFC 5424 APP-NAME, basename, lower case, ".log" dropped) ->
# source. Unconfirmed for 14.1-29+ RFC 5424 management-log exports: validate against
# archived samples. ns.log and Apache lines are recognised by their own header shape;
# nsaaad writes its login failures into ns.log without one (CVE-2026-88771 log poisoning).
SYSLOG_TAGS: dict[str, SyslogSource] = {
    "bash": "bashlog", "sh": "shlog", "csh": "shlog", "tcsh": "shlog",
    "sshd": "auth", "sshd-session": "auth", "login": "auth", "su": "auth", "auth": "auth",
    "pitboss": "notice", "kernel": "notice", "savecore": "notice", "notice": "notice",
    "nsaaad": "nslog",
    "httpaccess": "httpaccess", "httpaccess-vpn": "httpaccess-vpn",
    "httperror": "httperror", "httperror-vpn": "httperror",
}
INJECTION_FIELD = "Field_injection"  # field keys that appeared more than once in a message

_NS_RE = re.compile(
    r"(?P<date>\d{2,4}/\d{2}/\d{2,4}):(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?:(?P<tz>GMT|UTC|[A-Z]{2,5}|[+-]\d{2}:?\d{2})\s+)?"
    r"(?P<host>\S{1,255})\s+(?P<ppe>\d{1,4}-PPE-\d{1,4})\s+:\s+"
    r"(?:(?P<partition>\S{1,64})\s+)?"
    r"(?P<feature>[A-Z][A-Z0-9_]{0,39})\s+(?P<event>[A-Za-z][A-Za-z0-9_]{0,39})\s+"
    r"(?P<seq>\d{1,20})\s+(?P<flag>\d{1,10})\s+:\s?(?P<msg>.*)$"
)
_ISO_TS = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})"
_FACILITY = r"<[A-Za-z0-9]{1,16}\.[A-Za-z]{1,16}> +"  # on-box "<local0.info>"
_ENVELOPE_RE = re.compile(rf"{_ISO_TS} [0-9A-Fa-f:.]{{2,45}} ")  # rsyslog ScalarLine
_PRI_RE = re.compile(r"<\d{1,3}> *")
_RFC5424_RE = re.compile(
    rf"[1-9]\d{{0,2}} (?:-|{_ISO_TS}) \S{{1,255}} (?P<app>\S{{1,48}}) \S{{1,128}} \S{{1,32}} "
    r'(?:-|(?:\[(?:[^\]"\\]|\\.|"(?:[^"\\]|\\.)*")*\])+)(?: |$)(?:\xef\xbb\xbf)?'
)
_BSD_RE = re.compile(
    rf"(?:{_FACILITY})?(?:(?:[A-Z][a-z]{{2}} +\d{{1,2}} \d{{2}}:\d{{2}}:\d{{2}}|{_ISO_TS}) +)?"
    rf"(?:{_FACILITY})?"
)
_HOST_RE = re.compile(r"\S{1,255} +")
_TAG_RE = re.compile(r"(?P<tag>[A-Za-z/][A-Za-z0-9_./-]{0,63})(?:\[\d{1,10}\])?:(?: +|$)")
_ACCESS_RE = re.compile(
    r'\S{1,255} \S{1,255} \S{1,255} \[[^\]]{1,64}\] "|[0-9A-Fa-f:.]{2,45} "[A-Z]{3,10} ')
_ERROR_RE = re.compile(
    r"\[[A-Z][a-z]{2} [A-Z][a-z]{2} [ \d]?\d \d{2}:\d{2}:\d{2}(?:\.\d{1,6})? \d{4}\] \[")

# Key/value extraction for the " - " separated NetScaler message format.
_FIELD_KEYS = ("User", "Client_ip", "SessionId", "Remote_ip", "Command", "Status", "Source",
               "Destination", "Vserver", "Nat_ip", "Context", "Browser_type", "Group(s)",
               "Failure_reason", "ClientIP")
_FIELD_NAMES = {"Group(s)": "Groups"}
_KEYS = "|".join(re.escape(key) for key in _FIELD_KEYS)
_KEY_RE = re.compile(rf"(?<![^\s-])({_KEYS})(?=[\s:])")
_SEPARATED_KEY_RE = re.compile(rf"(?:^|-\s+)({_KEYS})(?=[\s:])")
_QUOTED_VALUE = re.compile(r' "((?:[^"\\]|\\.)*)"')
_WORD_VALUE = re.compile(r" (\S+)")
_VALUE_RES: dict[str, re.Pattern[str]] = {
    "SessionId": re.compile(r":?\s*(\d{1,20})"),
    "Nat_ip": re.compile(r' ("(?:[^"\\]|\\.)*"|\S+)'),
    **dict.fromkeys(("Command", "Status", "Browser_type", "Group(s)", "Failure_reason"),
                    _QUOTED_VALUE),
}
_USER_ANCHORS = frozenset({"Client_ip", "Remote_ip"})  # appended by the appliance after User
_TRAILING = frozenset({"Status", "Failure_reason"})  # appended last: the last occurrence wins
_REJECTED = "Authentication is rejected for "
_SHELL_RE = re.compile(r"(?P<prog>bash|sh|csh|tcsh)\[\d+\]:\s*(?P<body>.*)$")
_SHELL_USER_RE = re.compile(r"(\S+) on (\S+)")
_SHELL_COMMAND = "shell_command="
_MAX_IP_TEXT = 64
_YEARS = range(2000, 2101)


@dataclass(slots=True)
class LogEvent:
    source: str  # SyslogSource
    device: str
    raw: str
    ts: datetime | None = None
    host: str | None = None
    ppe: str | None = None
    partition: str | None = None
    feature: str | None = None
    event: str | None = None
    seq: int | None = None
    message: str = ""
    fields: dict[str, str] = field(default_factory=dict)

    @property
    def event_type(self) -> str | None:
        return f"{self.feature} {self.event}" if self.feature and self.event else None

    def ip_field(self, name: str) -> str | None:
        """Field value reduced to a bare IP (drops :port and quotes); None if not a plain IP."""
        v = self.fields.get(name)
        if not v or len(v) > _MAX_IP_TEXT:
            return None
        v = v.strip('"')
        if v.startswith("[") and "]" in v:
            host = v[1:v.index("]")]
        else:
            host = v.rsplit(":", 1)[0] if v.count(":") == 1 else v
        if "%" in host:  # scoped IPv6 is never an appliance-written client address
            return None
        try:
            return str(ipaddress.ip_address(host))
        except ValueError:
            return None


@dataclass(frozen=True, slots=True)
class _Header:
    source: SyslogSource
    start: int  # offset of the body (text after the syslog header)
    ns: re.Match[str] | None = None


@dataclass(frozen=True, slots=True)
class _Field:
    key: str
    value: str
    start: int
    value_start: int


def _shape(text: str, pos: int) -> _Header | None:
    ns = _NS_RE.match(text, pos)
    if ns:
        return _Header("nslog", pos, ns)
    if _ACCESS_RE.match(text, pos):
        return _Header("httpaccess", pos)
    if _ERROR_RE.match(text, pos):
        return _Header("httperror", pos)
    return None


def _tag_source(tag: str) -> SyslogSource | None:
    name = tag.rsplit("/", 1)[-1].lower()
    return SYSLOG_TAGS.get(name.removesuffix(".log"))


def _bsd(text: str, pos: int) -> _Header:
    """RFC 3164 or on-box header: [<fac.lvl>] [timestamp] [<fac.lvl>] [host] then a
    TAG[pid]: or a header-shaped body (ns.log, Apache), each tried at a fixed position."""
    prefix = _BSD_RE.match(text, pos)
    pos = prefix.end() if prefix else pos
    host = _HOST_RE.match(text, pos)
    starts = (pos, host.end()) if host else (pos,)
    for start in starts:
        tag = _TAG_RE.match(text, start)
        if tag:
            source = _tag_source(tag["tag"])
            if source:
                return _Header(source, tag.end())
            return _shape(text, tag.end()) or _Header("unknown", tag.end())
    for start in starts:
        shaped = _shape(text, start)
        if shaped:
            return shaped
    return _Header("unknown", pos)


def _rfc5424_body(text: str, pos: int) -> _Header:
    """MSG under an unmapped APP-NAME. Only a whole embedded on-box line (it starts with a
    timestamp or <fac.lvl>) has a header of its own; otherwise the body must be header-shaped,
    so a tag-shaped word in the message never decides the source."""
    prefix = _BSD_RE.match(text, pos)
    if prefix and prefix.end() > pos:
        return _bsd(text, pos)
    return _shape(text, pos) or _Header("unknown", pos)


def _classify(text: str) -> _Header:
    pos = 0
    envelope = _ENVELOPE_RE.match(text)
    if envelope:
        pos = envelope.end()
    pri = _PRI_RE.match(text, pos)
    if pri:
        pos = pri.end()
    rfc5424 = _RFC5424_RE.match(text, pos)
    if rfc5424:
        source = _tag_source(rfc5424["app"])
        return _Header(source, rfc5424.end()) if source else _rfc5424_body(text, rfc5424.end())
    return _bsd(text, pos)


def classify_syslog(line: str) -> tuple[SyslogSource, str]:
    """Source and body of a stored syslog line, decided from header tokens only.

    Never raises; lines it cannot place are 'unknown' with the text after any header."""
    text = line.rstrip("\r\n")
    header = _classify(text)
    return header.source, text[header.start:]


def _parse_ts(date: str, time: str, fmt: DateFormat, tz: str | None = None,
              device_timezone: str = "UTC") -> datetime | None:
    a, b, c = date.split("/")
    try:
        if fmt == "YYYYMMDD":
            y, m, d = int(a), int(b), int(c)
        elif fmt == "DDMMYYYY":
            d, m, y = int(a), int(b), int(c)
        else:
            m, d, y = int(a), int(b), int(c)
        if y not in _YEARS:
            return None
        hh, mm, ss = (int(x) for x in time.split(":"))
        zone = ZoneInfo(device_timezone)
        if tz in ("GMT", "UTC"):
            return datetime(y, m, d, hh, mm, ss, tzinfo=UTC)
        if tz and tz[0] in ("+", "-"):
            offset = tz[1:].replace(":", "")
            minutes = int(offset[:2]) * 60 + int(offset[2:])
            fixed = timezone(timedelta(minutes=minutes if tz[0] == "+" else -minutes))
            return datetime(y, m, d, hh, mm, ss, tzinfo=fixed).astimezone(UTC)
        return datetime(y, m, d, hh, mm, ss, tzinfo=zone).astimezone(UTC)
    except (ValueError, OverflowError, KeyError):  # KeyError: unknown device timezone
        return None


def _scan_fields(message: str) -> list[_Field]:
    found = []
    pos = 0
    while (key := _KEY_RE.search(message, pos)) is not None:
        value = _VALUE_RES.get(key[1], _WORD_VALUE).match(message, key.end())
        if value is None:
            pos = key.end()
            continue
        found.append(_Field(key[1], value[1], key.start(), value.start(1)))
        pos = value.end()
    return found


def extract_fields(message: str) -> dict[str, str]:
    """NetScaler "Key value - Key value" fields, read in order; the first occurrence of a
    key wins (the last for Status and Failure_reason, which the appliance appends at the
    end) and quoted values are consumed whole, so text inside them is never a key.

    An attempted username comes before the Client_ip/Remote_ip the appliance appends, so a
    User value extends to the last of those; fake fields inside it are not extracted. Keys
    seen more than once are listed in Field_injection."""
    found = _scan_fields(message)
    suspicious: set[str] = set()
    user = next((i for i, item in enumerate(found) if item.key == "User"), None)
    if user is not None:
        anchors = [i for i in range(user + 1, len(found)) if found[i].key in _USER_ANCHORS]
        if anchors:
            last = anchors[-1]
            suspicious.update(item.key for item in found[user + 1:last])
            value = message[found[user].value_start:found[last].start].rstrip()
            value = value[:-1].rstrip() if value.endswith("-") else value
            found[user] = replace(found[user], value=value)
            del found[user + 1:last]
    out: dict[str, str] = {}
    for item in found:
        name = _FIELD_NAMES.get(item.key, item.key)
        if item.key in _TRAILING:
            out[name] = item.value
        else:
            out.setdefault(name, item.value)
    rejected = message.find(_REJECTED)
    if rejected >= 0:
        name = message[rejected + len(_REJECTED):].rstrip()
        out["Rejected_user"] = name[:-1] if name.endswith('"') else name
    counts = Counter(match[1] for match in _SEPARATED_KEY_RE.finditer(message))
    suspicious.update(key for key, count in counts.items() if count > 1)
    if suspicious:
        out[INJECTION_FIELD] = ",".join(sorted(_FIELD_NAMES.get(k, k) for k in suspicious))
    return out


def _ns_event(raw: str, m: re.Match[str], device: str, date_format: DateFormat,
              device_timezone: str) -> LogEvent:
    msg = m["msg"]
    return LogEvent(
        source="nslog",
        device=device,
        raw=raw,
        ts=_parse_ts(m["date"], m["time"], date_format, m["tz"], device_timezone),
        host=m["host"],
        ppe=m["ppe"],
        partition=m["partition"],
        feature=m["feature"],
        event=m["event"],
        seq=int(m["seq"]),
        message=msg,
        fields=extract_fields(msg),
    )


def parse_nslog(line: str, device: str, date_format: DateFormat = "YYYYMMDD",
                device_timezone: str = "UTC") -> LogEvent:
    raw = line.rstrip("\r\n")
    header = _classify(raw)
    if header.ns is None:
        return LogEvent("nslog", device, raw, message=raw)
    return _ns_event(raw, header.ns, device, date_format, device_timezone)


def _shell_command(body: str) -> str:
    start = body.find(_SHELL_COMMAND)
    if start < 0:
        return body
    command = body[start + len(_SHELL_COMMAND):]
    command = (command[1:] if command.startswith('"') else command).rstrip()
    return command[:-1] if command.endswith('"') else command


def _shell_event(raw: str, body: str, device: str, source: str) -> LogEvent:
    ev = LogEvent(source, device, raw, message=raw)
    ev.fields["Command"] = _shell_command(body)
    um = _SHELL_USER_RE.match(body)
    if um:
        ev.fields["User"], ev.fields["Tty"] = um.group(1), um.group(2)
    ev.message = ev.fields["Command"]
    return ev


def parse_shell_log(line: str, device: str, source: str = "bashlog") -> LogEvent:
    """bash.log / sh.log. Exact on-box format must be confirmed with `scalar probe`;
    the parser falls back to the whole line when shell_command= isn't present."""
    raw = line.rstrip("\r\n")
    header = _classify(raw)
    if header.source in ("bashlog", "shlog"):
        return _shell_event(raw, raw[header.start:], device, source)
    m = _SHELL_RE.search(raw)
    if m:
        return _shell_event(raw, m["body"], device, source)
    return LogEvent(source, device, raw, message=raw)


def parse_line(source: str, line: str, device: str,
               date_format: DateFormat = "YYYYMMDD", device_timezone: str = "UTC") -> LogEvent:
    if source == "nslog":
        return parse_nslog(line, device, date_format, device_timezone)
    if source in ("bashlog", "shlog"):
        return parse_shell_log(line, device, source)
    raw = line.rstrip("\r\n")
    return LogEvent(source, device, raw, message=raw)


def parse_syslog(line: str, device: str, date_format: DateFormat = "YYYYMMDD",
                 device_timezone: str = "UTC") -> LogEvent:
    """Classify a forwarded line by its header (classify_syslog), then parse it."""
    raw = line.rstrip("\r\n")
    header = _classify(raw)
    if header.ns is not None:
        return _ns_event(raw, header.ns, device, date_format, device_timezone)
    if header.source in ("bashlog", "shlog"):
        return _shell_event(raw, raw[header.start:], device, header.source)
    return LogEvent(header.source, device, raw, message=raw)
