"""Tokenize, structure, redact and normalize NetScaler ns.conf / running-config text.

ns.conf is one CLI command per line: ``<verb> <group> <object> [name] [positional...]
[-option value...]``. A few network-group objects (route, vlan, server, ...) omit the
group word. Quoting:
  * "double quotes" with backslash escapes (``\\"``)
  * q-strings used in advanced expressions: q{..} q(..) q[..] q<..> and qX..X for X in |/~!+#%'
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field

VERBS = frozenset({
    "add", "set", "unset", "bind", "unbind", "rm", "enable", "disable", "link", "unlink",
    "apply", "renumber", "clear", "import", "update", "rename", "expire", "install",
    "create", "save", "kill", "reset", "sync", "force", "shell", "show", "stat",
})

# Objects that are written without a group word.
SINGLE_WORD_OBJECTS = frozenset(s.lower() for s in {
    "server", "service", "serviceGroup", "vserver", "location", "locationFile", "route",
    "route6", "vlan", "arp", "nd6", "interface", "channel", "netProfile", "rnat", "rnat6",
    "inat", "inatparam", "vrid", "vrid6", "vxlan", "bridgegroup", "bridgetable", "fis",
    "netbridge", "l2param", "l3param", "l4param", "linkset", "ipset", "ipTunnel",
    "ip6Tunnel", "ipTunnelParam", "ptp", "ci", "onLinkIPv6Prefix", "mapbmr", "mapdmr",
    "mapdomain", "forwardingSession", "lacp", "rsskeytype",
})

_Q_PAIRS = {"{": "}", "(": ")", "[": "]", "<": ">"}
_Q_SAME = set("|/~!+#%'")
_OPTION_RE = re.compile(r"^-[A-Za-z][A-Za-z0-9_]*$")


class NsConfParseError(ValueError):
    pass


def tokenize(line: str) -> list[str]:
    """Split a CLI line into tokens. Quoted tokens keep their quotes (lossless join)."""
    tokens: list[str] = []
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if c.isspace():
            i += 1
            continue
        start = i
        if c == '"':
            i += 1
            while i < n and line[i] != '"':
                i += 2 if line[i] == "\\" else 1
            if i >= n:
                raise NsConfParseError(f"unterminated double quote: {line!r}")
            i += 1
        elif c == "q" and i + 1 < n and (line[i + 1] in _Q_PAIRS or line[i + 1] in _Q_SAME):
            opener = line[i + 1]
            closer = _Q_PAIRS.get(opener, opener)
            end = line.find(closer, i + 2)
            if end < 0:
                raise NsConfParseError(f"unterminated q-string: {line!r}")
            i = end + 1
        else:
            while i < n and not line[i].isspace():
                if line[i] == '"':  # quote glued to a bare word, e.g. -x"a b"
                    i += 1
                    while i < n and line[i] != '"':
                        i += 2 if line[i] == "\\" else 1
                    if i >= n:
                        raise NsConfParseError(f"unterminated double quote: {line!r}")
                i += 1
        tokens.append(line[start:i])
    return tokens


def unquote(token: str) -> str:
    if len(token) >= 2 and token[0] == token[-1] == '"':
        return re.sub(r"\\(.)", r"\1", token[1:-1])
    if len(token) >= 3 and token[0] == "q":
        opener = token[1]
        if _Q_PAIRS.get(opener, opener) == token[-1]:
            return token[2:-1]
    return token


@dataclass(frozen=True, slots=True)
class Command:
    raw: str
    verb: str
    object: str  # lower-cased, e.g. "system user", "route"
    name: str | None
    positional: tuple[str, ...]
    options: dict[str, tuple[str, ...]] = field(hash=False, compare=False)

    @property
    def key(self) -> tuple[str, str, str | None]:
        """Identity used to pair a removed line with its replacement in a diff."""
        return (self.verb, self.object, self.name)

    def option(self, name: str) -> tuple[str, ...] | None:
        return self.options.get(name.lower())


def parse_command(line: str) -> Command | None:
    """Parse one config line. Returns None for blank lines and comments."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    toks = tokenize(stripped)
    verb = toks[0].lower()
    rest = toks[1:]
    if not rest:
        return Command(stripped, verb, "", None, (), {})
    first = rest[0].lower()
    if first in SINGLE_WORD_OBJECTS:
        obj, rest = first, rest[1:]
    elif len(rest) >= 2 and not rest[1].startswith("-"):
        obj, rest = f"{first} {rest[1].lower()}", rest[2:]
    else:
        obj, rest = first, rest[1:]

    name: str | None = None
    positional: list[str] = []
    options: dict[str, list[str]] = {}
    current: str | None = None
    for t in rest:
        if _OPTION_RE.match(t):
            current = t[1:].lower()
            options.setdefault(current, [])
        elif current is not None:
            options[current].append(t)
        elif name is None:
            name = unquote(t)
        else:
            positional.append(t)
    return Command(stripped, verb, obj, name, tuple(positional),
                   {k: tuple(v) for k, v in options.items()})


def iter_commands(text: str) -> Iterator[Command]:
    for line in text.splitlines():
        cmd = parse_command(line)
        if cmd is not None:
            yield cmd


# ---- redaction ----------------------------------------------------------------------------

SENSITIVE_OPTIONS = frozenset(s.lower() for s in {
    "password", "ldapBindDnPassword", "radKey", "sharedSecret", "passcrypt", "secret",
    "clientSecret", "keyValue", "kek", "Hash", "authPassword", "privPassword", "PSK",
    "encryptionKey", "signingKey", "radiusKey", "tacacsSecret", "serverKey", "bindPassword",
    "certKeyPassword", "keyPassword", "oauthClientSecret", "token",
})
# Objects whose first positional (the name) is itself a secret.
SECRET_NAME_OBJECTS = frozenset({"snmp community"})
# Objects whose first positional after the name is a password hash.
HASH_POSITIONAL_OBJECTS = frozenset({"system user", "aaa user"})
_BLOB_RE = re.compile(r"^[0-9A-Fa-f]{16,}$|^[A-Za-z0-9+/=]{24,}$")


def fingerprint(value: str) -> str:
    return f"<redacted:{hashlib.sha256(value.encode()).hexdigest()[:8]}>"


def redact_line(line: str) -> str:
    """Replace secret material with stable fingerprints so changes stay visible in diffs."""
    cmd = parse_command(line)
    if cmd is None:
        return line.strip()
    toks = tokenize(line.strip())
    encrypted = any(t.lower() == "-encrypted" for t in toks)
    out: list[str] = []
    current: str | None = None
    seen_name = False
    positional_idx = 0
    header_len = 1 + len(cmd.object.split()) if cmd.object else 1
    for idx, t in enumerate(toks):
        if idx < header_len:
            out.append(t)
            continue
        if _OPTION_RE.match(t):
            current = t[1:].lower()
            out.append(t)
            continue
        redact = False
        if current is not None:
            redact = current in SENSITIVE_OPTIONS or (encrypted and bool(_BLOB_RE.match(t)))
        elif not seen_name:
            seen_name = True
            redact = cmd.object in SECRET_NAME_OBJECTS
        else:
            positional_idx += 1
            redact = (
                cmd.verb in {"add", "set"}
                and cmd.object in HASH_POSITIONAL_OBJECTS
                and positional_idx == 1
            ) or (encrypted and bool(_BLOB_RE.match(t)))
        out.append(fingerprint(unquote(t)) if redact else t)
    return " ".join(out)


def redact_config(text: str) -> str:
    return "\n".join(redact_line(line) for line in text.splitlines() if line.strip())


# ---- normalization ------------------------------------------------------------------------


def _is_node_specific(cmd: Command) -> bool:
    if cmd.object in {"ha node", "ns rpcnode", "ns hostname"}:
        return True
    if cmd.object == "ns config" and cmd.option("IPAddress") is not None:
        return True
    if cmd.object == "ns ip":
        t = cmd.option("type")
        return bool(t and t[0].upper() == "NSIP")
    return False


def config_lines(text: str, *, for_peer_compare: bool = False) -> list[str]:
    """Redacted, comment-free command lines.

    With ``for_peer_compare`` node-specific lines (NSIP, HA node, rpcNode, hostname) are
    dropped, so the two nodes of an HA pair can be compared.
    """
    lines = []
    for raw in text.splitlines():
        cmd = parse_command(raw)
        if cmd is None:
            continue
        if for_peer_compare and _is_node_specific(cmd):
            continue
        lines.append(redact_line(raw))
    return lines


def parse_many(lines: Iterable[str]) -> list[Command]:
    return [c for c in (parse_command(line) for line in lines) if c is not None]
