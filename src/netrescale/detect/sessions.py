"""Correlate Gateway/AAA session IDs with client IPs to spot hijacked sessions.

CitrixBleed (CVE-2023-4966) and CitrixBleed 2 (CVE-2025-5777) leak session tokens. An
attacker replaying a token shows up as one SessionId used from more than one client IP.
Session IDs reset when the appliance reboots, so the key includes the node's boot id.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from netrescale.parse.nslog import LogEvent

_IP_SOURCES = ("Client_ip", "Source", "ClientIP")


@dataclass(slots=True)
class SessionState:
    user: str | None
    first_ip: str
    first_seen: datetime
    last_seen: datetime
    ips: dict[str, datetime] = field(default_factory=dict)
    reported_ips: set[str] = field(default_factory=set)


@dataclass(frozen=True, slots=True)
class SessionReuse:
    device: str
    session_id: str
    user: str | None
    original_ip: str
    new_ip: str
    first_seen: datetime
    seen_at: datetime

    @property
    def dedup_key(self) -> str:
        return f"session-reuse|{self.device}|{self.session_id}|{self.new_ip}"


class SessionTracker:
    """In-memory, bounded. The daemon persists observations to session_observations too."""

    def __init__(self, idle_ttl: timedelta = timedelta(hours=24),
                 max_sessions: int = 500_000) -> None:
        self._ttl = idle_ttl
        self._max = max_sessions
        self._sessions: OrderedDict[tuple[str, str, str], SessionState] = OrderedDict()

    def __len__(self) -> int:
        return len(self._sessions)

    def observe(self, ev: LogEvent, boot_id: str = "") -> list[SessionReuse]:
        sid = ev.fields.get("SessionId")
        if not sid:
            return []
        ips = {ip for ip in (ev.ip_field(f) for f in _IP_SOURCES) if ip}
        if not ips:
            return []
        now = ev.ts or datetime.now(UTC)
        key = (ev.device, boot_id, sid)
        state = self._sessions.get(key)
        if state is None:
            first = ev.ip_field("Client_ip") or sorted(ips)[0]
            state = SessionState(ev.fields.get("User"), first, now, now)
            self._sessions[key] = state
        self._sessions.move_to_end(key)
        state.last_seen = max(state.last_seen, now)
        out = []
        for ip in sorted(ips):
            state.ips.setdefault(ip, now)
            if ip != state.first_ip and ip not in state.reported_ips:
                state.reported_ips.add(ip)
                out.append(SessionReuse(ev.device, sid, state.user, state.first_ip, ip,
                                        state.first_seen, now))
        self._evict(now)
        return out

    def _evict(self, now: datetime) -> None:
        while self._sessions:
            state = next(iter(self._sessions.values()))
            if len(self._sessions) > self._max or now - state.last_seen > self._ttl:
                self._sessions.popitem(last=False)
            else:
                break
