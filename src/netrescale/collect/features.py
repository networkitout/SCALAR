"""Work out which exploitability gates apply to a device (read-only NITRO queries).

A gate that can't be determined (for example, the cmdPolicy denies the query) stays None,
and the exposure check reports "possibly exposed" rather than guessing.
"""

from __future__ import annotations

import ipaddress
import logging

from netrescale.detect.exposure import DeviceFeatures
from netrescale.transport.nitro import NitroClient, NitroError

log = logging.getLogger(__name__)


async def _count(c: NitroClient, resource: str) -> int | None:
    try:
        return await c.count(resource)
    except NitroError as exc:
        log.info("%s: cannot count %s: %s", c.target.name, resource, exc)
        return None


async def _any_ipv6(c: NitroClient, resource: str, attrs: list[str]) -> bool | None:
    """True if any entry has an IPv6 address or is a domain-based server resolved over IPv6
    (IPv6 addressing mode or AAAA query type)."""
    try:
        body = await c.config(resource, attrs=attrs)
    except NitroError as exc:
        log.info("%s: cannot list %s: %s", c.target.name, resource, exc)
        return None
    return any(_is_ipv6(str(item.get("ipaddress", "")))
               or str(item.get("ipv6address", "")).upper() == "YES"
               or str(item.get("querytype", "")).upper() == "AAAA"
               for item in body.get(resource) or [])


def _is_ipv6(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).version == 6
    except ValueError:
        return False


async def _hdx_cr(c: NitroClient) -> bool | None:
    try:
        body = await c.config("crvserver", attrs=["name", "servicetype"])
    except NitroError:
        return None
    return any(str(v.get("servicetype", "")).upper() == "HDX"
               for v in body.get("crvserver") or [])


def _gt0(n: int | None) -> bool | None:
    return None if n is None else n > 0


def _any(*vals: bool | None) -> bool | None:
    if any(v is True for v in vals):
        return True
    if all(v is False for v in vals):
        return False
    return None


async def detect_features(c: NitroClient) -> DeviceFeatures:
    vpn = _gt0(await _count(c, "vpnvserver"))
    aaa = _gt0(await _count(c, "authenticationvserver"))
    idp = _gt0(await _count(c, "authenticationsamlidpprofile"))
    sp = _gt0(await _count(c, "authenticationsamlaction"))
    server_attrs = ["name", "ipaddress", "domain", "ipv6address", "querytype"]
    v6 = _any(await _any_ipv6(c, "server", server_attrs),
              await _any_ipv6(c, "service", ["name", "ipaddress"]))
    return DeviceFeatures(
        gateway_or_aaa=_any(vpn, aaa),
        saml_idp=idp,
        saml=_any(idp, sp),
        ipv6_lb=v6,
        hdx_content_routing=await _hdx_cr(c),
    )
