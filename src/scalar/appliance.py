"""NetScaler CLI snippets an admin applies by hand. scalar itself never changes appliances.

Lines marked VERIFY rely on options whose exact behaviour should be confirmed on your
firmware (with `scalar probe` output or Citrix docs) before you apply them.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from pathlib import Path

from scalar.collect.fim import WATCHES, Watch
from scalar.config import Config, Device
from scalar.secrets.vault import atomic_write

APPLIANCE_EGRESS_DROPIN = Path(
    "/etc/systemd/system/scalar.service.d/30-appliance-egress.conf")
APPLIANCE_EGRESS_MARKER = "# Managed by scalar device allow-network.\n"


def allow_appliance_network(cfg: Config, path: Path = APPLIANCE_EGRESS_DROPIN) -> list[str]:
    hosts = [ipaddress.ip_address(device.nsip) for device in cfg.devices]
    if any(isinstance(host, ipaddress.IPv6Address) and host.scope_id is not None for host in hosts):
        raise ValueError("scoped IPv6 addresses are not supported in the appliance allowlist")
    addresses = sorted({str(ipaddress.ip_network(host)) for host in hosts})
    if not addresses:
        raise ValueError("no device management addresses are configured")
    if path.exists() and not path.read_text().startswith(APPLIANCE_EGRESS_MARKER):
        raise ValueError("refusing to overwrite an unmanaged appliance-egress drop-in")
    content = APPLIANCE_EGRESS_MARKER + "[Service]\n" + "".join(
        f"IPAddressAllow={address}\n" for address in addresses)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    atomic_write(path, content.encode(), backup=True, mode=0o644)
    return addresses

# show/stat only, including the objects the built-in read-only policy hides (running and
# saved config, system users). Everything else, including `shell`, is implicitly denied.
RO_POLICY_REGEX = r"(^show\s+(?!techsupport)\S.*)|(^stat\s+\S.*)"


def accounts_snippet() -> str:
    return f"""\
# ---- scalar accounts (apply once per appliance; HA config sync copies them) ----------
# Least-privilege NITRO account: config polling, stats, exposure checks.
add system cmdPolicy scalar_ro ALLOW "{RO_POLICY_REGEX}"
add system user sc_nitro -externalAuth DISABLED -allowedManagementInterface API -timeout 900
#   (the CLI prompts for the password; store the same value with: scalar cred set sc_nitro)
bind system user sc_nitro scalar_ro 100

# VERIFY: -allowedManagementInterface is available on 13.1/14.1 builds. Check after applying
# with: show system user sc_nitro
#
# Restrict where management logins can come from. NetScaler has no per-account source
# restriction, so limit NSIP management (SSH/HTTPS) to your admin subnets plus this server
# with ns ACLs or the -restrictAccess option on the NSIP. Plan this with your network team
# because it affects every administrator.
save ns config
"""


# ---- file-integrity monitoring account ------------------------------------------------------
# The policies are generated from collect/fim.py's watch list so they cannot drift from what
# the collector requests. A double quote is written as \x22 so the CLI string needs no
# escaping. VERIFY: the command text NITRO `GET systemfile` is matched as (argument order and
# -fileLocation quoting) on 13.1 and 14.1; run the prod_probe feasibility test and compare the
# CMD_EXECUTED lines in ns.log.
_Q = r"\x22?"
_NAME = r"[^/\x22\s]+"
_SEGMENT = rf"(?:/(?!\.\.?(?:/|\x22|\s|$)){_NAME})"
# Stricter than collect/fim.py's check, never looser: any ssh_host_* or id_<keytype>* name.
_PRIVATE_KEY = (r"(?i:ssh_host_|id_(?:rsa|dsa|ecdsa|ed25519)"
                r"|[^/\x22\s]*\.(?:key|pem|p12|pfx|ppk)\x22?\s)")


def _locations(watches: Iterable[Watch]) -> str:
    """-fileLocation values for these watches: each root, plus subdirectories to its depth
    (a watch limited to named files covers its root only)."""
    levels: dict[str, int] = {}
    for watch in watches:
        depth = 0 if watch.names else watch.depth
        levels[watch.root] = max(levels.get(watch.root, 0), depth)
    deep = [root for root, depth in levels.items() if depth > 1]
    roots = [root for root in levels if not any(root.startswith(other + "/") for other in deep)]
    groups = []
    for wanted, suffix in ((0, ""), (1, f"{_SEGMENT}?"), (2, f"{_SEGMENT}*")):
        chosen = [re.escape(root) for root in roots if min(levels[root], 2) == wanted]
        if chosen:
            groups.append(f"(?:{'|'.join(chosen)}){suffix}")
    return f"(?:{'|'.join(groups)})"


FIM_LIST_REGEX = (rf"^show\s+system\s+file\s+-fileLocation\s+{_Q}{_locations(WATCHES)}/?{_Q}$")
FIM_READ_REGEX = (
    rf"^show\s+system\s+file\s+{_Q}(?:" + "|".join(
        [rf"(?:{'|'.join(re.escape(name) for name, _kind in watch.names)}){_Q}\s+-fileLocation"
         rf"\s+{_Q}{re.escape(watch.root)}/?{_Q}" for watch in WATCHES if watch.names]
        # SSH directories: public material only (authorized_keys*, *.pub), never private keys.
        + [rf"(?!{_PRIVATE_KEY})(?:authorized_keys[^/\x22\s]*|[^/\x22\s]+\.pub){_Q}\s+"
           rf"-fileLocation\s+{_Q}"
           + _locations(w for w in WATCHES if w.kind == "ssh" and not w.names) + rf"/?{_Q}"]
        + [rf"(?!\.\.?{_Q}\s)(?!{_PRIVATE_KEY}){_NAME}{_Q}\s+-fileLocation\s+{_Q}"
           + _locations(w for w in WATCHES if w.content and not w.names and w.kind != "ssh")
           + rf"/?{_Q}"])
    + ")$")
FIM_VERSION_REGEX = r"^show\s+ns\s+version$"


def fim_snippet() -> str:
    return f"""\
# ---- scalar file-integrity account (devices with fim.enabled) -----------------------------
# A separate account, so sc_nitro never needs `show system file` outside /var/log. sc_fim may
# list the monitored directories, read files in them (never /nsconfig/ssl, /nsconfig/keys,
# private keys, ns.conf, cores or crash dumps), and read the firmware version. Nothing else.
add system cmdPolicy scalar_fim_list ALLOW "{FIM_LIST_REGEX}"
add system cmdPolicy scalar_fim_read ALLOW "{FIM_READ_REGEX}"
add system cmdPolicy scalar_fim_version ALLOW "{FIM_VERSION_REGEX}"
add system user sc_fim -externalAuth DISABLED -allowedManagementInterface API -timeout 900
#   (the CLI prompts for the password; store the same value with: scalar cred set sc_fim)
bind system user sc_fim scalar_fim_list 100
bind system user sc_fim scalar_fim_read 110
bind system user sc_fim scalar_fim_version 120
# Listing only: leave out scalar_fim_read. Files are then compared on listing metadata
# (size, mtime) and every refused read is reported as a 'coverage unknown' gap.
#
# VERIFY on 13.1 and 14.1 before relying on these policies:
#   - the command text NITRO GET systemfile is matched as (argument order, -fileLocation
#     quoting): run the prod_probe feasibility test and compare ns.log CMD_EXECUTED lines;
#   - that \\x22 in a cmdSpec matches a double quote, and the maximum cmdSpec length;
#   - that sc_fim is refused: show system file -fileLocation /nsconfig/ssl
#     and: show system file ns.conf -fileLocation /nsconfig
save ns config
"""


def syslog_snippet(server_ip: str) -> str:
    return f"""\
# ---- send audit/syslog to scalar (TCP, GMT, ISO-like dates) ----------------------------
add audit syslogAction sc_syslog {server_ip} -serverPort 514 -transport TCP -logLevel ALL -dateFormat YYYYMMDD -timeZone GMT_TIME -managementlog ALL -mgmtlogLevel ALL
add audit syslogPolicy sc_syslog_pol true sc_syslog
bind audit syslogGlobal -policyName sc_syslog_pol -priority 100
# VERIFY: -managementlog/-mgmtlogLevel (forward SHELL/ACCESS logs) need 13.1+; use archive
# search to confirm the expected records arrive. Syslog leaves from the NSIP unless a
# netProfile is set; list every source IP under the device's syslog_sources.
save ns config
"""


def device_snippet(cfg: Config, d: Device, server_ip: str) -> str:
    pair = cfg.pair_of(d.name)
    head = f"# ===== {d.name} ({d.nsip}){' - HA pair ' + pair.name if pair else ''} =====\n"
    note = ("# HA: apply on the PRIMARY only; config sync copies it to the secondary.\n"
            if pair else "")
    fim = (fim_snippet() if d.fim.enabled else
           "# File-integrity monitoring is off for this device (set fim.enabled: true to print "
           "the sc_fim account).\n")
    return head + note + accounts_snippet() + "\n" + syslog_snippet(server_ip) + "\n" + fim
