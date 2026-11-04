# Sending SCALAR findings to CrowdStrike NG-SIEM through Cribl

SCALAR sends each finding as an RFC 5424 syslog message over TCP or TLS, framed with
RFC 6587 octet counting (newline-safe). The message body is ECS-style JSON (the default) or
CEF.

## SCALAR side

```yaml
notify:
  siem:
    host: cribl.example.internal
    port: 6514
    transport: tls            # tcp for testing only
    format: json              # or cef
    ca_bundle: /etc/scalar/cribl-ca.pem   # if Cribl's cert isn't publicly trusted
    min_severity: info        # the SIEM should get everything
```

Add Cribl's IP to `IPAddressAllow=` in the systemd unit.

## Cribl side

1. **Source:** create a Syslog source with TCP and TLS on 6514, and set the
   octet-counting/framing option to auto-detect.
2. **Route:** match `appname == 'scalar'`.
3. **Pipeline:**
   - parse `message` with the JSON parser into top-level fields (or Serialize/Parser in
     KV mode for CEF);
   - set `_time` from `@timestamp`;
   - keep `event.*`, `rule.*`, `host.name`, `vulnerability.id`, `threat.technique.id`,
     and `scalar.*`.
4. **Destination:** your CrowdStrike Falcon NG-SIEM HEC/HTTP destination. Tag it with a
   parser that knows the ECS-style fields, such as a custom parser based on
   CrowdStrike's parsing standard.

## Field map (JSON)

| SCALAR field | Meaning | Example |
|---|---|---|
| `@timestamp` | When the evidence was observed (UTC) | `2026-10-05T10:00:01+00:00` |
| `message` | One-line summary | `NetScaler running configuration changed on ns-gw-01: 1 added` |
| `event.kind` | Always `alert` | |
| `event.category` | `configuration` or `intrusion_detection` | |
| `event.severity` | 1/25/50/75/99 for info..critical | `99` |
| `event.id` | Dedup key, stable for the same issue | `config-running\|ns-gw-01\|9f2c...` |
| `event.dataset` | `scalar.<category>` | `scalar.config_change` |
| `rule.id` / `rule.name` | Detection id and title | `mgmt-high-risk-command` |
| `host.name`, `observer.hostname` | NetScaler device name | `ns-gw-01` |
| `vulnerability.id` | CVE list | `["CVE-2025-5777"]` |
| `threat.technique.id` | MITRE ATT&CK techniques | `["T1098"]` |
| `scalar.severity` | Text severity | `critical` |
| `scalar.evidence` | Redacted diff, raw log line, fields, counts | object |

CEF uses `rt`, `dvchost`, `msg`, `cat`, `externalId` (dedup key), `cs1=cve`, `cs2=mitre`
and `cs3=evidence` (JSON, truncated to 3800 characters).

## Testing

```bash
# on the scalar server, after configuring notify.siem:
scalar hunt /path/to/sample-ns.log --json | head -1   # what one event looks like
```

Coming in M3: when `forward_events: true` is set, all indexed NetScaler events are
forwarded too, with `event.kind: event`.
