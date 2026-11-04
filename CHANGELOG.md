# Changelog

## 0.5.0

**Renamed from netrescale to SCALAR (breaking).** Install fresh; there is no in-place upgrade.
Package and CLI are `scalar`; service user/group `scalar` and `scalar-admin`; paths
`/etc/scalar`, `/var/lib/scalar`, `/var/log/scalar`, `/opt/scalar`; units `scalar.service` and
`scalar-web.service`; database `scalar`; environment variables `SCALAR_*`; appliance-side
account names `sc_nitro`, `sc_fim`, `sc_sweep`, `sc_syslog`. The vault/escrow file format is
unchanged apart from the renamed credential store file `scalar.vault-key`.

## 0.4.4

Security hardening release. Behavior changes to review before upgrading:

- Browser settings can no longer change appliance addresses, TLS trust files, credential
  references, new appliances or notification destinations. Edit those in the config file on
  the host, or set `web.allow_sensitive_settings: true` there.
- `notify.smtp.credential` now requires `starttls: true`.
- The control-socket peer check refuses when the peer identity cannot be read (Linux only in
  practice; other platforms are for development).
- Per-username login throttle; unauthenticated `/api/auth` no longer reports the version.
- HSTS adds `includeSubDomains`; the session cookie is `Secure` on any HTTPS request.
- Settings validation warns on HTTP dashboard, plain-TCP SIEM and SMTP without STARTTLS.
- `install.sh` installs a logrotate rule bounding the syslog quarantine file.
- Dependencies: certifi, opentelemetry-api and setuptools updated.
- Documentation uses the project name SCALAR.
- Project: MIT license, `SECURITY.md`, Dependabot, CI dependency/static/secret scanning.

## 0.4.3

Browser administration and monitoring (first public baseline).
