# Changelog

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
- Documentation now uses the project name SCALAR; the `netrescale` package, command and paths are unchanged.
- Project: MIT license, `SECURITY.md`, Dependabot, CI dependency/static/secret scanning.

## 0.4.3

Browser administration and monitoring (first public baseline).
