#!/usr/bin/env bash
# Install scalar on Ubuntu 24.04 (run as root from the repository root).
#   sudo bash deploy/install.sh
# Idempotent: re-running upgrades the package and keeps config, vault and state.
set -euo pipefail
umask 022

PREFIX=/opt/scalar
SRC_DIR=$(cd "$(dirname "$0")/.." && pwd)

die() { echo "error: $*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Usage:
  sudo bash deploy/install.sh
  sudo bash deploy/install.sh --verify-only

The default action installs or upgrades scalar without replacing local configuration
or customized systemd units. --verify-only makes no changes and checks the installed CLI,
configuration, systemd units, and local PostgreSQL connection.
EOF
}

verify_installation() {
    local expected_version installed_version
    echo "==> verifying installation"
    [[ -x "$PREFIX/venv/bin/scalar" ]] || die "installed CLI is missing"
    [[ -r /etc/scalar/config.yaml ]] || die "/etc/scalar/config.yaml is missing or unreadable"
    [[ -r /etc/systemd/system/scalar.service ]] || die "monitoring systemd unit is missing"
    [[ -r /etc/systemd/system/scalar-web.service ]] || die "web systemd unit is missing"

    expected_version=$("$PREFIX/venv/bin/python" -c \
        'import sys, tomllib; print(tomllib.load(open(sys.argv[1], "rb"))["project"]["version"])' \
        "$SRC_DIR/pyproject.toml")
    installed_version=$(runuser -u scalar -- "$PREFIX/venv/bin/scalar" version) \
        || die "scalar service user cannot run the installed CLI"
    [[ "$installed_version" == "$expected_version" ]] \
        || die "installed CLI version $installed_version does not match checkout $expected_version"
    runuser -u scalar -- "$PREFIX/venv/bin/scalar" web --help >/dev/null \
        || die "installed web commands are unavailable"
    runuser -u scalar -- "$PREFIX/venv/bin/scalar" \
        --config /etc/scalar/config.yaml config validate >/dev/null \
        || die "installed configuration is invalid"
    systemd-analyze verify /etc/systemd/system/scalar.service \
        /etc/systemd/system/scalar-web.service >/dev/null \
        || die "installed systemd units failed verification"
    runuser -u scalar -- psql -XAt -d scalar -c "SELECT 1" | grep -qx 1 \
        || die "scalar service user cannot connect to the local database"
    echo "    scalar $installed_version: CLI, config, units, and database verified"
}

[[ $EUID -eq 0 ]] || die "run as root"
[[ -s "$SRC_DIR/requirements.lock" ]] || die "requirements.lock is missing; use a complete release checkout"

. /etc/os-release
[[ "${VERSION_ID:-}" == "24.04" ]] || echo "warning: tested on Ubuntu 24.04 only (found ${PRETTY_NAME:-unknown})"
SYSTEMD_VER=$(systemctl --version | awk 'NR==1 {print $2}')
(( SYSTEMD_VER >= 250 )) || die "systemd >= 250 is required for encrypted credentials (found $SYSTEMD_VER)"

case "${1:-}" in
    "")
        ;;
    --verify-only)
        verify_installation
        exit 0
        ;;
    -h|--help)
        usage
        exit 0
        ;;
    *)
        usage >&2
        die "unknown argument: $1"
        ;;
esac

echo "==> packages"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y python3-venv python3-pip rsyslog nftables postgresql-16

echo "==> accounts"
getent group scalar-admin >/dev/null || groupadd --system scalar-admin
id scalar >/dev/null 2>&1 || useradd --system --user-group --home-dir /var/lib/scalar \
    --shell /usr/sbin/nologin --comment "scalar service" scalar
usermod -a -G scalar syslog   # rsyslog writes NetScaler syslog files for scalar to read

echo "==> directories"
install -d -m 0770 -o root -g scalar /etc/scalar
install -d -m 0700 -o scalar -g scalar /var/lib/scalar
install -d -m 0750 -o scalar -g scalar /var/log/scalar
install -d -m 0770 -o syslog -g scalar /var/log/scalar/syslog
install -d -m 0700 -o root -g root /etc/credstore.encrypted

echo "==> host key for systemd-creds"
systemd-creds setup >/dev/null
if [[ -e /dev/tpm0 || -e /dev/tpmrm0 ]]; then
    echo "    TPM2 present: consider re-sealing with --with-key=host+tpm2 (see docs/operations.md)"
fi

echo "==> python environment"
python3 -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install -q --require-hashes -r "$SRC_DIR/requirements.lock"
"$PREFIX/venv/bin/pip" install -q --force-reinstall --no-deps --no-build-isolation "$SRC_DIR"
chmod 0755 "$PREFIX"
chmod -R a+rX "$PREFIX/venv"
if [[ ! "$SRC_DIR/README.md" -ef "$PREFIX/README.md" ]]; then
    install -m 0644 "$SRC_DIR/README.md" "$PREFIX/README.md"
fi
ln -sf "$PREFIX/venv/bin/scalar" /usr/local/sbin/scalar

install -m 0644 "$SRC_DIR/deploy/scalar-syslog.logrotate" /etc/logrotate.d/scalar-syslog

echo "==> configuration"
if [[ ! -f /etc/scalar/config.yaml ]]; then
    install -m 0640 -o root -g scalar "$SRC_DIR/deploy/config.example.yaml" /etc/scalar/config.yaml
    echo "    wrote /etc/scalar/config.yaml from the example - edit it before starting"
fi
if [[ ! -f /etc/systemd/system/scalar.service ]]; then
    install -m 0644 "$SRC_DIR/deploy/scalar.service" /etc/systemd/system/scalar.service
else
    install -m 0644 "$SRC_DIR/deploy/scalar.service" /etc/systemd/system/scalar.service.packaged
    echo "    kept existing unit; updated template is scalar.service.packaged"
    if grep -qx 'ReadOnlyPaths=/etc/scalar' /etc/systemd/system/scalar.service; then
        sed -i.admin-backup 's|^ReadOnlyPaths=/etc/scalar$|ReadWritePaths=/etc/scalar|' /etc/systemd/system/scalar.service
        echo "    enabled daemon-side settings writes; other unit customizations kept"
    fi
fi
install -d -m 0755 /etc/systemd/system/scalar.service.d
if [[ ! -f /etc/systemd/system/scalar-web.service ]]; then
    install -m 0644 "$SRC_DIR/deploy/scalar-web.service" /etc/systemd/system/scalar-web.service
else
    install -m 0644 "$SRC_DIR/deploy/scalar-web.service" /etc/systemd/system/scalar-web.service.packaged
fi
if [[ ! -f /etc/systemd/system/scalar.service.d/egress.conf ]]; then
    install -m 0644 "$SRC_DIR/deploy/egress.conf.example" /etc/systemd/system/scalar.service.d/egress.conf
fi
systemctl daemon-reload

echo "==> PostgreSQL"
systemctl enable --now postgresql
if [[ $(runuser -u postgres -- psql -XAt -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM pg_roles WHERE rolname='scalar'") == 0 ]]; then
    runuser -u postgres -- createuser --no-superuser --no-createdb --no-createrole scalar
fi
if [[ $(runuser -u postgres -- psql -XAt -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM pg_database WHERE datname='scalar'") == 0 ]]; then
    runuser -u postgres -- createdb --owner=scalar scalar
fi
runuser -u scalar -- "$PREFIX/venv/bin/scalar" --config /etc/scalar/config.yaml db init

verify_installation

cat <<'EOF'

Installed and verified, but not started. Next steps (see README.md):
    1. Edit /etc/scalar/config.yaml and scalar.service.d/egress.conf
    2. sudo scalar bootstrap --escrow-out /root/scalar-escrow.json
       Move the escrow file offline, then remove the server copy.
    3. sudo scalar device pin <nsip>             -> verify and save spki_pin
    4. sudo scalar snippets <device> --server-ip <this-server>
       Review and apply the printed commands on the NetScaler.
    5. sudo scalar cred set sc_nitro
       sudo scalar cred test sc_nitro
    6. sudo scalar probe <device> && sudo scalar exposure
    7. sudo scalar rsyslog-config | sudo tee /etc/rsyslog.d/60-scalar.conf >/dev/null
       sudo rsyslogd -N1 && sudo systemctl restart rsyslog
       Review and persist the inventory firewall rules described in README.md.
    8. sudo systemctl daemon-reload && sudo systemctl enable --now scalar
    9. sudo bash deploy/install.sh --verify-only
       sudo systemctl is-active scalar
       sudo -u scalar scalar status
       sudo -u scalar scalar notify test

The service is not started automatically. For upgrades, restart scalar after validation.

Web dashboard (no default username/password):
    sudo scalar web user-set admin
    sudo systemctl enable --now scalar-web
    Open http://127.0.0.1:8080 on the server, or use the SSH tunnel in README.md.
    The legacy admin account (or first account) becomes the bootstrap administrator.
    Other legacy accounts become operators; assign roles from the Users screen.
    Restart both scalar and scalar-web after upgrading to enable administration.
EOF
