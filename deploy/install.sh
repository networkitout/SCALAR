#!/usr/bin/env bash
# Install netrescale on Ubuntu 24.04 (run as root from the repository root).
#   sudo bash deploy/install.sh
# Idempotent: re-running upgrades the package and keeps config, vault and state.
set -euo pipefail
umask 022

PREFIX=/opt/netrescale
SRC_DIR=$(cd "$(dirname "$0")/.." && pwd)

die() { echo "error: $*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Usage:
  sudo bash deploy/install.sh
  sudo bash deploy/install.sh --verify-only

The default action installs or upgrades netrescale without replacing local configuration
or customized systemd units. --verify-only makes no changes and checks the installed CLI,
configuration, systemd units, and local PostgreSQL connection.
EOF
}

verify_installation() {
    local expected_version installed_version
    echo "==> verifying installation"
    [[ -x "$PREFIX/venv/bin/netrescale" ]] || die "installed CLI is missing"
    [[ -r /etc/netrescale/config.yaml ]] || die "/etc/netrescale/config.yaml is missing or unreadable"
    [[ -r /etc/systemd/system/netrescale.service ]] || die "monitoring systemd unit is missing"
    [[ -r /etc/systemd/system/netrescale-web.service ]] || die "web systemd unit is missing"

    expected_version=$("$PREFIX/venv/bin/python" -c \
        'import sys, tomllib; print(tomllib.load(open(sys.argv[1], "rb"))["project"]["version"])' \
        "$SRC_DIR/pyproject.toml")
    installed_version=$(runuser -u netrescale -- "$PREFIX/venv/bin/netrescale" version) \
        || die "netrescale service user cannot run the installed CLI"
    [[ "$installed_version" == "$expected_version" ]] \
        || die "installed CLI version $installed_version does not match checkout $expected_version"
    runuser -u netrescale -- "$PREFIX/venv/bin/netrescale" web --help >/dev/null \
        || die "installed web commands are unavailable"
    runuser -u netrescale -- "$PREFIX/venv/bin/netrescale" \
        --config /etc/netrescale/config.yaml config validate >/dev/null \
        || die "installed configuration is invalid"
    systemd-analyze verify /etc/systemd/system/netrescale.service \
        /etc/systemd/system/netrescale-web.service >/dev/null \
        || die "installed systemd units failed verification"
    runuser -u netrescale -- psql -XAt -d netrescale -c "SELECT 1" | grep -qx 1 \
        || die "netrescale service user cannot connect to the local database"
    echo "    netrescale $installed_version: CLI, config, units, and database verified"
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
getent group netrescale-admin >/dev/null || groupadd --system netrescale-admin
id netrescale >/dev/null 2>&1 || useradd --system --user-group --home-dir /var/lib/netrescale \
    --shell /usr/sbin/nologin --comment "netrescale service" netrescale
usermod -a -G netrescale syslog   # rsyslog writes NetScaler syslog files for netrescale to read

echo "==> directories"
install -d -m 0770 -o root -g netrescale /etc/netrescale
install -d -m 0700 -o netrescale -g netrescale /var/lib/netrescale
install -d -m 0750 -o netrescale -g netrescale /var/log/netrescale
install -d -m 0770 -o syslog -g netrescale /var/log/netrescale/syslog
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
ln -sf "$PREFIX/venv/bin/netrescale" /usr/local/sbin/netrescale

install -m 0644 "$SRC_DIR/deploy/netrescale-syslog.logrotate" /etc/logrotate.d/netrescale-syslog

echo "==> configuration"
if [[ ! -f /etc/netrescale/config.yaml ]]; then
    install -m 0640 -o root -g netrescale "$SRC_DIR/deploy/config.example.yaml" /etc/netrescale/config.yaml
    echo "    wrote /etc/netrescale/config.yaml from the example - edit it before starting"
fi
if [[ ! -f /etc/systemd/system/netrescale.service ]]; then
    install -m 0644 "$SRC_DIR/deploy/netrescale.service" /etc/systemd/system/netrescale.service
else
    install -m 0644 "$SRC_DIR/deploy/netrescale.service" /etc/systemd/system/netrescale.service.packaged
    echo "    kept existing unit; updated template is netrescale.service.packaged"
    if grep -qx 'ReadOnlyPaths=/etc/netrescale' /etc/systemd/system/netrescale.service; then
        sed -i.admin-backup 's|^ReadOnlyPaths=/etc/netrescale$|ReadWritePaths=/etc/netrescale|' /etc/systemd/system/netrescale.service
        echo "    enabled daemon-side settings writes; other unit customizations kept"
    fi
fi
install -d -m 0755 /etc/systemd/system/netrescale.service.d
if [[ ! -f /etc/systemd/system/netrescale-web.service ]]; then
    install -m 0644 "$SRC_DIR/deploy/netrescale-web.service" /etc/systemd/system/netrescale-web.service
else
    install -m 0644 "$SRC_DIR/deploy/netrescale-web.service" /etc/systemd/system/netrescale-web.service.packaged
fi
if [[ ! -f /etc/systemd/system/netrescale.service.d/egress.conf ]]; then
    install -m 0644 "$SRC_DIR/deploy/egress.conf.example" /etc/systemd/system/netrescale.service.d/egress.conf
fi
systemctl daemon-reload

echo "==> PostgreSQL"
systemctl enable --now postgresql
if [[ $(runuser -u postgres -- psql -XAt -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM pg_roles WHERE rolname='netrescale'") == 0 ]]; then
    runuser -u postgres -- createuser --no-superuser --no-createdb --no-createrole netrescale
fi
if [[ $(runuser -u postgres -- psql -XAt -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM pg_database WHERE datname='netrescale'") == 0 ]]; then
    runuser -u postgres -- createdb --owner=netrescale netrescale
fi
runuser -u netrescale -- "$PREFIX/venv/bin/netrescale" --config /etc/netrescale/config.yaml db init

verify_installation

cat <<'EOF'

Installed and verified, but not started. Next steps (see README.md):
    1. Edit /etc/netrescale/config.yaml and netrescale.service.d/egress.conf
    2. sudo netrescale bootstrap --escrow-out /root/netrescale-escrow.json
       Move the escrow file offline, then remove the server copy.
    3. sudo netrescale device pin <nsip>             -> verify and save spki_pin
    4. sudo netrescale snippets <device> --server-ip <this-server>
       Review and apply the printed commands on the NetScaler.
    5. sudo netrescale cred set nr_nitro
       sudo netrescale cred test nr_nitro
    6. sudo netrescale probe <device> && sudo netrescale exposure
    7. sudo netrescale rsyslog-config | sudo tee /etc/rsyslog.d/60-netrescale.conf >/dev/null
       sudo rsyslogd -N1 && sudo systemctl restart rsyslog
       Review and persist the inventory firewall rules described in README.md.
    8. sudo systemctl daemon-reload && sudo systemctl enable --now netrescale
    9. sudo bash deploy/install.sh --verify-only
       sudo systemctl is-active netrescale
       sudo -u netrescale netrescale status
       sudo -u netrescale netrescale notify test

The service is not started automatically. For upgrades, restart netrescale after validation.

Web dashboard (no default username/password):
    sudo netrescale web user-set admin
    sudo systemctl enable --now netrescale-web
    Open http://127.0.0.1:8080 on the server, or use the SSH tunnel in README.md.
    The legacy admin account (or first account) becomes the bootstrap administrator.
    Other legacy accounts become operators; assign roles from the Users screen.
    Restart both netrescale and netrescale-web after upgrading to enable administration.
EOF
