#!/usr/bin/env bash
# NTLM-Analyzer - find out who still uses NTLM in your Active Directory.
# Copyright (C) 2026  Nobrac / Carbon / NoPCAP
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# ---------------------------------------------------------------------------
# NTLM-Analyzer — collector installer for Linux (systemd)
#
# Detects the distribution family (Debian/Ubuntu vs. RHEL/Alma/Rocky/Fedora),
# asks a few questions, then installs the collector as a hardened systemd
# service running under a dedicated system user.
#
# Usage:  sudo ./install.sh          (run from the repository root,
#                                     next to ntlm-collector.py)
# ---------------------------------------------------------------------------
set -euo pipefail

# ----------------------------- pretty output -------------------------------
if [[ -t 1 ]]; then
    C_RESET=$'\e[0m'; C_BOLD=$'\e[1m'; C_DIM=$'\e[2m'
    C_GREEN=$'\e[32m'; C_YELLOW=$'\e[33m'; C_RED=$'\e[31m'; C_CYAN=$'\e[36m'
else
    C_RESET=""; C_BOLD=""; C_DIM=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_CYAN=""
fi
ok()   { echo "  ${C_GREEN}✓${C_RESET} $*"; }
warn() { echo "  ${C_YELLOW}!${C_RESET} $*"; }
fail() { echo "  ${C_RED}✗${C_RESET} $*" >&2; exit 1; }
step() { echo; echo "${C_BOLD}${C_CYAN}==>${C_RESET}${C_BOLD} $*${C_RESET}"; }
ask()  { # ask "Question" "default" -> REPLY
    local q="$1" def="${2-}"
    if [[ -n "$def" ]]; then
        read -r -p "  ${q} ${C_DIM}[${def}]${C_RESET}: " REPLY || true
        REPLY="${REPLY:-$def}"
    else
        read -r -p "  ${q}: " REPLY || true
    fi
}

trap 'echo; echo "${C_RED}Installation aborted (error in line $LINENO).${C_RESET}" >&2' ERR

echo "${C_BOLD}"
echo "  ─────────────────────────────────────────────"
echo "   NTLM-Analyzer · collector installer (Linux)"
echo "  ─────────────────────────────────────────────${C_RESET}"

# ----------------------------- preconditions -------------------------------
step "Checking preconditions"

[[ $EUID -eq 0 ]] || fail "Please run as root (sudo ./install.sh)."
ok "Running as root"

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COLLECTOR_SRC="${SRC_DIR}/ntlm-collector.py"
[[ -f "$COLLECTOR_SRC" ]] || fail "ntlm-collector.py not found next to this script (${SRC_DIR})."
ok "Found ntlm-collector.py"

command -v systemctl >/dev/null 2>&1 || fail "systemd (systemctl) not found — this installer targets systemd distributions."
ok "systemd present"

# ----------------------------- distro detection ----------------------------
step "Detecting distribution"

OS_RELEASE_FILE="${OS_RELEASE_FILE:-/etc/os-release}"
[[ -r "$OS_RELEASE_FILE" ]] || fail "Cannot read ${OS_RELEASE_FILE}."
# shellcheck disable=SC1090
. "$OS_RELEASE_FILE"
DISTRO_ID="${ID:-unknown}"
DISTRO_LIKE="${ID_LIKE:-}"
PRETTY="${PRETTY_NAME:-$DISTRO_ID}"

FAMILY=""
case " ${DISTRO_ID} ${DISTRO_LIKE} " in
    *" debian "*|*" ubuntu "*)          FAMILY="debian" ;;
    *" rhel "*|*" fedora "*|*" centos "*|*" almalinux "*|*" rocky "*) FAMILY="rhel" ;;
esac
[[ -n "$FAMILY" ]] || fail "Unsupported distribution: ${PRETTY} (need Debian- or RHEL-family)."
ok "Detected: ${PRETTY}  ${C_DIM}(family: ${FAMILY})${C_RESET}"

PKG_INSTALL="apt-get install -y"
[[ "$FAMILY" == "rhel" ]] && PKG_INSTALL="dnf install -y"

# ----------------------------- python check -------------------------------
step "Checking Python (need ≥ 3.7)"

PYBIN=""
for cand in python3.12 python3.11 python3.10 python3.9 python3.8 python3.7 python3; do
    if command -v "$cand" >/dev/null 2>&1; then
        if "$cand" -c 'import sys; sys.exit(0 if sys.version_info >= (3,7) else 1)' 2>/dev/null; then
            PYBIN="$(command -v "$cand")"
            break
        fi
    fi
done

if [[ -z "$PYBIN" ]]; then
    warn "No suitable Python found."
    PKG="python3"; [[ "$FAMILY" == "rhel" ]] && PKG="python3.11"   # RHEL/Alma 8 ships 3.6
    ask "Install ${PKG} now via package manager? (yes/no)" "yes"
    [[ "$REPLY" == "yes" || "$REPLY" == "y" ]] || fail "Python ≥ 3.7 is required."
    $PKG_INSTALL "$PKG" >/dev/null
    for cand in python3.11 python3; do
        command -v "$cand" >/dev/null 2>&1 && PYBIN="$(command -v "$cand")" && break
    done
    [[ -n "$PYBIN" ]] || fail "Python installation did not yield a usable interpreter."
fi
ok "Using $($PYBIN -V 2>&1) at ${PYBIN}"

# ----------------------------- questions -----------------------------------
step "Configuration"

ask "Install directory" "/opt/ntlm-analyzer";        INSTALL_DIR="$REPLY"
ask "Data directory (SQLite DB)" "/var/lib/ntlm-analyzer"; DATA_DIR="$REPLY"
ask "Listen port" "8443";                            PORT="$REPLY"
[[ "$PORT" =~ ^[0-9]+$ ]] || fail "Port must be numeric."

GEN_KEY="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
ask "API key for agents (X-Api-Key)" "$GEN_KEY";     API_KEY="$REPLY"

echo -n "  Dashboard password ${C_DIM}(empty = generate)${C_RESET}: "
read -rs DASH_PW || true; echo
if [[ -z "$DASH_PW" ]]; then
    DASH_PW="$(head -c 18 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    GENERATED_PW=1
else
    GENERATED_PW=0
fi

ask "Retention in days (0 = keep forever)" "90";     RETENTION="$REPLY"
[[ "$RETENTION" =~ ^[0-9]+$ ]] || fail "Retention must be numeric."

TLS_ARGS=(); TLS_ON=0
ask "Path to TLS certificate (PEM, empty = plain HTTP)" ""
CERT="$REPLY"
if [[ -n "$CERT" ]]; then
    [[ -f "$CERT" ]] || fail "Certificate not found: ${CERT}"
    ask "Path to TLS private key (PEM)" ""
    KEY="$REPLY"
    [[ -f "$KEY" ]] || fail "Key not found: ${KEY}"
    TLS_ARGS=(--cert "$CERT" --tlskey "$KEY"); TLS_ON=1
else
    warn "No TLS: telemetry, API key and login will cross the network in cleartext."
fi

# ----------------------------- install -------------------------------------
step "Installing files"

SVC_USER="ntlm-analyzer"
if ! id -u "$SVC_USER" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER" 2>/dev/null \
        || useradd --system --no-create-home --shell /sbin/nologin "$SVC_USER"
    ok "Created system user '${SVC_USER}'"
else
    ok "System user '${SVC_USER}' already exists"
fi

install -d -m 755 "$INSTALL_DIR"
install -m 644 "$COLLECTOR_SRC" "${INSTALL_DIR}/ntlm-collector.py"
ok "Collector → ${INSTALL_DIR}/ntlm-collector.py"

install -d -m 750 -o "$SVC_USER" -g "$SVC_USER" "$DATA_DIR"
ok "Data dir  → ${DATA_DIR} (owner ${SVC_USER}, mode 750)"

ENV_DIR="/etc/ntlm-analyzer"
ENV_FILE="${ENV_DIR}/collector.env"
install -d -m 750 "$ENV_DIR"
umask 077
cat > "$ENV_FILE" <<EOF
# NTLM-Analyzer collector secrets — root only. Loaded by the systemd unit.
NTLM_DASHBOARD_PASSWORD=${DASH_PW}
NTLM_API_KEY=${API_KEY}
EOF
umask 022
chmod 600 "$ENV_FILE"
ok "Secrets   → ${ENV_FILE} (mode 600; not visible in 'ps' or the unit file)"

if [[ $TLS_ON -eq 1 ]]; then
    # the service user must be able to read cert + key
    setfacl -m "u:${SVC_USER}:r" "$CERT" "$KEY" 2>/dev/null \
        || warn "Could not set ACL on cert/key — ensure '${SVC_USER}' can read them."
fi

step "Writing systemd unit"

UNIT=/etc/systemd/system/ntlm-analyzer.service
EXTRA=""
[[ $TLS_ON -eq 1 ]] && EXTRA=" --cert ${CERT} --tlskey ${KEY}"
cat > "$UNIT" <<EOF
[Unit]
Description=NTLM-Analyzer collector (dashboard + ingest API)
Documentation=https://github.com/Nobrac/NTLM-Analyzer
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SVC_USER}
Group=${SVC_USER}
EnvironmentFile=${ENV_FILE}
ExecStart=${PYBIN} ${INSTALL_DIR}/ntlm-collector.py --host 0.0.0.0 --port ${PORT} --db ${DATA_DIR}/ntlm.db --retention-days ${RETENTION}${EXTRA}
Restart=always
RestartSec=5

# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DATA_DIR}
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
EOF
ok "Unit      → ${UNIT}"

# ----------------------------- firewall ------------------------------------
step "Firewall"

if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    ask "firewalld is active — open port ${PORT}/tcp? (yes/no)" "yes"
    if [[ "$REPLY" == "yes" || "$REPLY" == "y" ]]; then
        firewall-cmd --add-port="${PORT}/tcp" --permanent >/dev/null
        firewall-cmd --reload >/dev/null
        ok "Opened ${PORT}/tcp (firewalld, permanent)"
    else
        warn "Skipped — agents will not reach the collector until the port is open."
    fi
elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    ask "ufw is active — allow port ${PORT}/tcp? (yes/no)" "yes"
    if [[ "$REPLY" == "yes" || "$REPLY" == "y" ]]; then
        ufw allow "${PORT}/tcp" >/dev/null
        ok "Allowed ${PORT}/tcp (ufw)"
    else
        warn "Skipped — agents will not reach the collector until the port is open."
    fi
else
    ok "No active firewalld/ufw detected — nothing to do"
fi

# ----------------------------- start ---------------------------------------
step "Starting the service"

systemctl daemon-reload
systemctl enable --now ntlm-analyzer.service >/dev/null 2>&1 || systemctl enable --now ntlm-analyzer
ok "Service enabled and started"

sleep 1.5
SCHEME="http"; CURL_K=""
[[ $TLS_ON -eq 1 ]] && SCHEME="https" && CURL_K="-k"
if command -v curl >/dev/null 2>&1 \
   && curl -s $CURL_K --max-time 4 -o /dev/null "${SCHEME}://127.0.0.1:${PORT}/healthz"; then
    ok "Health check: ${SCHEME}://127.0.0.1:${PORT}/healthz answers"
else
    warn "Health check did not answer (yet). Inspect with: journalctl -u ntlm-analyzer -n 30"
fi

# ----------------------------- summary -------------------------------------
HOSTNAME_FQDN="$(hostname -f 2>/dev/null || hostname)"
echo
echo "${C_BOLD}${C_GREEN}  Installation complete.${C_RESET}"
echo
echo "  ${C_BOLD}Dashboard${C_RESET}   ${SCHEME}://${HOSTNAME_FQDN}:${PORT}/"
if [[ $GENERATED_PW -eq 1 ]]; then
echo "  ${C_BOLD}Password${C_RESET}    ${DASH_PW}   ${C_DIM}(generated — stored in ${ENV_FILE})${C_RESET}"
else
echo "  ${C_BOLD}Password${C_RESET}    (as entered — stored in ${ENV_FILE})"
fi
echo "  ${C_BOLD}API key${C_RESET}     ${API_KEY}"
echo
echo "  ${C_BOLD}Agent install command (on each Windows machine, elevated):${C_RESET}"
echo "      ntlm-agent.exe install --collector-url ${SCHEME}://${HOSTNAME_FQDN}:${PORT} --api-key ${API_KEY}"
echo
echo "  ${C_DIM}Service:   systemctl status|restart ntlm-analyzer"
echo "  Logs:      journalctl -u ntlm-analyzer -f"
echo "  Database:  ${DATA_DIR}/ntlm.db"
echo "  Backup:    sqlite3 ${DATA_DIR}/ntlm.db \".backup /path/backup.db\"${C_RESET}"
echo
