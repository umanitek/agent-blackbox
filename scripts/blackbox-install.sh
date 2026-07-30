#!/bin/bash
# ============================================================================
# Agent Blackbox — one-command installer (macOS / Linux)
# ============================================================================
# A thin, guided wrapper around the Hermes Agent dev setup that adds the
# Blackbox threat-graph layer: it wires up the plugin, installs the OriginTrail
# DKG node CLI, bootstraps a mainnet node, enables the plugin, and writes
# sensible config defaults — so onboarding is one command and dead simple.
#
# Usage:
#   curl -fsSL blackbox.umanitek.ai | bash
#   # or, from a clone:
#   ./scripts/blackbox-install.sh [--help]
#
# Idempotent: safe to re-run. If the DKG node or initial threat-graph sync
# cannot complete, the installer exits non-zero and prints clear next steps
# instead of claiming Blackbox is fully ready with an empty ruleset.
# ============================================================================

set -euo pipefail

# ── Configuration (override via env) ────────────────────────────────────────
REPO_URL="${BLACKBOX_REPO_URL:-https://github.com/umanitek/agent-blackbox.git}"
REPO_BRANCH="${BLACKBOX_REPO_BRANCH:-main}"
HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
# Keep the managed npm DKG package and node state inside the Agent Blackbox
# checkout. For a local script this is the current repository; for curl | bash
# the default is ./agent-blackbox beneath the directory where the user invoked
# the installer. BLACKBOX_INSTALL_DIR remains the explicit override.
if [ -n "${BLACKBOX_INSTALL_DIR:-}" ]; then
    BLACKBOX_INSTALL_ROOT="$BLACKBOX_INSTALL_DIR"
elif [ -f "$PWD/pyproject.toml" ] && [ -d "$PWD/plugins/blackbox" ]; then
    BLACKBOX_INSTALL_ROOT="$PWD"
else
    BLACKBOX_INSTALL_ROOT="$PWD/agent-blackbox"
fi
BLACKBOX_INSTALL_SCRIPT="${BASH_SOURCE[0]:-}"
if [ -n "$BLACKBOX_INSTALL_SCRIPT" ] && [ -f "$BLACKBOX_INSTALL_SCRIPT" ]; then
    _blackbox_script_root="$(cd "$(dirname "$BLACKBOX_INSTALL_SCRIPT")/.." && pwd)"
    if [ -f "$_blackbox_script_root/pyproject.toml" ] &&
        [ -d "$_blackbox_script_root/plugins/blackbox" ]; then
        BLACKBOX_INSTALL_ROOT="$_blackbox_script_root"
    fi
    unset _blackbox_script_root
fi
DKG_NETWORK="${BLACKBOX_DKG_NETWORK:-mainnet-base}"   # a valid dkg mainnet (mainnet-base | mainnet-gnosis). Base uses ETH for gas. No testnet.
BLACKBOX_HOME="${BLACKBOX_HOME:-$HERMES_HOME/blackbox}"
BLACKBOX_DKG_PORT_EXPLICIT=false
[ -n "${BLACKBOX_DKG_PORT+x}" ] && BLACKBOX_DKG_PORT_EXPLICIT=true
BLACKBOX_DKG_STORE_URL_EXPLICIT=false
[ -n "${BLACKBOX_DKG_STORE_URL+x}" ] && BLACKBOX_DKG_STORE_URL_EXPLICIT=true
BLACKBOX_DKG_PORT="${BLACKBOX_DKG_PORT:-9320}"
BLACKBOX_DKG_STORE_PORT="${BLACKBOX_DKG_STORE_PORT:-9999}"
BLACKBOX_DKG_STORE_URL="${BLACKBOX_DKG_STORE_URL:-}"
BLACKBOX_DKG_STORE_MANAGED_BY_DKG=false
BLACKBOX_DKG_STORE_NAMESPACE="agent-blackbox"
BLACKBOX_DKG_STORE_BACKEND="auto"
BLACKBOX_DKG_SELECTED_STORE_BACKEND=""
BLACKBOX_DOCKER_REQUIRED=false
BLACKBOX_DKG_ACCEPT_STORE_RESET=false
BLACKBOX_DKG_HOME="$BLACKBOX_INSTALL_ROOT/.dkg"
BLACKBOX_DKG_CLI_DIR="$BLACKBOX_INSTALL_ROOT/dkg"
BLACKBOX_DKG_BIN="$BLACKBOX_DKG_CLI_DIR/node_modules/.bin/dkg"
BLACKBOX_DKG_PACKAGE="${BLACKBOX_DKG_PACKAGE:-@origintrail-official/dkg@latest}"
BLACKBOX_DKG_DAEMON_URL="http://127.0.0.1:$BLACKBOX_DKG_PORT"
BLACKBOX_DKG_STORE_QUEUE_LIMIT="${BLACKBOX_DKG_STORE_QUEUE_LIMIT:-512}"
BLACKBOX_DKG_LIST_CONTEXT_GRAPHS_PROJECTION="${BLACKBOX_DKG_LIST_CONTEXT_GRAPHS_PROJECTION:-1}"
BLACKBOX_DKG_SYNC_GLOBAL_MAX_INFLIGHT="1"
BLACKBOX_DKG_SYNC_GLOBAL_QUEUE_LIMIT="0"
BLACKBOX_DKG_DURABLE_SYNC_ENABLED="${BLACKBOX_DKG_DURABLE_SYNC_ENABLED:-1}"
BLACKBOX_DKG_CATCHUP_MAX_CONCURRENT_PEERS="1"
BLACKBOX_DKG_STORE_QUEUE_WAIT_TIMEOUT_MS="300000"
BLACKBOX_DKG_NODE_OPTIONS=""
NODE_MAJOR="${BLACKBOX_NODE_MAJOR:-22}"
BLACKBOX_CONTEXT_GRAPH_ID="${BLACKBOX_CONTEXT_GRAPH_ID:-0x37b1Fdfd134e2b17583bCBdD3034F91504cD9C70/agent-blackbox-vm}"
BLACKBOX_GRAPH_PEER_ID="${BLACKBOX_GRAPH_PEER_ID:-12D3KooWBJskzr2unXQG9mR3LRZFUJoxWr1PN6hTbyWyKndHXjZM}"
BLACKBOX_DKG_CATCHUP_TIMEOUT="${BLACKBOX_DKG_CATCHUP_TIMEOUT:-3600}"
BLACKBOX_LLM_PROVIDER="${BLACKBOX_LLM_PROVIDER:-}"
BLACKBOX_LLM_MODEL="${BLACKBOX_LLM_MODEL:-}"
BLACKBOX_LLM_KEY_SOURCE="${BLACKBOX_LLM_KEY_SOURCE:-}"
BLACKBOX_LLM_API_KEY="${BLACKBOX_LLM_API_KEY:-}"
BLACKBOX_HERMES_SETUP="${BLACKBOX_HERMES_SETUP:-reuse}" # reuse | always | never
BLACKBOX_AUTO_DASHBOARD="${BLACKBOX_AUTO_DASHBOARD:-1}"
BLACKBOX_SYNC_MODE="${BLACKBOX_SYNC_MODE:-wait}" # retained for compatibility; sync is controlled
BLACKBOX_INSTALL_INCOMPLETE=false
BLACKBOX_THREAT_GRAPH_INCOMPLETE=false
BLACKBOX_PARTIAL_RULESET_READY=false
BLACKBOX_SYNC_PENDING=false
BLACKBOX_SYNC_LOG=""
BLACKBOX_DETACHED_PID=""
BLACKBOX_DKG_ALREADY_RUNNING=false
BLACKBOX_DKG_FRESH_STATE=false
BLACKBOX_DKG_FOREIGN_ENDPOINT=false
BLACKBOX_DKG_RESTART_REQUIRED=false
BLACKBOX_DKG_RUNTIME_MARKER="$BLACKBOX_DKG_HOME/.blackbox-runtime.sha256"
BLACKBOX_DKG_NODE_PATH_MARKER="$BLACKBOX_DKG_HOME/.blackbox-node-path"
BLACKBOX_DKG_STORE_RESET_MARKER="$BLACKBOX_DKG_HOME/.blackbox-store-reset-pending"
BLACKBOX_DKG_RUNTIME_FINGERPRINT=""
HERMES_API_KEY_VARS='OPENAI_API_KEY|ANTHROPIC_API_KEY|OPENROUTER_API_KEY|NOUS_API_KEY|ZAI_API_KEY|KIMI_API_KEY|KIMI_CN_API_KEY|MINIMAX_API_KEY|MINIMAX_CN_API_KEY|GOOGLE_API_KEY|GEMINI_API_KEY|MISTRAL_API_KEY|GROQ_API_KEY|TOGETHER_API_KEY|XAI_API_KEY'
HERMES_API_KEY_RE="^[[:space:]]*(${HERMES_API_KEY_VARS})[[:space:]]*=[[:space:]]*[^[:space:]#]+"

# ── Colors / echo helpers (DRY) ─────────────────────────────────────────────
# ANSI-C ($'...') quoting stores REAL escape bytes, so the codes render both
# via `echo` and inside `cat <<EOF` heredocs (a plain '\033' string does not).
if [ -t 1 ]; then
    GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'; CYAN=$'\033[0;36m'
    RED=$'\033[0;31m'; MINT=$'\033[38;5;115m'; BOLD=$'\033[1m'; NC=$'\033[0m'
else
    GREEN=''; YELLOW=''; CYAN=''; RED=''; MINT=''; BOLD=''; NC=''
fi

step()    { echo "${CYAN}→${NC} $1"; }
ok()      { echo "${GREEN}✓${NC} $1"; }
warn()    { echo "${YELLOW}⚠${NC} $1"; }
err()     { echo "${RED}✗${NC} $1"; }
heading() { echo ""; echo "${MINT}${BOLD}$1${NC}"; }

run_detached() {
    local log_file="$1"
    shift
    local python_bin="${VENV_DIR:-}/bin/python"
    if [ -x "$python_bin" ]; then
        # macOS has no setsid(1). Python's start_new_session creates a real
        # session boundary, so an installer exiting non-zero cannot propagate a
        # terminal hangup to the dashboard it already reported as running.
        BLACKBOX_DETACHED_PID="$("$python_bin" -c '
import subprocess, sys
log = open(sys.argv[1], "ab", buffering=0)
proc = subprocess.Popen(
    sys.argv[2:],
    stdin=subprocess.DEVNULL,
    stdout=log,
    stderr=subprocess.STDOUT,
    start_new_session=True,
    close_fds=True,
)
print(proc.pid)
' "$log_file" "$@")"
    elif command -v setsid >/dev/null 2>&1; then
        nohup setsid "$@" </dev/null >"$log_file" 2>&1 &
        BLACKBOX_DETACHED_PID=$!
    else
        # macOS has no `setsid`.  Detach stdin as well as stdout/stderr and
        # remove the job from Bash's table; otherwise the installer shell can
        # propagate a hangup when it exits, killing a dashboard/sync child it
        # just reported as running.
        nohup "$@" </dev/null >"$log_file" 2>&1 &
        BLACKBOX_DETACHED_PID=$!
    fi
    disown "$BLACKBOX_DETACHED_PID" 2>/dev/null || true
}

detached_process_survived_startup() {
    local pid="${1:-}"
    local grace_seconds="${2:-2}"
    [ -n "$pid" ] || return 1
    sleep "$grace_seconds"
    kill -0 "$pid" 2>/dev/null
}

prepare_blackbox_dkg_process_environment() {
    local helper="$REPO_DIR/scripts/blackbox-dkg-runtime-fingerprint.py"
    local heap_mb
    if [ ! -f "$helper" ]; then
        warn "DKG runtime settings helper is missing: $helper"
        return 1
    fi
    if ! heap_mb="$("$VENV_DIR/bin/python" "$helper" heap 8192)" ||
        ! [[ "$heap_mb" =~ ^[1-9][0-9]*$ ]]; then
        warn "Could not resolve a safe Node.js heap limit for the DKG daemon."
        return 1
    fi
    if ! BLACKBOX_DKG_NODE_OPTIONS="$("$VENV_DIR/bin/python" "$helper" node-options "$heap_mb" "${NODE_OPTIONS:-}")"; then
        warn "Could not prepare Node.js options for the DKG daemon."
        return 1
    fi
    ok "DKG safety limits: one large sync at a time; V8 heap ${heap_mb}MB"
}

blackbox_dkg() {
    local node_bin_dir accept_store_reset=0
    node_bin_dir="$(dirname "$(command -v node)")"
    if [ "$BLACKBOX_DKG_ACCEPT_STORE_RESET" = true ] ||
        [ -f "$BLACKBOX_DKG_STORE_RESET_MARKER" ]; then
        accept_store_reset=1
    fi
    # Process-level guards intentionally wrap the DKG entrypoint, not a store
    # adapter, so Blazegraph and managed Oxigraph receive identical protection.
    PATH="$node_bin_dir:$PATH" \
    DKG_HOME="$BLACKBOX_DKG_HOME" \
    DKG_ACCEPT_STORE_RESET="$accept_store_reset" \
    DKG_STORE_QUEUE_LIMIT="$BLACKBOX_DKG_STORE_QUEUE_LIMIT" \
    DKG_LIST_CONTEXT_GRAPHS_PROJECTION="$BLACKBOX_DKG_LIST_CONTEXT_GRAPHS_PROJECTION" \
    DKG_SYNC_ON_CONNECT_ENABLED="1" \
    DKG_SYNC_RECONCILER_ENABLED="1" \
    DKG_DURABLE_SYNC_ENABLED="$BLACKBOX_DKG_DURABLE_SYNC_ENABLED" \
    DKG_SYNC_GLOBAL_MAX_INFLIGHT="$BLACKBOX_DKG_SYNC_GLOBAL_MAX_INFLIGHT" \
    DKG_SYNC_GLOBAL_QUEUE_LIMIT="$BLACKBOX_DKG_SYNC_GLOBAL_QUEUE_LIMIT" \
    DKG_CATCHUP_MAX_CONCURRENT_PEERS="$BLACKBOX_DKG_CATCHUP_MAX_CONCURRENT_PEERS" \
    DKG_STORE_QUEUE_WAIT_TIMEOUT_MS="$BLACKBOX_DKG_STORE_QUEUE_WAIT_TIMEOUT_MS" \
    DKG_SYNC_TOTAL_TIMEOUT_MS="1800000" \
    DKG_SWM_RECOVERY_TIMEOUT_MS="3600000" \
    NODE_OPTIONS="$BLACKBOX_DKG_NODE_OPTIONS" \
    "$BLACKBOX_DKG_BIN" "$@"
}

blackbox_has_dkg_state() {
    [ -f "$BLACKBOX_DKG_HOME/auth.token" ] || [ -f "$BLACKBOX_DKG_HOME/config.json" ]
}

prepare_blackbox_dkg_runtime_fingerprint() {
    local fingerprinter="$REPO_DIR/scripts/blackbox-dkg-runtime-fingerprint.py"
    local node_bin
    local applied=""
    if [ ! -f "$fingerprinter" ]; then
        BLACKBOX_INSTALL_INCOMPLETE=true
        BLACKBOX_THREAT_GRAPH_INCOMPLETE=true
        warn "DKG runtime fingerprint helper is missing; loaded npm runtime cannot be verified."
        return 1
    fi
    node_bin="$(command -v node)"
    if ! BLACKBOX_DKG_RUNTIME_FINGERPRINT="$("$VENV_DIR/bin/python" "$fingerprinter" compute \
        "$BLACKBOX_DKG_CLI_DIR" "$BLACKBOX_DKG_HOME" "$node_bin" "$BLACKBOX_DKG_BIN" \
        "$BLACKBOX_DKG_STORE_QUEUE_LIMIT" "$BLACKBOX_DKG_LIST_CONTEXT_GRAPHS_PROJECTION" \
        "$BLACKBOX_DKG_SYNC_GLOBAL_MAX_INFLIGHT" "$BLACKBOX_DKG_NODE_OPTIONS" \
        "$BLACKBOX_DKG_CATCHUP_MAX_CONCURRENT_PEERS" \
        "$BLACKBOX_DKG_STORE_QUEUE_WAIT_TIMEOUT_MS")"; then
        BLACKBOX_INSTALL_INCOMPLETE=true
        BLACKBOX_THREAT_GRAPH_INCOMPLETE=true
        warn "Could not fingerprint the configured DKG runtime; setup is incomplete."
        return 1
    fi
    if [ -f "$BLACKBOX_DKG_RUNTIME_MARKER" ]; then
        applied="$(tr -d '\r\n' <"$BLACKBOX_DKG_RUNTIME_MARKER")"
    fi
    if [ "$applied" != "$BLACKBOX_DKG_RUNTIME_FINGERPRINT" ]; then
        BLACKBOX_DKG_RESTART_REQUIRED=true
    fi
}

record_blackbox_dkg_runtime_fingerprint() {
    local fingerprinter="$REPO_DIR/scripts/blackbox-dkg-runtime-fingerprint.py"
    if [ -z "$BLACKBOX_DKG_RUNTIME_FINGERPRINT" ] ||
        ! "$VENV_DIR/bin/python" "$fingerprinter" record \
            "$BLACKBOX_DKG_RUNTIME_MARKER" "$BLACKBOX_DKG_RUNTIME_FINGERPRINT"; then
        BLACKBOX_INSTALL_INCOMPLETE=true
        BLACKBOX_THREAT_GRAPH_INCOMPLETE=true
        warn "DKG restarted, but its applied runtime fingerprint could not be recorded."
        return 1
    fi
    printf '%s\n' "$(command -v node)" >"$BLACKBOX_DKG_NODE_PATH_MARKER"
    return 0
}

wait_for_blackbox_dkg_runtime() {
    local verifier="$REPO_DIR/scripts/blackbox-dkg-runtime-fingerprint.py"
    local expected_commit
    if ! expected_commit="$("$VENV_DIR/bin/python" "$verifier" commit \
        "$BLACKBOX_DKG_CLI_DIR")"; then
        BLACKBOX_INSTALL_INCOMPLETE=true
        BLACKBOX_THREAT_GRAPH_INCOMPLETE=true
        warn "Could not resolve the published DKG build commit."
        return 1
    fi
    if ! "$VENV_DIR/bin/python" "$verifier" wait \
        "$BLACKBOX_DKG_DAEMON_URL" "$expected_commit" 90 >/dev/null; then
        BLACKBOX_INSTALL_INCOMPLETE=true
        BLACKBOX_THREAT_GRAPH_INCOMPLETE=true
        warn "The DKG daemon did not activate npm build ${expected_commit:0:12}."
        return 1
    fi
    ok "DKG daemon is ready on npm build ${expected_commit:0:12}"
}

migrate_legacy_blackbox_dkg_home() {
    local legacy_home="$HOME/.hermes/blackbox/dkg"
    local legacy_bin="$HOME/.hermes/blackbox/dkg-cli/node_modules/.bin/dkg"
    local legacy_pid=""
    [ "$(cd "$(dirname "$BLACKBOX_DKG_HOME")" 2>/dev/null && pwd -P)/$(basename "$BLACKBOX_DKG_HOME")" != \
        "$(cd "$(dirname "$legacy_home")" 2>/dev/null && pwd -P)/$(basename "$legacy_home")" ] || return 0
    [ -f "$legacy_home/config.json" ] || return 0

    [ -f "$legacy_home/daemon.pid" ] && legacy_pid="$(tr -dc '0-9' <"$legacy_home/daemon.pid")"
    if [ -n "$legacy_pid" ] && kill -0 "$legacy_pid" 2>/dev/null; then
        if [ ! -x "$legacy_bin" ]; then
            BLACKBOX_INSTALL_INCOMPLETE=true
            BLACKBOX_THREAT_GRAPH_INCOMPLETE=true
            warn "The deprecated Blackbox DKG is running, but its stop command is missing: $legacy_bin"
            return 1
        fi
        step "Stopping the deprecated Blackbox DKG at $legacy_home ..."
        if ! DKG_HOME="$legacy_home" "$legacy_bin" stop; then
            BLACKBOX_INSTALL_INCOMPLETE=true
            BLACKBOX_THREAT_GRAPH_INCOMPLETE=true
            warn "Could not stop the deprecated Blackbox DKG safely."
            return 1
        fi
        if kill -0 "$legacy_pid" 2>/dev/null; then
            BLACKBOX_INSTALL_INCOMPLETE=true
            BLACKBOX_THREAT_GRAPH_INCOMPLETE=true
            warn "The deprecated Blackbox DKG did not stop; its state was not moved."
            return 1
        fi
    fi

    if [ ! -e "$BLACKBOX_DKG_HOME" ]; then
        mkdir -p "$(dirname "$BLACKBOX_DKG_HOME")"
        mv "$legacy_home" "$BLACKBOX_DKG_HOME"
        ok "Migrated the Blackbox DKG identity and graph state into this checkout"
    else
        warn "Deprecated DKG state remains at $legacy_home (stopped); current state is $BLACKBOX_DKG_HOME."
    fi
}

port_in_use() {
    "$VENV_DIR/bin/python" - "$1" <<'PYEOF'
import socket
import sys

port = int(sys.argv[1])
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(0.5)
try:
    raise SystemExit(0 if sock.connect_ex(("127.0.0.1", port)) == 0 else 1)
finally:
    sock.close()
PYEOF
}

set_blackbox_dkg_port() {
    BLACKBOX_DKG_PORT="$1"
    BLACKBOX_DKG_DAEMON_URL="http://127.0.0.1:$BLACKBOX_DKG_PORT"
}

choose_blackbox_dkg_port() {
    local start="$BLACKBOX_DKG_PORT"
    local candidate
    for candidate in $(seq "$start" 9399); do
        if ! port_in_use "$candidate"; then
            set_blackbox_dkg_port "$candidate"
            ok "Using Blackbox DKG port $BLACKBOX_DKG_PORT"
            return 0
        fi
    done
    return 1
}

check_blackbox_dkg_port() {
    local port="$BLACKBOX_DKG_PORT"
    local url="$BLACKBOX_DKG_DAEMON_URL"
    if command -v curl >/dev/null 2>&1 && curl -fsS "$url/api/status" >/dev/null 2>&1; then
        if blackbox_has_dkg_state; then
            ok "Blackbox DKG endpoint already responds at $url"
            BLACKBOX_DKG_ALREADY_RUNNING=true
            return 0
        fi
        warn "Port $port already has a DKG endpoint, but $BLACKBOX_DKG_HOME has no Blackbox node state."
        BLACKBOX_DKG_FOREIGN_ENDPOINT=true
        if [ "$BLACKBOX_DKG_PORT_EXPLICIT" = true ]; then
            BLACKBOX_INSTALL_INCOMPLETE=true
            BLACKBOX_THREAT_GRAPH_INCOMPLETE=true
            step "Set BLACKBOX_DKG_PORT to a free port or stop the process on $url."
            return 1
        fi
        step "Choosing a different Blackbox-owned port so the existing DKG node is untouched."
        choose_blackbox_dkg_port || {
            BLACKBOX_INSTALL_INCOMPLETE=true
            BLACKBOX_THREAT_GRAPH_INCOMPLETE=true
            warn "Could not find a free Blackbox DKG port in 9320-9399."
            return 1
        }
        return 0
    fi
    if port_in_use "$port"; then
        warn "Port $port is already in use, but it did not answer as a DKG node at $url."
        if [ "$BLACKBOX_DKG_PORT_EXPLICIT" = true ]; then
            BLACKBOX_INSTALL_INCOMPLETE=true
            BLACKBOX_THREAT_GRAPH_INCOMPLETE=true
            step "Set BLACKBOX_DKG_PORT to a free port and re-run the installer."
            return 1
        fi
        step "Choosing a different Blackbox-owned port."
        choose_blackbox_dkg_port || {
            BLACKBOX_INSTALL_INCOMPLETE=true
            BLACKBOX_THREAT_GRAPH_INCOMPLETE=true
            warn "Could not find a free Blackbox DKG port in 9320-9399."
            return 1
        }
    fi
    return 0
}

docker_setup_hint() {
    heading "Docker is required for the Blazegraph store"
    case "$OS" in
        macos)
            err "Docker Desktop is not installed or its engine is not running."
            step "Install and start it, wait for Docker to report Ready, then re-run Blackbox:"
            echo ""
            echo "    brew install --cask docker && open -a Docker"
            echo ""
            step "Docker's official guide: https://docs.docker.com/desktop/setup/install/mac-install/"
            ;;
        linux)
            err "Docker Engine is not installed, running, or accessible to this user."
            step "Install and start it, then log out/in once so the docker group applies:"
            echo ""
            echo '    curl -fsSL https://get.docker.com | sudo sh && sudo systemctl enable --now docker && sudo usermod -aG docker "$USER"'
            echo ""
            step "Docker's official guide: https://docs.docker.com/engine/install/"
            ;;
    esac
    step "Verify Docker before retrying: docker info"
}

require_docker_for_blazegraph() {
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        ok "Docker engine is ready for Blazegraph"
        return 0
    fi
    if [ "$OS" = "macos" ] && command -v docker >/dev/null 2>&1 &&
        [ -d "/Applications/Docker.app" -o -d "$HOME/Applications/Docker.app" ]; then
        step "Docker Desktop is installed but stopped; starting it now ..."
        open -gja Docker >/dev/null 2>&1 || true
        local waited=0
        while [ "$waited" -lt 120 ]; do
            if docker info >/dev/null 2>&1; then
                ok "Docker Desktop is ready for Blazegraph"
                return 0
            fi
            sleep 5
            waited=$((waited + 5))
            if [ $((waited % 15)) -eq 0 ]; then
                step "Waiting for Docker Desktop (${waited}s) ..."
            fi
        done
        warn "Docker Desktop did not become ready within 120 seconds."
    fi
    if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
        BLACKBOX_DOCKER_REQUIRED=true
        docker_setup_hint
        return 1
    fi
    ok "Docker engine is ready for Blazegraph"
}

use_blackbox_oxigraph() {
    BLACKBOX_DOCKER_REQUIRED=false
    BLACKBOX_DKG_SELECTED_STORE_BACKEND="oxigraph-server"
    BLACKBOX_DKG_STORE_URL=""
    BLACKBOX_DKG_STORE_MANAGED_BY_DKG=false
    warn "Using the DKG-managed Oxigraph store (no Docker container required)."
}

confirm_oxigraph_fallback() {
    local reason="$1"
    local answer=""
    warn "$reason"
    step "Recommended default: stop here, install/start or repair Docker, then re-run Blackbox with Blazegraph."
    step "Alternative: type y to continue now with the DKG-managed Oxigraph store."
    # /dev/tty can exist and pass -r/-w while the piped `curl | bash`
    # process has no controlling terminal. Probe by opening it once and keep
    # that descriptor for both prompt and response so no shell-level
    # "Device not configured" errors leak into the install.
    if ! { exec 9<>/dev/tty; } 2>/dev/null; then
        warn "No interactive terminal is available, so Oxigraph was not selected."
        step "To choose it explicitly, re-run the installer with: --store oxigraph"
        return 1
    fi
    printf "Continue with Oxigraph instead? [y/N] " >&9
    IFS= read -r answer <&9 || answer=""
    exec 9>&-
    case "$answer" in
        y|Y|yes|YES|Yes) return 0 ;;
        *)
            step "Keeping Blazegraph as the default. Set up Docker and re-run the installer."
            return 1
            ;;
    esac
}

blackbox_store_description() {
    case "$BLACKBOX_DKG_SELECTED_STORE_BACKEND" in
        oxigraph-server) echo "Oxigraph (DKG-managed local server)" ;;
        blazegraph) echo "Blazegraph at $BLACKBOX_DKG_STORE_URL" ;;
        *) echo "${BLACKBOX_DKG_STORE_URL:-not configured}" ;;
    esac
}

provision_blackbox_store() {
    local helper="$REPO_DIR/scripts/blackbox-blazegraph.mjs"
    local existing_state namespace existing_backend existing_url existing_managed
    local provisioned parsed

    existing_state="$($VENV_DIR/bin/python - "$BLACKBOX_DKG_HOME" <<'PYEOF'
import json
import sys
from pathlib import Path

cfg = Path(sys.argv[1]).expanduser() / "config.json"
try:
    data = json.loads(cfg.read_text(encoding="utf-8"))
except Exception:
    data = {}
store = data.get("store") if isinstance(data.get("store"), dict) else {}
options = store.get("options") if isinstance(store.get("options"), dict) else {}
print(data.get("name") or "agent-blackbox")
print(store.get("backend") or "")
print(options.get("url") or "")
print("true" if options.get("managedByDkg") is True else "false")
PYEOF
    )"
    namespace="$(printf '%s\n' "$existing_state" | sed -n '1p')"
    BLACKBOX_DKG_STORE_NAMESPACE="$namespace"
    existing_backend="$(printf '%s\n' "$existing_state" | sed -n '2p')"
    existing_url="$(printf '%s\n' "$existing_state" | sed -n '3p')"
    existing_managed="$(printf '%s\n' "$existing_state" | sed -n '4p')"

    if [ "$BLACKBOX_DKG_STORE_BACKEND" = "oxigraph" ]; then
        use_blackbox_oxigraph
        return 0
    fi
    if [ "$BLACKBOX_DKG_STORE_URL_EXPLICIT" = true ]; then
        BLACKBOX_DKG_SELECTED_STORE_BACKEND="blazegraph"
        BLACKBOX_DKG_STORE_MANAGED_BY_DKG=false
        step "Using operator-managed Blazegraph at $BLACKBOX_DKG_STORE_URL"
        check_blackbox_blazegraph
        return
    fi
    if [ "$BLACKBOX_DKG_STORE_BACKEND" = "auto" ] &&
        [ "$existing_backend" = "oxigraph-server" ]; then
        step "Preserving the existing DKG-managed Oxigraph store."
        use_blackbox_oxigraph
        return 0
    fi
    if [ "$existing_backend" = "blazegraph" ] &&
        [ "$existing_managed" != true ] && [ -n "$existing_url" ]; then
        BLACKBOX_DKG_SELECTED_STORE_BACKEND="blazegraph"
        BLACKBOX_DKG_STORE_URL="$existing_url"
        BLACKBOX_DKG_STORE_MANAGED_BY_DKG=false
        step "Reusing operator-managed Blazegraph at $BLACKBOX_DKG_STORE_URL"
        check_blackbox_blazegraph
        return
    fi
    if [ "$existing_backend" = "blazegraph" ] &&
        [ "$existing_managed" = true ] && [ -n "$existing_url" ]; then
        BLACKBOX_DKG_SELECTED_STORE_BACKEND="blazegraph"
        BLACKBOX_DKG_STORE_URL="$existing_url"
        BLACKBOX_DKG_STORE_MANAGED_BY_DKG=true
        if check_blackbox_blazegraph; then
            return 0
        fi
        if [ "$BLACKBOX_DKG_ALREADY_RUNNING" = true ]; then
            step "Pausing DKG so its overloaded store can pass recovery checks ..."
            if blackbox_dkg stop; then
                BLACKBOX_DKG_ALREADY_RUNNING=false
                if check_blackbox_blazegraph; then
                    return 0
                fi
                local managed_container="dkg-blazegraph-$namespace"
                local store_restarted=false
                step "Restarting the unresponsive managed Blazegraph container ..."
                if docker restart "$managed_container" >/dev/null 2>&1; then
                    store_restarted=true
                else
                    # A wedged JVM can make Docker's graceful restart return
                    # non-zero after it has nevertheless stopped the container.
                    # Starting that same container preserves its named volume
                    # and is safer than falling through to reprovisioning.
                    if [ "$(docker inspect -f '{{.State.Running}}' "$managed_container" 2>/dev/null)" = false ] &&
                        docker start "$managed_container" >/dev/null 2>&1; then
                        store_restarted=true
                    else
                        warn "Could not restart managed container $managed_container."
                    fi
                fi
                if [ "$store_restarted" = true ] && check_blackbox_blazegraph; then
                    return 0
                fi
            else
                warn "Could not pause the Blackbox DKG daemon before store recovery."
            fi
        fi
        warn "The managed Blazegraph endpoint is down; attempting Docker recovery."
    fi
    if ! require_docker_for_blazegraph; then
        if [ "$BLACKBOX_DKG_STORE_BACKEND" = "auto" ] &&
            confirm_oxigraph_fallback "Blazegraph cannot be installed because Docker is unavailable."; then
            use_blackbox_oxigraph
            return 0
        fi
        return 2
    fi
    if [ ! -f "$helper" ]; then
        warn "Blazegraph provisioner helper is missing: $helper"
        if [ "$BLACKBOX_DKG_STORE_BACKEND" = "auto" ] &&
            confirm_oxigraph_fallback "Blazegraph provisioning cannot continue without its helper."; then
            use_blackbox_oxigraph
            return 0
        fi
        return 1
    fi

    step "Provisioning Blazegraph through the DKG Docker provisioner ..."
    if ! provisioned="$(node "$helper" "$BLACKBOX_DKG_CLI_DIR" "$namespace" "$BLACKBOX_DKG_STORE_PORT")"; then
        if [ "$BLACKBOX_DKG_STORE_BACKEND" = "auto" ] &&
            confirm_oxigraph_fallback "Blazegraph provisioning failed even though Docker is available."; then
            use_blackbox_oxigraph
            return 0
        fi
        warn "Could not provision Blazegraph."
        return 1
    fi
    parsed="$($VENV_DIR/bin/python - "$provisioned" <<'PYEOF'
import json
import sys

result = json.loads(sys.argv[1])
print(f'{result["url"]}|{int(result["port"])}')
PYEOF
    )"
    IFS='|' read -r BLACKBOX_DKG_STORE_URL BLACKBOX_DKG_STORE_PORT <<< "$parsed"
    BLACKBOX_DKG_SELECTED_STORE_BACKEND="blazegraph"
    BLACKBOX_DKG_STORE_MANAGED_BY_DKG=true
    if check_blackbox_blazegraph; then
        return 0
    fi
    if [ "$BLACKBOX_DKG_STORE_BACKEND" = "auto" ] &&
        confirm_oxigraph_fallback "Blazegraph did not pass its SPARQL health check."; then
        use_blackbox_oxigraph
        return 0
    fi
    return 1
}

check_blackbox_blazegraph() {
    local helper="$REPO_DIR/scripts/blackbox-blazegraph.mjs"
    local result
    step "Checking the Blazegraph SPARQL endpoint ..."
    if ! result="$(node "$helper" check "$BLACKBOX_DKG_CLI_DIR" "$BLACKBOX_DKG_STORE_URL")"; then
        err "Blazegraph is unavailable or returned an error at $BLACKBOX_DKG_STORE_URL."
        return 1
    fi
    ok "Blazegraph SPARQL endpoint is healthy at $BLACKBOX_DKG_STORE_URL"
}

reset_fresh_managed_blazegraph() {
    [ "$BLACKBOX_DKG_FRESH_STATE" = true ] || return 0
    [ "$BLACKBOX_DKG_SELECTED_STORE_BACKEND" = blazegraph ] || return 0
    [ "$BLACKBOX_DKG_STORE_MANAGED_BY_DKG" = true ] || return 0
    [ "$BLACKBOX_DKG_STORE_URL_EXPLICIT" = false ] || return 0
    if [ "$BLACKBOX_DKG_FOREIGN_ENDPOINT" = true ]; then
        err "Refusing to reset the Blackbox namespace while an unrelated DKG endpoint is running."
        step "Stop that DKG node or set BLACKBOX_DKG_STORE_URL to an operator-managed store."
        return 1
    fi
    local helper="$REPO_DIR/scripts/blackbox-blazegraph.mjs"
    step "Clearing the installer-managed Blazegraph namespace for the fresh DKG identity ..."
    if ! node "$helper" reset "$BLACKBOX_DKG_CLI_DIR" \
        "$BLACKBOX_DKG_STORE_URL" "$BLACKBOX_DKG_STORE_NAMESPACE" >/dev/null; then
        err "Could not clear the stale installer-managed Blackbox namespace."
        return 1
    fi
    ok "Fresh Blackbox store is empty and ready for the new DKG identity"
}

ensure_blackbox_dkg_config() {
    local config_state
    config_state="$("$VENV_DIR/bin/python" - "$BLACKBOX_DKG_HOME" "$BLACKBOX_DKG_PORT" "$BLACKBOX_DKG_SELECTED_STORE_BACKEND" "$BLACKBOX_DKG_STORE_URL" "$BLACKBOX_DKG_STORE_MANAGED_BY_DKG" "$BLACKBOX_CONTEXT_GRAPH_ID" <<'PYEOF'
import json
import os
import secrets
import shutil
import sys
from pathlib import Path

home = Path(sys.argv[1]).expanduser()
api_port = int(sys.argv[2])
store_backend = sys.argv[3]
store_url = sys.argv[4]
store_managed = sys.argv[5].lower() == "true"
context_graph_id = sys.argv[6]
home.mkdir(parents=True, exist_ok=True)
cfg_path = home / "config.json"
original = None
if cfg_path.exists():
    try:
        original = cfg_path.read_text(encoding="utf-8")
        data = json.loads(original)
    except Exception:
        data = {}
else:
    data = {}

data.setdefault("name", "agent-blackbox")
data["apiPort"] = api_port
data.setdefault("listenPort", 0)
data["nodeRole"] = "edge"
data["networkConfig"] = "mainnet-base"
# Relay reachability: an edge node behind NAT must hold circuit-relay
# reservations so other members can dial it (and so it can dial them). DKG
# only builds its relay set from `relayPeers`; with that empty, the network-
# isolation gate denies EVERY relayed connection and the node holds 0
# reservations. Include the mainnet-base core relays so every install is reachable.
MAINNET_BASE_RELAYS = [
    "/ip4/178.104.98.10/tcp/9090/p2p/12D3KooWFWm8sg6dkitmdBd5Uxaqp3CDRL27mFcM7vEHK92Xapyy",
    "/ip4/168.119.127.54/tcp/9090/p2p/12D3KooWMasqzRrim48ZJM64UyTfHufDTmSG3n3jqwsS5phz8m91",
    "/ip4/178.156.237.133/tcp/9090/p2p/12D3KooWDgTunUpkGaE7dYCaDP1CCBT6Dm2HPMXSZhJn2KXYLH15",
    "/ip4/178.105.211.42/tcp/9090/p2p/12D3KooWCodgXHMwybaEe93rbKgWMfGXQvUb6cpT3VCrjCbbnyEu",
]
existing_relays = data.get("relayPeers") if isinstance(data.get("relayPeers"), list) else []
merged_relays = list(dict.fromkeys([*existing_relays, *MAINNET_BASE_RELAYS]))
data["relayPeers"] = merged_relays
data["relayReservationCount"] = int(data.get("relayReservationCount") or 4)
# DKG owns restart-safe continuation of the persisted Blackbox subscription.
# The one-inflight/zero-queue limits below prevent sync fan-out from starving
# Blazegraph while still allowing the reconciler to resume bounded manifests.
data["syncOnConnectEnabled"] = True
data["syncReconcilerEnabled"] = True
data["durableSyncEnabled"] = True
data.pop("syncAgentsMeta", None)
data["syncGlobalMaxInflight"] = 1
data["syncGlobalQueueLimit"] = 0
data.pop("restrictAutoSubscribeContextGraphs", None)
data["syncSharedMemoryOnConnect"] = False
priorities = data.get("syncContextGraphPriorities")
if not isinstance(priorities, dict):
    priorities = {}
priorities.update({context_graph_id: 100, "agents": -100, "ontology": -100})
data["syncContextGraphPriorities"] = priorities
data.setdefault("autoUpdate", {"enabled": False})
data["chain"] = {
    "type": "evm",
    "rpcUrl": "https://mainnet.base.org",
    "rpcUrls": ["https://base-rpc.publicnode.com", "https://base.drpc.org"],
    "hubAddress": "0x99Aa571fD5e681c2D27ee08A7b7989DB02541d13",
    "chainId": "base:8453",
}
auth = data.get("auth") if isinstance(data.get("auth"), dict) else {}
data["auth"] = {**auth, "enabled": True}
store = data.get("store") if isinstance(data.get("store"), dict) else {}
previous_backend = store.get("backend")
switched = bool(previous_backend and previous_backend != store_backend)
if switched and original is not None:
    backup_path = home / f"config.json.pre-{store_backend}"
    if not backup_path.exists():
        shutil.copy2(cfg_path, backup_path)
    (home / ".blackbox-store-reset-pending").write_text(store_backend + "\n", encoding="utf-8")
if store_backend == "blazegraph":
    data["store"] = {
        "backend": "blazegraph",
        "options": {"url": store_url, "managedByDkg": store_managed, "timeout": 900000},
    }
elif store_backend == "oxigraph-server":
    previous_options = store.get("options") if previous_backend == store_backend else None
    data["store"] = {"backend": "oxigraph-server"}
    if isinstance(previous_options, dict) and previous_options:
        data["store"]["options"] = previous_options
else:
    raise SystemExit(f"unsupported store backend: {store_backend}")
rendered = json.dumps(data, indent=2) + "\n"
changed = rendered != original
if changed:
    cfg_path.write_text(rendered, encoding="utf-8")

token_path = home / "auth.token"
if not token_path.exists():
    token_path.write_text(
        "# DKG node API token - treat this like a password\n"
        + secrets.token_urlsafe(32)
        + "\n",
        encoding="utf-8",
    )
    os.chmod(token_path, 0o600)
    changed = True
print("switched" if switched else ("changed" if changed else "unchanged"))
PYEOF
    )"
    if [ "$config_state" = "switched" ]; then
        BLACKBOX_DKG_ACCEPT_STORE_RESET=true
        BLACKBOX_DKG_RESTART_REQUIRED=true
        warn "Switching DKG storage to $BLACKBOX_DKG_SELECTED_STORE_BACKEND; the previous store will not be deleted."
        step "Backup config: $BLACKBOX_DKG_HOME/config.json.pre-$BLACKBOX_DKG_SELECTED_STORE_BACKEND"
    elif [ "$config_state" = "changed" ]; then
        BLACKBOX_DKG_RESTART_REQUIRED=true
    fi
}

banner() {
    echo ""
    echo -e "${MINT}${BOLD}"
    echo "  Agent Blackbox installer"
    echo -e "${NC}"
}

usage() {
    cat <<EOF
Agent Blackbox installer

Usage: blackbox-install.sh [OPTIONS]

Options:
  --skip-dkg     Skip local DKG node setup; exits incomplete
  --store MODE   Store backend: auto, blazegraph, or oxigraph (default: auto; fallback asks first)
  -h, --help     Show this help

Environment overrides:
  BLACKBOX_REPO_URL, BLACKBOX_REPO_BRANCH, HERMES_HOME,
  BLACKBOX_NODE_MAJOR, BLACKBOX_INSTALL_DIR, BLACKBOX_CONTEXT_GRAPH_ID,
  BLACKBOX_DKG_PORT, BLACKBOX_DKG_STORE_PORT, BLACKBOX_DKG_STORE_URL,
  BLACKBOX_DKG_HOME, BLACKBOX_DKG_CLI_DIR,
  BLACKBOX_DKG_BIN, BLACKBOX_DKG_PACKAGE,
  BLACKBOX_DKG_DAEMON_URL, BLACKBOX_DKG_CATCHUP_TIMEOUT,
  BLACKBOX_DKG_STORE_QUEUE_LIMIT, BLACKBOX_DKG_LIST_CONTEXT_GRAPHS_PROJECTION,
  BLACKBOX_CONTEXT_GRAPH_ID, BLACKBOX_GRAPH_PEER_ID,
  BLACKBOX_LLM_PROVIDER,
  BLACKBOX_LLM_MODEL, BLACKBOX_LLM_KEY_SOURCE, BLACKBOX_LLM_API_KEY,
  BLACKBOX_HERMES_SETUP=reuse|always|never, BLACKBOX_AUTO_DASHBOARD=0|1,
  BLACKBOX_SYNC_MODE=background|wait

Installs Blackbox in audit mode. Hermes model/API setup reuses existing keys by
default and never opens the setup wizard unless BLACKBOX_HERMES_SETUP=always.
Threat-graph sync does not require a Nous subscription or model key. The LLM
reviewer can reuse existing config, use BLACKBOX_LLM_* env values, or prompt on
a real terminal. Blackbox uses its own DKG home and port by default:
  DKG home: $BLACKBOX_DKG_HOME
  DKG CLI:  $BLACKBOX_DKG_BIN
  DKG URL:  $BLACKBOX_DKG_DAEMON_URL
  Store:    auto (Blazegraph preferred; Oxigraph requires confirmation)
EOF
}

# ── Arg parsing ─────────────────────────────────────────────────────────────
SKIP_DKG=false
while [ $# -gt 0 ]; do
    case "$1" in
        --skip-dkg) SKIP_DKG=true; shift ;;
        --store)
            [ $# -ge 2 ] || { err "--store requires auto, blazegraph, or oxigraph"; exit 1; }
            BLACKBOX_DKG_STORE_BACKEND="$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')"
            case "$BLACKBOX_DKG_STORE_BACKEND" in
                auto|blazegraph|oxigraph) ;;
                *) err "Unsupported store backend: $2 (use auto, blazegraph, or oxigraph)"; exit 1 ;;
            esac
            shift 2
            ;;
        -h|--help)  usage; exit 0 ;;
        *) err "Unknown option: $1"; echo; usage; exit 1 ;;
    esac
done
if [ "$BLACKBOX_DKG_STORE_BACKEND" = "oxigraph" ] &&
    [ "$BLACKBOX_DKG_STORE_URL_EXPLICIT" = true ]; then
    err "BLACKBOX_DKG_STORE_URL cannot be combined with --store oxigraph."
    exit 1
fi

# ── Locate (or fetch) the repo ──────────────────────────────────────────────
# When run from a clone, use it in-place. When piped from curl, clone REPO_URL.
blackbox_repo_is_valid() {
    local repo="$1"
    [ -d "$repo/.git" ] &&
        git -C "$repo" rev-parse --verify HEAD >/dev/null 2>&1 &&
        [ -f "$repo/pyproject.toml" ] &&
        [ -d "$repo/plugins/blackbox" ]
}

move_broken_blackbox_repo_aside() {
    local repo="$1"
    local backup="${repo}.broken-$(date +%Y%m%d-%H%M%S)-$$"
    warn "Existing install at $repo is incomplete or not an Agent Blackbox checkout."
    mv -- "$repo" "$backup"
    step "Preserved it at $backup"
}

resolve_repo() {
    local script_src="${BASH_SOURCE[0]:-}"
    if [ -n "$script_src" ] && [ -f "$script_src" ]; then
        local d
        d="$(cd "$(dirname "$script_src")/.." && pwd)"
        if [ -f "$d/pyproject.toml" ] && [ -d "$d/plugins/blackbox" ]; then
            REPO_DIR="$d"
            step "Using existing checkout at $REPO_DIR"
            return 0
        fi
    fi
    # curl | bash path — clone fresh
    if ! command -v git >/dev/null 2>&1; then
        err "git is required to download Blackbox. Install git and re-run."
        exit 1
    fi
    REPO_DIR="$BLACKBOX_INSTALL_ROOT"
    if [ -e "$REPO_DIR" ] && ! blackbox_repo_is_valid "$REPO_DIR"; then
        move_broken_blackbox_repo_aside "$REPO_DIR"
    fi
    if blackbox_repo_is_valid "$REPO_DIR"; then
        step "Updating existing clone at $REPO_DIR"
        if ! git -C "$REPO_DIR" fetch --depth 1 origin "$REPO_BRANCH"; then
            err "Could not fetch $REPO_BRANCH from $REPO_URL."
            return 1
        fi
        if ! git -C "$REPO_DIR" checkout "$REPO_BRANCH"; then
            err "Could not check out $REPO_BRANCH in $REPO_DIR. Resolve local changes and re-run."
            return 1
        fi
        if ! git -C "$REPO_DIR" pull --ff-only origin "$REPO_BRANCH"; then
            err "Could not fast-forward $REPO_DIR to origin/$REPO_BRANCH."
            return 1
        fi
    else
        step "Cloning $REPO_URL → $REPO_DIR"
        git clone --depth 1 --branch "$REPO_BRANCH" "$REPO_URL" "$REPO_DIR"
    fi
    if ! blackbox_repo_is_valid "$REPO_DIR"; then
        err "$REPO_DIR is not a complete Agent Blackbox Python project."
        return 1
    fi
    ok "Repo ready at $REPO_DIR"
}

# ── Prerequisite checks (guidance, not silent failure) ──────────────────────
check_git() {
    if command -v git >/dev/null 2>&1 && git --version >/dev/null 2>&1; then
        ok "git $(git --version | awk '{print $3}')"
    else
        err "git not found."
        case "$OS" in
            macos) step "Install: xcode-select --install   (or: brew install git)" ;;
            linux) step "Install: sudo apt install git   (or your distro's package manager)" ;;
        esac
        exit 1
    fi
}

check_python() {
    # Accept 3.11–3.13. Prefer python3.11/3.12/3.13, then python3.
    PY=""
    for c in python3.13 python3.12 python3.11 python3; do
        command -v "$c" >/dev/null 2>&1 || continue
        if "$c" -c 'import sys; raise SystemExit(0 if (3,11)<=sys.version_info[:2]<=(3,13) else 1)' 2>/dev/null; then
            PY="$c"; break
        fi
    done
    if [ -n "$PY" ]; then
        ok "Python $($PY -V 2>&1 | awk '{print $2}') ($PY)"
    elif command -v uv >/dev/null 2>&1; then
        # No system 3.11–3.13 (e.g. the machine only has 3.14) — that's fine:
        # uv fetches a compatible interpreter when it builds the venv.
        warn "No system Python 3.11–3.13 found — uv will provide a compatible one."
        PY=""
    else
        err "Python 3.11–3.13 not found (and uv isn't installed)."
        case "$OS" in
            macos) step "Easiest fix: brew install uv   (or: brew install python@3.12)" ;;
            linux) step "Easiest fix: curl -LsSf https://astral.sh/uv/install.sh | sh   (or: apt install python3.12 python3.12-venv)" ;;
        esac
        exit 1
    fi
}

# Node ≥ NODE_MAJOR is needed for the DKG CLI. If it's missing we auto-install
# it (best-effort) so the DKG node bootstraps without a manual detour.
_node_ok() {
    command -v node >/dev/null 2>&1 || return 1
    local maj; maj="$(node -v 2>/dev/null | sed 's/^v//' | cut -d. -f1)"
    [ "${maj:-0}" -ge "$NODE_MAJOR" ] 2>/dev/null
}

ensure_node() {
    if _node_ok; then
        ok "Node.js $(node -v) + npm $(npm -v 2>/dev/null || echo '?')"
        HAS_NODE=true
        return 0
    fi
    if [ "$SKIP_DKG" = true ]; then
        HAS_NODE=false
        return 0
    fi
    warn "Node.js $NODE_MAJOR+ not found — installing it automatically (via nvm)…"
    # nvm is the portable path on both macOS and Linux and needs no sudo.
    export NVM_DIR="${NVM_DIR:-$HOME/.nvm}"
    if [ ! -s "$NVM_DIR/nvm.sh" ]; then
        step "Installing nvm into $NVM_DIR …"
        if ! curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash >/dev/null 2>&1; then
            warn "Could not install nvm automatically."
            _node_manual_hint
            HAS_NODE=false
            return 0
        fi
    fi
    # shellcheck disable=SC1091
    . "$NVM_DIR/nvm.sh"
    step "Installing Node $NODE_MAJOR (nvm install $NODE_MAJOR) …"
    if nvm install "$NODE_MAJOR" >/dev/null 2>&1 && nvm use "$NODE_MAJOR" >/dev/null 2>&1 && _node_ok; then
        ok "Node.js $(node -v) installed via nvm"
        HAS_NODE=true
    else
        warn "Automatic Node install did not complete."
        _node_manual_hint
        HAS_NODE=false
    fi
}

_node_manual_hint() {
    case "$OS" in
        macos) step "Install Node $NODE_MAJOR manually: brew install node@$NODE_MAJOR   (or: nvm install $NODE_MAJOR)" ;;
        linux) step "Install Node $NODE_MAJOR manually: nvm install $NODE_MAJOR   (https://github.com/nvm-sh/nvm)" ;;
    esac
    step "The Blackbox plugin still works; re-run this installer once Node is present to add the DKG node."
}

# ── OS / arch detection ─────────────────────────────────────────────────────
detect_os() {
    ARCH="$(uname -m)"
    case "$(uname -s)" in
        Darwin*) OS="macos" ;;
        Linux*)  OS="linux" ;;
        *) err "Unsupported OS: $(uname -s). Blackbox supports macOS and Linux (use blackbox-install.ps1 on Windows)."; exit 1 ;;
    esac
    ok "Detected $OS ($ARCH)"
}

# ── Python venv + editable install (reuse setup-hermes.sh when present) ──────
install_python_env() {
    heading "Installing Hermes + Blackbox (Python)"
    VENV_DIR="$REPO_DIR/venv"
    # Fast idempotent re-run: if a working hermes venv already exists, don't let
    # setup-hermes.sh (which `rm -rf venv`s on every run) rebuild it from scratch.
    if [ -x "$VENV_DIR/bin/hermes" ] && "$VENV_DIR/bin/python" -c "import hermes_cli" >/dev/null 2>&1; then
        ok "Existing Hermes environment detected — reusing it"
        ensure_web_extra
        HERMES_BIN="$VENV_DIR/bin/hermes"
        return 0
    fi
    if [ -x "$REPO_DIR/setup-hermes.sh" ] || [ -f "$REPO_DIR/setup-hermes.sh" ]; then
        step "Reusing $REPO_DIR/setup-hermes.sh for the base environment..."
        # The base installer normally prints standalone Hermes next steps and
        # asks about the setup wizard. Blackbox owns that flow below, so run it
        # in embedded mode and launch `hermes setup` ourselves only if needed.
        if HERMES_EMBEDDED_INSTALL=1 bash "$REPO_DIR/setup-hermes.sh"; then
            ok "Base environment ready via setup-hermes.sh"
        else
            warn "setup-hermes.sh did not complete cleanly — falling back to a minimal venv install."
            minimal_python_env
        fi
    else
        minimal_python_env
    fi
    ensure_web_extra
    HERMES_BIN="$VENV_DIR/bin/hermes"
}

# The dashboard needs fastapi/uvicorn (the `[web]` extra, already part of
# `[all]`). Verify by IMPORTING them — not by shelling pip, which a uv-built
# venv doesn't ship. Only install if genuinely missing, preferring `uv pip`.
ensure_web_extra() {
    step "Checking dashboard extras (fastapi/uvicorn) …"
    if "$VENV_DIR/bin/python" -c "import fastapi, uvicorn" >/dev/null 2>&1; then
        ok "Dashboard extras present"
        return 0
    fi
    step "Installing dashboard extras (.[web]) …"
    local installed=false
    if command -v uv >/dev/null 2>&1; then
        ( cd "$REPO_DIR" && VIRTUAL_ENV="$VENV_DIR" uv pip install -e ".[web]" >/dev/null 2>&1 ) && installed=true
    fi
    if [ "$installed" != true ]; then
        ( cd "$REPO_DIR" && "$VENV_DIR/bin/python" -m pip install -e ".[web]" >/dev/null 2>&1 ) && installed=true
    fi
    if [ "$installed" = true ] && "$VENV_DIR/bin/python" -c "import fastapi, uvicorn" >/dev/null 2>&1; then
        ok "Dashboard extras installed"
    else
        warn "Dashboard extras unavailable — 'blackbox dashboard' may not start. Retry: (cd $REPO_DIR && uv pip install -e '.[web]')"
    fi
}

minimal_python_env() {
    VENV_DIR="$REPO_DIR/venv"
    if [ ! -d "$VENV_DIR" ]; then
        if [ -n "$PY" ]; then
            step "Creating virtual environment ($PY) ..."
            "$PY" -m venv "$VENV_DIR"
        elif command -v uv >/dev/null 2>&1; then
            step "Creating virtual environment (uv fetches Python 3.12) ..."
            ( cd "$REPO_DIR" && uv venv --python 3.12 "$VENV_DIR" )
        else
            err "Need Python 3.11–3.13 or uv to build the environment."; exit 1
        fi
    else
        step "Reusing existing venv at $VENV_DIR"
    fi
    step "Installing Hermes + Agent Blackbox (web extras, editable) ..."
    # A uv-built venv ships no pip, so install with uv when it's available.
    if command -v uv >/dev/null 2>&1; then
        ( cd "$REPO_DIR" && VIRTUAL_ENV="$VENV_DIR" uv pip install -e ".[web]" )
    else
        "$VENV_DIR/bin/python" -m pip install --upgrade pip >/dev/null
        ( cd "$REPO_DIR" && "$VENV_DIR/bin/python" -m pip install -e ".[web]" )
    fi
    ok "Blackbox installed (editable, with dashboard extras)"
}

# ── hermes + blackbox commands on PATH (~/.local/bin) ────────────────────────
link_hermes() {
    local link_dir="$HOME/.local/bin"
    local blackbox_bin="$link_dir/blackbox"
    mkdir -p "$link_dir"
    if [ -x "$HERMES_BIN" ]; then
        ln -sf "$HERMES_BIN" "$link_dir/hermes"
        ok "Linked hermes → $link_dir/hermes"
        if { [ -e "$blackbox_bin" ] || [ -L "$blackbox_bin" ]; } &&
           ! grep -q 'managed-by: agent-blackbox-installer' "$blackbox_bin" 2>/dev/null; then
            warn "Not replacing existing command at $blackbox_bin; remove or rename it, then re-run the installer."
        else
            cat > "$blackbox_bin" <<'SH'
#!/bin/sh
# managed-by: agent-blackbox-installer
bin_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
exec "$bin_dir/hermes" blackbox "$@"
SH
            chmod 755 "$blackbox_bin"
            ok "Installed blackbox → hermes blackbox ($blackbox_bin)"
        fi
        case ":$PATH:" in
            *":$link_dir:"*) : ;;
            *) warn "Add $link_dir to your PATH for the hermes and blackbox commands:  export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
        esac
    fi
    # Prefer the venv binary for the rest of this run.
    export PATH="$VENV_DIR/bin:$link_dir:$PATH"
}

refresh_blackbox_plugin_copy() {
    heading "Installing Blackbox plugin copy"
    step "Refreshing $HERMES_HOME/plugins/blackbox from this checkout..."
    if "$VENV_DIR/bin/python" - "$REPO_DIR" "$HERMES_HOME" <<'PYEOF'
import os
import shutil
import sys
from pathlib import Path

repo = Path(sys.argv[1]).resolve()
home = Path(sys.argv[2]).expanduser()
src = repo / "plugins" / "blackbox"
dest = home / "plugins" / "blackbox"
openclaw_src = repo / "integrations" / "openclaw"
openclaw_dest = dest / "_openclaw"

if not src.is_dir():
    raise SystemExit(f"missing Blackbox plugin source: {src}")

def ignore_runtime(_dir, names):
    skip_dirs = {"__pycache__", "tests", ".pytest_cache", "node_modules"}
    return [n for n in names if n in skip_dirs or n.endswith((".pyc", ".pyo"))]

def ignore_openclaw(_dir, names):
    skip_dirs = {"node_modules", "dist", ".turbo", "test", "tests", "__pycache__"}
    return [n for n in names if n in skip_dirs or n.endswith((".pyc", ".log", ".tsbuildinfo"))]

home.joinpath("plugins").mkdir(parents=True, exist_ok=True)
if dest.exists():
    shutil.rmtree(dest)
shutil.copytree(src, dest, ignore=ignore_runtime)
if openclaw_src.is_dir():
    if openclaw_dest.exists():
        shutil.rmtree(openclaw_dest)
    shutil.copytree(openclaw_src, openclaw_dest, ignore=ignore_openclaw)
(dest / ".blackbox-source-root").write_text(str(repo), encoding="utf-8")
PYEOF
    then
        ok "Blackbox plugin copy refreshed"
    else
        BLACKBOX_INSTALL_INCOMPLETE=true
        warn "Could not refresh the Blackbox plugin copy. Commands may use stale plugin files."
    fi
}

hermes_env_has_api_key() {
    local path="$1"
    [ -f "$path" ] && grep -Eq "$HERMES_API_KEY_RE" "$path"
}

hermes_setup_needed() {
    local key
    for key in \
        OPENAI_API_KEY ANTHROPIC_API_KEY OPENROUTER_API_KEY NOUS_API_KEY \
        ZAI_API_KEY KIMI_API_KEY KIMI_CN_API_KEY MINIMAX_API_KEY \
        MINIMAX_CN_API_KEY GOOGLE_API_KEY GEMINI_API_KEY MISTRAL_API_KEY \
        GROQ_API_KEY TOGETHER_API_KEY XAI_API_KEY; do
        if [ -n "${!key:-}" ]; then
            return 1
        fi
    done
    if hermes_env_has_api_key "$HERMES_HOME/.env"; then
        return 1
    fi
    return 0
}

reuse_existing_hermes_api_keys() {
    local dest="$HERMES_HOME/.env"
    mkdir -p "$HERMES_HOME"
    if [ ! -f "$dest" ]; then
        : >"$dest"
    fi
    chmod 600 "$dest" 2>/dev/null || true

    if hermes_env_has_api_key "$dest"; then
        ok "Hermes API configuration already present"
        return 0
    fi

    local src
    for src in "$REPO_DIR/.env" "$HOME/.hermes/.env"; do
        [ "$src" = "$dest" ] && continue
        if hermes_env_has_api_key "$src"; then
            {
                printf '\n# Reused by Agent Blackbox installer from %s\n' "$src"
                grep -E "$HERMES_API_KEY_RE" "$src"
            } >>"$dest"
            chmod 600 "$dest" 2>/dev/null || true
            ok "Reused existing Hermes API key configuration"
            return 0
        fi
    done
    return 1
}

run_hermes_setup() {
    heading "Hermes API setup"
    case "$BLACKBOX_HERMES_SETUP" in
        never|false|0)
            step "Skipping Hermes setup wizard (BLACKBOX_HERMES_SETUP=$BLACKBOX_HERMES_SETUP)."
            return 0
            ;;
        always|true|1)
            ;;
        reuse|auto|"")
            if reuse_existing_hermes_api_keys; then
                :
            elif ! hermes_setup_needed; then
                ok "Hermes API configuration already present in environment"
            else
                step "No existing Hermes API key found; skipping Hermes setup wizard."
                step "Threat-graph sync does not require a Nous subscription or model key."
            fi
            return 0
            ;;
        *)
            warn "Unknown BLACKBOX_HERMES_SETUP=$BLACKBOX_HERMES_SETUP; using reuse."
            if reuse_existing_hermes_api_keys; then
                :
            elif ! hermes_setup_needed; then
                ok "Hermes API configuration already present in environment"
            else
                step "No existing Hermes API key found; skipping Hermes setup wizard."
                step "Threat-graph sync does not require a Nous subscription or model key."
            fi
            return 0
            ;;
    esac

    if ! { [ -r /dev/tty ] && [ -w /dev/tty ]; }; then
        warn "No interactive terminal is available for Hermes API setup."
        step "Run later if needed: hermes setup"
        return 0
    fi

    step "Launching Hermes setup wizard now so API keys are configured before first use."
    if "$HERMES_BIN" setup </dev/tty; then
        ok "Hermes setup wizard completed"
    else
        warn "Hermes setup wizard did not complete. Run later if needed: hermes setup"
    fi
}

# ── DKG node CLI + bootstrap ────────────────────────────────────────────────
install_blackbox_dkg_package() {
    local backup_dir=""
    local package_json="$BLACKBOX_DKG_CLI_DIR/node_modules/@origintrail-official/dkg/package.json"
    local installed_version=""
    local npm_log="$HERMES_HOME/logs/blackbox-npm-install.log"

    if ! command -v npm >/dev/null 2>&1; then
        warn "npm is required to install the published OriginTrail DKG package."
        return 1
    fi

    if [ -d "$BLACKBOX_DKG_CLI_DIR/.git" ]; then
        backup_dir="${BLACKBOX_DKG_CLI_DIR}.custom-backup-$(date +%Y%m%d%H%M%S)"
        step "Moving the custom DKG checkout to $backup_dir"
        if ! mv "$BLACKBOX_DKG_CLI_DIR" "$backup_dir"; then
            warn "Could not preserve the custom DKG checkout before installing npm DKG."
            return 1
        fi
    fi

    mkdir -p "$BLACKBOX_DKG_CLI_DIR"
    mkdir -p "$(dirname "$npm_log")"
    if ! npm install --prefix "$BLACKBOX_DKG_CLI_DIR" --prefer-online \
        "$BLACKBOX_DKG_PACKAGE" >"$npm_log" 2>&1; then
        if [ -n "$backup_dir" ]; then
            rm -rf "$BLACKBOX_DKG_CLI_DIR"
            mv "$backup_dir" "$BLACKBOX_DKG_CLI_DIR"
        fi
        warn "Could not install the published DKG package $BLACKBOX_DKG_PACKAGE."
        if grep -Eiq 'EACCES|permission denied|root-owned' "$npm_log"; then
            local npm_cache
            npm_cache="$(npm config get cache 2>/dev/null || echo "$HOME/.npm")"
            step "npm cache permissions are invalid. Fix them, then re-run:"
            echo "      sudo chown -R \"$(id -u):$(id -g)\" \"$npm_cache\""
        fi
        step "npm log: $npm_log"
        return 1
    fi

    if [ ! -x "$BLACKBOX_DKG_BIN" ] || [ ! -f "$package_json" ]; then
        if [ -n "$backup_dir" ]; then
            rm -rf "$BLACKBOX_DKG_CLI_DIR"
            mv "$backup_dir" "$BLACKBOX_DKG_CLI_DIR"
        fi
        warn "npm completed, but the DKG CLI entrypoint is missing at $BLACKBOX_DKG_BIN."
        return 1
    fi
    installed_version="$(node -p \
        "require(process.argv[1]).version" "$package_json" 2>/dev/null || true)"
    if [ -z "$installed_version" ]; then
        warn "Could not determine the installed DKG package version."
        return 1
    fi
    if ! "$VENV_DIR/bin/python" -m plugins.blackbox.dkg_version "$installed_version"; then
        warn "DKG $installed_version is too old for direct verified Blackbox recovery; version 10.0.9+ is required."
        return 1
    fi
    step "Using published upstream DKG $installed_version unchanged."
    ok "Published DKG npm package ready (${installed_version:-installed})"
}

install_dkg() {
    heading "Setting up the OriginTrail DKG node"
    if [ "$SKIP_DKG" = true ]; then
        BLACKBOX_INSTALL_INCOMPLETE=true
        BLACKBOX_THREAT_GRAPH_INCOMPLETE=true
        warn "Skipping DKG node setup (--skip-dkg)."
        dkg_manual_hint
        return 0
    fi
    if [ "${HAS_NODE:-false}" != true ]; then
        BLACKBOX_INSTALL_INCOMPLETE=true
        BLACKBOX_THREAT_GRAPH_INCOMPLETE=true
        warn "Node.js $NODE_MAJOR+ not available — cannot set up the DKG node or sync the threat graph."
        dkg_manual_hint
        return 0
    fi
    if ! prepare_blackbox_dkg_process_environment; then
        BLACKBOX_INSTALL_INCOMPLETE=true
        BLACKBOX_THREAT_GRAPH_INCOMPLETE=true
        dkg_manual_hint
        return 0
    fi

    step "Installing the published OriginTrail DKG package ($BLACKBOX_DKG_PACKAGE) ..."
    step "  npm prefix: $BLACKBOX_DKG_CLI_DIR"
    if ! install_blackbox_dkg_package; then
        BLACKBOX_INSTALL_INCOMPLETE=true
        BLACKBOX_THREAT_GRAPH_INCOMPLETE=true
        dkg_manual_hint
        return 0
    fi

    if ! migrate_legacy_blackbox_dkg_home; then
        dkg_manual_hint
        return 0
    fi

    if blackbox_has_dkg_state; then
        BLACKBOX_DKG_FRESH_STATE=false
    else
        BLACKBOX_DKG_FRESH_STATE=true
    fi
    mkdir -p "$BLACKBOX_DKG_HOME"
    if ! check_blackbox_dkg_port; then
        dkg_manual_hint
        return 0
    fi
    local store_rc=0
    provision_blackbox_store || store_rc=$?
    if [ "$store_rc" -eq 2 ] || [ "$BLACKBOX_DOCKER_REQUIRED" = true ]; then
        err "Installation stopped before changing the DKG store. Set up Docker and re-run the installer."
        exit 1
    fi
    if [ "$store_rc" -ne 0 ]; then
        err "Blazegraph setup did not complete and Oxigraph was not confirmed. Installation stopped."
        exit 1
    fi
    if ! reset_fresh_managed_blazegraph; then
        err "Installation stopped before creating a DKG identity against stale graph state."
        exit 1
    fi
    if [ "$BLACKBOX_DKG_ALREADY_RUNNING" = true ]; then
        ensure_blackbox_dkg_config
        if ! prepare_blackbox_dkg_runtime_fingerprint; then
            dkg_manual_hint
            return 0
        fi
        if [ "$BLACKBOX_DKG_RESTART_REQUIRED" != true ]; then
            DKG_READY=true
            return 0
        fi
        step "Restarting the Blackbox-owned DKG node to activate sync and relay updates ..."
        if blackbox_dkg stop; then
            blackbox_dkg start || true
        fi
        if wait_for_blackbox_dkg_runtime; then
            rm -f "$BLACKBOX_DKG_STORE_RESET_MARKER"
            ok "Blackbox DKG node restarted with the current sync settings"
            if ! record_blackbox_dkg_runtime_fingerprint; then
                dkg_manual_hint
                return 0
            fi
            DKG_READY=true
        else
            BLACKBOX_INSTALL_INCOMPLETE=true
            BLACKBOX_THREAT_GRAPH_INCOMPLETE=true
            warn "Could not restart the Blackbox DKG node; the updated sync settings are not active."
            dkg_manual_hint
        fi
        return 0
    fi
    ensure_blackbox_dkg_config
    if ! prepare_blackbox_dkg_runtime_fingerprint; then
        dkg_manual_hint
        return 0
    fi

    step "Bootstrapping a Blackbox-owned $DKG_NETWORK node at $BLACKBOX_DKG_DAEMON_URL ..."
    step "  DKG home: $BLACKBOX_DKG_HOME"
    step "  DKG CLI:  $BLACKBOX_DKG_BIN"
    step "  Store:    $(blackbox_store_description)"
    step "  (non-interactive; subscribing and reading need no wallet funding)"
    # DKG's launcher can give up its 15-second startup wait just before a
    # healthy daemon finishes loading a large Blazegraph namespace. The
    # commit-aware readiness check below is the authoritative result.
    blackbox_dkg start || true
    if wait_for_blackbox_dkg_runtime; then
        rm -f "$BLACKBOX_DKG_STORE_RESET_MARKER"
        ok "DKG node bootstrapped on $DKG_NETWORK"
        if ! record_blackbox_dkg_runtime_fingerprint; then
            dkg_manual_hint
            return 0
        fi
        DKG_READY=true
    else
        BLACKBOX_INSTALL_INCOMPLETE=true
        BLACKBOX_THREAT_GRAPH_INCOMPLETE=true
        warn "DKG node bootstrap did not complete. Threat-graph sync is not active yet."
        dkg_manual_hint
    fi
}

# Pull the verified ruleset from the graph now, so detection is live immediately
# after install rather than after the user runs a manual sync.
sync_ruleset() {
    [ "${DKG_READY:-false}" = true ] || return 0
    heading "Syncing the threat ruleset"
    mkdir -p "$HERMES_HOME/logs"
    BLACKBOX_SYNC_LOG="$HERMES_HOME/logs/blackbox-sync-install.log"
    step "Requesting one controlled verified graph catch-up ..."
    step "Sync progress will stream below (also saved to $BLACKBOX_SYNC_LOG)."
    # Start the dashboard before the long initial transfer so discovery,
    # download, verification, and reconciliation are observable immediately.
    : >"$BLACKBOX_SYNC_LOG"
    if [ "$BLACKBOX_AUTO_DASHBOARD" != "0" ] &&
        [ "$BLACKBOX_AUTO_DASHBOARD" != "false" ] &&
        [ "$BLACKBOX_AUTO_DASHBOARD" != "never" ] &&
        [ "$BLACKBOX_AUTO_DASHBOARD" != "no" ]; then
        start_dashboard
    fi

    local sync_code=0
    if PYTHONUNBUFFERED=1 "$HERMES_BIN" blackbox sync --wait --timeout "$BLACKBOX_DKG_CATCHUP_TIMEOUT" --require-rules 2>&1 |
        tee -a "$BLACKBOX_SYNC_LOG"; then
        sync_code=0
    else
        sync_code=$?
    fi
    if [ "$sync_code" -eq 0 ]; then
        ok "Ruleset synced — Blackbox is watching with the latest threats"
    else
        if grep -Eq '  [1-9][0-9,]* verified threats ready' "$BLACKBOX_SYNC_LOG"; then
            BLACKBOX_PARTIAL_RULESET_READY=true
        fi
        BLACKBOX_INSTALL_INCOMPLETE=true
        BLACKBOX_THREAT_GRAPH_INCOMPLETE=true
        err "Initial verified threat-graph sync did not complete."
        step "A partial verified ruleset may already be active, but setup is incomplete until the curator snapshot settles."
        step "Retry the full sync with: blackbox sync --wait --require-rules"
    fi
    ok "DKG native reconciliation enabled; one in-flight slot; zero queue"
    return 0
}

dkg_manual_hint() {
    step "To set up the DKG node later:"
    echo "      node -v  # must be v$NODE_MAJOR or newer (run: nvm use $NODE_MAJOR)"
    echo "      mkdir -p \"$BLACKBOX_DKG_CLI_DIR\""
    echo "      npm install --prefix \"$BLACKBOX_DKG_CLI_DIR\" \"$BLACKBOX_DKG_PACKAGE\""
    echo "      export BLACKBOX_DKG_HOME=\"$BLACKBOX_DKG_HOME\""
    echo "      export BLACKBOX_DKG_BIN=\"$BLACKBOX_DKG_BIN\""
    echo "      export BLACKBOX_DKG_PORT=\"$BLACKBOX_DKG_PORT\""
    echo "      export BLACKBOX_DKG_STORE_URL=\"$BLACKBOX_DKG_STORE_URL\""
    echo "      export BLACKBOX_DKG_DAEMON_URL=\"$BLACKBOX_DKG_DAEMON_URL\""
    echo "      # create config.json/auth.token as in scripts/blackbox-install.sh, then:"
    echo "      NODE_OPTIONS=\"$BLACKBOX_DKG_NODE_OPTIONS\" DKG_HOME=\"\$BLACKBOX_DKG_HOME\" DKG_SYNC_GLOBAL_MAX_INFLIGHT=\"$BLACKBOX_DKG_SYNC_GLOBAL_MAX_INFLIGHT\" DKG_STORE_QUEUE_LIMIT=\"$BLACKBOX_DKG_STORE_QUEUE_LIMIT\" DKG_LIST_CONTEXT_GRAPHS_PROJECTION=\"$BLACKBOX_DKG_LIST_CONTEXT_GRAPHS_PROJECTION\" \"\$BLACKBOX_DKG_BIN\" start"
    echo "      # then re-run:  blackbox sync --wait --require-rules"
}

# ── Enable plugin + write config defaults (idempotent) ──────────────────────
enable_and_configure() {
    heading "Enabling and configuring Blackbox"

    step "Enabling the blackbox plugin without privileged tool overrides ..."
    if "$HERMES_BIN" plugins enable blackbox --no-allow-tool-override >/dev/null 2>&1; then
        ok "Plugin enabled"
    else
        warn "Could not run 'hermes plugins enable blackbox --no-allow-tool-override' automatically."
        step "Run it yourself after the install: hermes plugins enable blackbox --no-allow-tool-override"
    fi

    step "Writing plugins.entries.blackbox defaults to $HERMES_HOME/config.yaml ..."
    if "$VENV_DIR/bin/python" - "$HERMES_HOME/config.yaml" "$DKG_NETWORK" "$BLACKBOX_CONTEXT_GRAPH_ID" "$BLACKBOX_GRAPH_PEER_ID" "$BLACKBOX_DKG_DAEMON_URL" "$BLACKBOX_DKG_HOME" "$BLACKBOX_DKG_BIN" <<'PYEOF'
import sys, os
cfg_path, network, context_graph_id, graph_peer_id, dkg_url, dkg_home, dkg_bin = sys.argv[1:8]
try:
    import yaml
except Exception:
    print("  (PyYAML unavailable — skipping config update; run 'blackbox status' to configure)")
    sys.exit(0)

os.makedirs(os.path.dirname(cfg_path), exist_ok=True)
data = {}
if os.path.exists(cfg_path):
    with open(cfg_path) as f:
        data = yaml.safe_load(f) or {}

plugins = data.setdefault("plugins", {})
entries = plugins.setdefault("entries", {})
blackbox = entries.setdefault("blackbox", {})
# Idempotent for custom user edits, but migrate deprecated defaults that point
# at the user's shared DKG install or a retired community graph.
legacy_dkg_urls = {"http://127.0.0.1:9200", "http://localhost:9200"}
legacy_graphs = {"0x37b1Fdfd134e2b17583bCBdD3034F91504cD9C70/agent-blackbox", "umanitek/blackbox-threats-staging", "umanitek/guardian-threats-staging", "umanitek/guardian-threats"}
legacy_peers = {"12D3KooWAuEHYTWbD3R3yPTcECCYZnrjHNpJmrUw5b4D5T3m5Kr3", "12D3KooWBY9jmNATMPv1DZcKbFas5RtjpkhT69pPwvkUBY2MMnDX", "12D3KooWQHQd1SNecrRxwceqPJkXS" + "K" + "EYn8vrV4QyJ2AfqeYwXz1E", "12D3KooWBJskzr2unXQG9mR3LRZFUJoxWr1PN6hTbyWyKndHXjZM"}
default_dkg_home = os.path.abspath(os.path.expanduser("~/.dkg"))
legacy_blackbox_dkg_home = os.path.abspath(os.path.expanduser("~/.hermes/blackbox/dkg"))
legacy_blackbox_dkg_bin = os.path.abspath(os.path.expanduser("~/.hermes/blackbox/dkg-cli/node_modules/.bin/dkg"))
added = []
current_dkg_url = str(blackbox.get("dkg_url") or blackbox.get("dkgUrl") or "").rstrip("/")
current_dkg_home = str(blackbox.get("dkg_home") or blackbox.get("dkgHome") or "").strip()
current_dkg_home_abs = os.path.abspath(os.path.expanduser(current_dkg_home)) if current_dkg_home else ""
target_dkg_home_abs = os.path.abspath(os.path.expanduser(dkg_home))
uses_shared_dkg_home = current_dkg_home_abs == default_dkg_home
uses_unpaired_shared_dkg_home = uses_shared_dkg_home and (not current_dkg_url or current_dkg_url in legacy_dkg_urls)
uses_legacy_blackbox_dkg_home = current_dkg_home_abs == legacy_blackbox_dkg_home
current_dkg_bin = str(blackbox.get("dkg_bin") or blackbox.get("dkgBin") or "").strip()
current_dkg_bin_abs = os.path.abspath(os.path.expanduser(current_dkg_bin)) if current_dkg_bin else ""
expected_managed_bin = (
    os.path.join(os.path.dirname(current_dkg_home_abs), "dkg", "node_modules", ".bin", "dkg")
    if current_dkg_home_abs else ""
)
uses_target_managed_home = current_dkg_home_abs == target_dkg_home_abs
uses_other_managed_checkout = bool(
    current_dkg_home_abs
    and os.path.basename(current_dkg_home_abs) == ".dkg"
    and current_dkg_home_abs != target_dkg_home_abs
    and current_dkg_bin_abs == expected_managed_bin
)
stale_configured_dkg_home = bool(current_dkg_home_abs) and not os.path.isdir(current_dkg_home_abs)
stale_configured_dkg_bin = bool(current_dkg_bin_abs) and not os.path.isfile(current_dkg_bin_abs)
rebind_managed_dkg = (
    uses_target_managed_home
    or uses_other_managed_checkout
    or stale_configured_dkg_home
    or stale_configured_dkg_bin
)
current_graph = str(blackbox.get("context_graph_id") or "")
if "dkg_url" not in blackbox or current_dkg_url in legacy_dkg_urls or uses_unpaired_shared_dkg_home or uses_legacy_blackbox_dkg_home or rebind_managed_dkg:
    blackbox["dkg_url"] = dkg_url.rstrip("/")
    added.append("dkg_url")
if "dkg_home" not in blackbox or not blackbox.get("dkg_home") or uses_unpaired_shared_dkg_home or uses_legacy_blackbox_dkg_home or rebind_managed_dkg:
    blackbox["dkg_home"] = dkg_home
    added.append("dkg_home")
if not current_dkg_bin or current_dkg_bin == "dkg" or current_dkg_bin_abs == legacy_blackbox_dkg_bin or rebind_managed_dkg:
    blackbox["dkg_bin"] = dkg_bin
    added.append("dkg_bin")
if current_graph in legacy_graphs:
    blackbox["context_graph_id"] = context_graph_id
    added.append("context_graph_id")
if not blackbox.get("graph_peer_id") or str(blackbox.get("graph_peer_id")) in legacy_peers:
    blackbox["graph_peer_id"] = graph_peer_id
    added.append("graph_peer_id")
defaults = {
    "mode": "audit",
    "context_graph_id": context_graph_id,
    "graph_peer_id": graph_peer_id,
    "sync_interval": 3600,
    # Community sharing has not shipped.  Keep fresh installs private, and
    # make the obsolete outbound-report allowance inert for compatibility
    # with older readers that still expect the key to exist.
    "report": False,
    "daily_report_limit": 0,
    "report_min_severity": "high",
    "block_severity": "critical",
    "dashboard_port": 9700,
    # Optional LLM reviewer — off until `blackbox setup-llm` fills it in.
    "llm": {"enabled": False, "provider": "", "model": "", "api_key": ""},
}
for k, v in defaults.items():
    if k not in blackbox:
        blackbox[k] = v
        added.append(k)
# Migrate stale pre-release sharing settings too. The feature is closed at
# runtime, so leaving an old opt-in in config is misleading even if inert.
for k, v in {"report": False, "daily_report_limit": 0}.items():
    if blackbox.get(k) != v:
        blackbox[k] = v
        added.append(k)
with open(cfg_path, "w") as f:
    yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)
if added:
    print("  configured: " + ", ".join(added))
else:
    print("  already configured — no changes")
PYEOF
    then
        ok "Config defaults written (audit mode — blocking is opt-in)"
    else
        warn "Could not write config automatically. Run 'blackbox status' to verify configuration."
    fi
}

read_blackbox_mode() {
    "$VENV_DIR/bin/python" - "$HERMES_HOME/config.yaml" <<'PYEOF'
import sys, os
cfg_path = sys.argv[1]
try:
    import yaml
except Exception:
    print("audit")
    sys.exit(0)
data = {}
if os.path.exists(cfg_path):
    with open(cfg_path) as f:
        data = yaml.safe_load(f) or {}
mode = (
    data.get("plugins", {})
    .get("entries", {})
    .get("blackbox", {})
    .get("mode", "audit")
)
mode = str(mode).lower()
print(mode if mode in ("audit", "block") else "audit")
PYEOF
}

write_blackbox_mode() {
    local mode="$1"
    "$VENV_DIR/bin/python" - "$HERMES_HOME/config.yaml" "$mode" <<'PYEOF'
import sys, os
cfg_path, mode = sys.argv[1], sys.argv[2]
try:
    import yaml
except Exception:
    print("  (PyYAML unavailable — could not save protection mode)")
    sys.exit(1)
if mode not in ("audit", "block"):
    sys.exit(1)
os.makedirs(os.path.dirname(cfg_path), exist_ok=True)
data = {}
if os.path.exists(cfg_path):
    with open(cfg_path) as f:
        data = yaml.safe_load(f) or {}
blackbox = data.setdefault("plugins", {}).setdefault("entries", {}).setdefault("blackbox", {})
blackbox["mode"] = mode
blackbox.setdefault("block_severity", "critical")
with open(cfg_path, "w") as f:
    yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)
PYEOF
}

configure_blackbox_mode() {
    heading "Blackbox mode"
    local current="${BLACKBOX_MODE:-}"
    current="$(printf '%s' "$current" | tr '[:upper:]' '[:lower:]')"
    [ "$current" = "block" ] || current="audit"
    BLACKBOX_SELECTED_MODE="$current"

    if write_blackbox_mode "$BLACKBOX_SELECTED_MODE"; then
        ok "Blackbox runs in $BLACKBOX_SELECTED_MODE mode"
    else
        warn "Could not save Blackbox mode. Set plugins.entries.blackbox.mode in config.yaml."
    fi
}

# ── Auto-protect every local agent (best-effort, non-fatal) ─────────────────
# Discovers every local Hermes home + OpenClaw workspace and enables Blackbox
# in each, so protection is on everywhere without per-instance setup.
attach_all_agents() {
    heading "Protecting all local agents"
    step "Discovering local Hermes homes + OpenClaw workspaces (blackbox attach) ..."
    if "$HERMES_BIN" blackbox attach; then
        ok "Blackbox attached to all discovered local agents"
    else
        warn "Could not auto-attach to every local agent (this is non-fatal)."
        step "Re-run anytime with:  blackbox attach"
    fi
}

# ── Optional: configure the LLM prompt-injection reviewer ───────────────────
# Under `curl | bash` the script's stdin is the pipe, so prompts use /dev/tty.
# Reuse existing LLM config when present. If none exists, skip cleanly: the
# threat-graph ruleset is the protection baseline, and the LLM reviewer is an
# optional local-only extra that can be configured later.
setup_llm() {
    heading "LLM reviewer"
    local args=()
    [ -n "$BLACKBOX_LLM_PROVIDER" ] && args+=(--provider "$BLACKBOX_LLM_PROVIDER")
    [ -n "$BLACKBOX_LLM_MODEL" ] && args+=(--model "$BLACKBOX_LLM_MODEL")
    if [ -n "$BLACKBOX_LLM_API_KEY" ]; then
        args+=(--api-key "$BLACKBOX_LLM_API_KEY")
        args+=(--key-source new)
    elif [ -n "$BLACKBOX_LLM_KEY_SOURCE" ]; then
        args+=(--key-source "$BLACKBOX_LLM_KEY_SOURCE")
    fi

    if [ "${#args[@]}" -gt 0 ]; then
        step "Using BLACKBOX_LLM_* settings."
        if "$HERMES_BIN" blackbox setup-llm "${args[@]}"; then
            ok "LLM reviewer configured"
        else
            warn "LLM reviewer setup failed from BLACKBOX_LLM_* values."
            step "Check BLACKBOX_LLM_PROVIDER, BLACKBOX_LLM_MODEL, and BLACKBOX_LLM_API_KEY, then re-run."
        fi
        return 0
    fi

    step "Trying existing Blackbox, Hermes, or OpenClaw LLM config."
    if "$HERMES_BIN" blackbox setup-llm --auto; then
        ok "LLM reviewer ready"
    else
        step "LLM reviewer not configured; this is optional and can be set up later:"
        step "  blackbox setup-llm"
    fi
}

start_dashboard() {
    case "$BLACKBOX_AUTO_DASHBOARD" in
        0|false|never|no)
            step "Dashboard auto-start disabled (BLACKBOX_AUTO_DASHBOARD=$BLACKBOX_AUTO_DASHBOARD)."
            return 0
            ;;
    esac

    heading "Starting Blackbox dashboard"
    local port="${BLACKBOX_DASHBOARD_PORT:-9700}"
    local url="http://127.0.0.1:$port"
    local log_dir="$HERMES_HOME/logs"
    local log_file="$log_dir/blackbox-dashboard-install.log"
    mkdir -p "$log_dir"

    if command -v curl >/dev/null 2>&1 && curl -fsS "$url/" >/dev/null 2>&1; then
        ok "Dashboard already running at $url"
        return 0
    fi

    step "Launching: blackbox dashboard"
    run_detached "$log_file" "$HERMES_BIN" blackbox dashboard
    sleep 2

    if command -v curl >/dev/null 2>&1 && ! curl -fsS "$url/" >/dev/null 2>&1; then
        warn "Dashboard process started, but $url did not respond yet."
        step "Log: $log_file"
        return 0
    fi
    ok "Dashboard running at $url"
    step "Log: $log_file"
}

# ── Guided next steps (short — everything above already ran) ─────────────────
next_steps() {
    local docs_url="${REPO_URL%.git}"
    local path_note=""
    local mode="${BLACKBOX_SELECTED_MODE:-$(read_blackbox_mode 2>/dev/null || echo audit)}"
    local store_note="$(blackbox_store_description)"
    case ":$PATH:" in
        *":$HOME/.local/bin:"*) : ;;
        *) path_note=$'\n  First reload your shell so `blackbox` is on PATH:  exec $SHELL -l' ;;
    esac
    if [ "$BLACKBOX_SYNC_PENDING" = true ]; then
        heading "Blackbox dashboard is running; threat-graph sync is catching up."
        cat <<EOF
${path_note}
  Dashboard:  http://127.0.0.1:${BLACKBOX_DASHBOARD_PORT:-9700}
  DKG node:   $BLACKBOX_DKG_DAEMON_URL
  DKG home:   $BLACKBOX_DKG_HOME
  DKG CLI:    $BLACKBOX_DKG_BIN
  Store:      $store_note

  The public threat-graph subscription and DKG sync are running in the
  background. Do not treat this install as fully protected until this command
  succeeds:

      blackbox sync --wait --require-rules

  Background log:
      ${BLACKBOX_SYNC_LOG:-$HERMES_HOME/logs/blackbox-sync-install.log}

  Docs:        $docs_url
EOF
        echo ""
        return 0
    fi
    if [ "$BLACKBOX_INSTALL_INCOMPLETE" = true ]; then
        heading "Blackbox installed, but setup is incomplete."
        cat <<EOF
${path_note}
EOF
        if [ "$BLACKBOX_THREAT_GRAPH_INCOMPLETE" = true ]; then
            if [ "$BLACKBOX_PARTIAL_RULESET_READY" = true ]; then
                cat <<EOF
  A partial verified ruleset is active, but the authoritative snapshot did not
  finish. Keep the dashboard open to inspect the active protection, then retry:

      blackbox sync --wait --require-rules

EOF
            else
                cat <<EOF
  The local DKG node did not provide a non-empty ruleset yet. Do not treat this
  install as protected until this command succeeds:

      blackbox sync --wait --require-rules

EOF
            fi
        fi
        cat <<EOF
  Dashboard:  http://127.0.0.1:${BLACKBOX_DASHBOARD_PORT:-9700}
  DKG node:   $BLACKBOX_DKG_DAEMON_URL
  DKG home:   $BLACKBOX_DKG_HOME
  DKG CLI:    $BLACKBOX_DKG_BIN
  Store:      $store_note
  Docs:        $docs_url
EOF
        echo ""
        return 0
    fi
    heading "Blackbox is ready ($mode mode)."
    cat <<EOF
${path_note}
  Dashboard:  http://127.0.0.1:${BLACKBOX_DASHBOARD_PORT:-9700}
  DKG node:   $BLACKBOX_DKG_DAEMON_URL
  DKG home:   $BLACKBOX_DKG_HOME
  DKG CLI:    $BLACKBOX_DKG_BIN
  Store:      $store_note
  Sync now:    blackbox sync --wait
  Docs:        $docs_url
EOF
    echo ""
}

# ── Main ────────────────────────────────────────────────────────────────────
main() {
    banner
    heading "Checking your system"
    detect_os
    check_git
    check_python
    ensure_node

    resolve_repo
    install_python_env
    link_hermes
    refresh_blackbox_plugin_copy
    run_hermes_setup
    install_dkg
    enable_and_configure
    configure_blackbox_mode
    attach_all_agents
    setup_llm
    sync_ruleset
    start_dashboard
    next_steps
    if [ "$BLACKBOX_INSTALL_INCOMPLETE" = true ]; then
        exit 1
    fi
}

main "$@"
