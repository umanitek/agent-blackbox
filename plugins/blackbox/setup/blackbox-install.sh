#!/usr/bin/env bash
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
# Setup-only mode: Blackbox is already installed as a plugin (the Hermes plugin catalog),
# and `hermes blackbox setup` runs this script for everything after Hermes — the DKG
# node, the graphs, attach, sync, dashboard and services — in the Hermes it runs in.
# The caller passes HERMES_BIN, VENV_DIR (that Hermes's Python environment),
# BLACKBOX_INSTALL_DIR, BLACKBOX_HELPER_DIR (the plugin's copies of the helper scripts),
# BLACKBOX_PLUGIN_DIR and BLACKBOX_REVISION (the plugin's pinned commit).
BLACKBOX_SETUP_ONLY="${BLACKBOX_SETUP_ONLY:-false}"
REPO_DIR=""   # set by resolve_repo; setup-only mode has no checkout
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
BLACKBOX_SYSTEMD_DIR=/etc/systemd/system   # where system units go (node service units below)
BLACKBOX_DKG_LAUNCHD_LABEL=ai.umanitek.blackbox-dkg   # the node's LaunchAgent on macOS (register_boot_service)
# The system folders every service PATH carries after its own tools. /usr/sbin is not optional: the
# DKG node runs `lsof` to see who holds its store's LOCK and refuses to start when it cannot, and
# macOS (and RHEL-family Linux) keep lsof only in /usr/sbin — a LaunchAgent without it crash-looped
# at every login (KI-427).
BLACKBOX_SERVICE_SYSTEM_PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
BLACKBOX_LINGER_DIR=/var/lib/systemd/linger   # systemd-logind keeps one file per lingering user here
BLACKBOX_PTRACE_SCOPE_FILE=/proc/sys/kernel/yama/ptrace_scope   # read by register_key_console
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
# The DKG node release this Blackbox installs and the sha512 the downloaded package must
# have (`npm view <package> dist.integrity`). The hash is checked on the tarball npm will
# install, never on the registry's own claim about it. Another BLACKBOX_DKG_PACKAGE needs
# its own BLACKBOX_DKG_INTEGRITY, or BLACKBOX_DKG_INTEGRITY=unpinned to skip the check knowingly.
BLACKBOX_DKG_DEFAULT_PACKAGE="@origintrail-official/dkg@10.0.26"
BLACKBOX_DKG_DEFAULT_INTEGRITY="sha512-QlCW/5UvL2UHaR2QGAemQzvu+ZtBKfefwuitoX2hGr/XZAgkFXsln1NHitzftQM99qTrlKBq8CFfDSfDFAbMHg=="
BLACKBOX_DKG_PACKAGE="${BLACKBOX_DKG_PACKAGE:-$BLACKBOX_DKG_DEFAULT_PACKAGE}"
BLACKBOX_DKG_INTEGRITY="${BLACKBOX_DKG_INTEGRITY:-}"
if [ -z "$BLACKBOX_DKG_INTEGRITY" ] && [ "$BLACKBOX_DKG_PACKAGE" = "$BLACKBOX_DKG_DEFAULT_PACKAGE" ]; then
    BLACKBOX_DKG_INTEGRITY="$BLACKBOX_DKG_DEFAULT_INTEGRITY"
fi
# Packages whose install scripts the DKG node needs (its sqlite runtime check, the better-sqlite3
# native build, a postinstall). Older npm ran every install script; npm 12 runs only those the
# project's package.json lists under "allowScripts" (its --allow-scripts flag is refused for a
# project install), and without the better-sqlite3 build the node crashes on every start.
BLACKBOX_DKG_ALLOW_SCRIPTS=(@origintrail-official/dkg better-sqlite3 @openuidev/lang-core)
BLACKBOX_DKG_DAEMON_URL="http://127.0.0.1:$BLACKBOX_DKG_PORT"
BLACKBOX_DKG_STORE_QUEUE_LIMIT="${BLACKBOX_DKG_STORE_QUEUE_LIMIT:-512}"
BLACKBOX_DKG_LIST_CONTEXT_GRAPHS_PROJECTION="${BLACKBOX_DKG_LIST_CONTEXT_GRAPHS_PROJECTION:-1}"
# The node's own sync defaults (DKG 10.0.25: 10 sync jobs, queue 20), so verified data and community
# data sync side by side. Was 1/0 from the original installer; with one slot the community catch-ups
# starved the verified download (bench 2026-10-22: 10 slots, community on from the start, full graph
# in about 30 min with no deferrals and no store recovery).
BLACKBOX_DKG_SYNC_GLOBAL_MAX_INFLIGHT="10"
BLACKBOX_DKG_SYNC_GLOBAL_QUEUE_LIMIT="20"
BLACKBOX_DKG_DURABLE_SYNC_ENABLED="${BLACKBOX_DKG_DURABLE_SYNC_ENABLED:-1}"
BLACKBOX_DKG_CATCHUP_MAX_CONCURRENT_PEERS="1"
BLACKBOX_DKG_STORE_QUEUE_WAIT_TIMEOUT_MS="300000"
BLACKBOX_DKG_NODE_OPTIONS=""
# DKG 10.0.21+ recovery speed-ups (KI-282), both off by default in the node. The exact
# batch stream is read ONLY from the environment, so every launch path below passes it.
BLACKBOX_DKG_EXACT_BATCH_STREAM_ENABLED="${BLACKBOX_DKG_EXACT_BATCH_STREAM_ENABLED:-1}"
BLACKBOX_DKG_VM_RECOVERY_PREFETCH_ENABLED="${BLACKBOX_DKG_VM_RECOVERY_PREFETCH_ENABLED:-1}"
NODE_MAJOR="${BLACKBOX_NODE_MAJOR:-22}"
# nvm's installer is run only after its bytes match this pinned sha256 (Hermes catalog review,
# 2026-10-16): a changed or tampered script never reaches bash. The hash is of
# https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh and equals install.sh in the
# v0.40.3 release archive. Moving to a new nvm release moves both lines together.
NVM_INSTALL_VERSION_PIN="v0.40.3"
NVM_INSTALL_SHA256="2d8359a64a3cb07c02389ad88ceecd43f2fa469c06104f92f98df5b6f315275f"
BLACKBOX_DEFAULT_CONTEXT_GRAPH_ID="0x37b1Fdfd134e2b17583bCBdD3034F91504cD9C70/agent-blackbox-vm"
BLACKBOX_CONTEXT_GRAPH_ID="${BLACKBOX_CONTEXT_GRAPH_ID:-$BLACKBOX_DEFAULT_CONTEXT_GRAPH_ID}"
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
    install_record_started_pid "$BLACKBOX_DETACHED_PID"
}

detached_process_survived_startup() {
    local pid="${1:-}"
    local grace_seconds="${2:-2}"
    [ -n "$pid" ] || return 1
    sleep "$grace_seconds"
    kill -0 "$pid" 2>/dev/null
}

# A helper script shipped beside this installer: scripts/ in a checkout, the plugin's
# setup/ folder in setup-only mode (BLACKBOX_HELPER_DIR).
blackbox_helper() {
    printf '%s/%s' "${BLACKBOX_HELPER_DIR:-$REPO_DIR/scripts}" "$1"
}

prepare_blackbox_dkg_process_environment() {
    local helper="$(blackbox_helper blackbox-dkg-runtime-fingerprint.py)"
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
    # Sync transfers at once, by the machine's memory (sync/process_limits.sync_slots): the
    # node's own 10 from 8 GB, 4 below — the store shares the machine (bench 2026-10-22).
    local slots=""
    if slots="$("$VENV_DIR/bin/python" "$helper" sync-slots)" && [[ "$slots" =~ ^[0-9]+\ [0-9]+$ ]]; then
        BLACKBOX_DKG_SYNC_GLOBAL_MAX_INFLIGHT="${slots%% *}"
        BLACKBOX_DKG_SYNC_GLOBAL_QUEUE_LIMIT="${slots##* }"
    else
        warn "Could not size the node's sync slots for this machine; using the node's defaults."
    fi
    # Record them so Blackbox's own node restarts (blackbox sync, the dashboard)
    # relaunch with the same limits (sync/process_limits.py). Not fatal: without
    # the record those restarts use the same defaults computed again.
    if ! "$VENV_DIR/bin/python" "$helper" write-limits "$BLACKBOX_DKG_HOME" "$BLACKBOX_DKG_NODE_OPTIONS" \
        "$BLACKBOX_DKG_STORE_QUEUE_LIMIT" >/dev/null; then
        warn "Could not record the DKG node limits; Blackbox restarts will recompute them."
    fi
    ok "DKG safety limits: V8 heap ${heap_mb}MB; $BLACKBOX_DKG_SYNC_GLOBAL_MAX_INFLIGHT syncs at once"
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
    # DKG_SYNC_TOTAL_TIMEOUT_MS and DKG_SWM_RECOVERY_TIMEOUT_MS have no effect: the
    # node reads neither (DKG 10.0.25 has its sync limits built in).
    PATH="$node_bin_dir:$PATH" \
    DKG_HOME="$BLACKBOX_DKG_HOME" \
    DKG_ACCEPT_STORE_RESET="$accept_store_reset" \
    DKG_STORE_QUEUE_LIMIT="$BLACKBOX_DKG_STORE_QUEUE_LIMIT" \
    DKG_LIST_CONTEXT_GRAPHS_PROJECTION="$BLACKBOX_DKG_LIST_CONTEXT_GRAPHS_PROJECTION" \
    DKG_SYNC_ON_CONNECT_ENABLED="0" \
    DKG_SYNC_RECONCILER_ENABLED="0" \
    DKG_DURABLE_SYNC_ENABLED="$BLACKBOX_DKG_DURABLE_SYNC_ENABLED" \
    DKG_SYNC_GLOBAL_MAX_INFLIGHT="$BLACKBOX_DKG_SYNC_GLOBAL_MAX_INFLIGHT" \
    DKG_SYNC_GLOBAL_QUEUE_LIMIT="$BLACKBOX_DKG_SYNC_GLOBAL_QUEUE_LIMIT" \
    DKG_CATCHUP_MAX_CONCURRENT_PEERS="$BLACKBOX_DKG_CATCHUP_MAX_CONCURRENT_PEERS" \
    DKG_STORE_QUEUE_WAIT_TIMEOUT_MS="$BLACKBOX_DKG_STORE_QUEUE_WAIT_TIMEOUT_MS" \
    DKG_SYNC_TOTAL_TIMEOUT_MS="1800000" \
    DKG_SWM_RECOVERY_TIMEOUT_MS="3600000" \
    DKG_EXACT_BATCH_STREAM_ENABLED="$BLACKBOX_DKG_EXACT_BATCH_STREAM_ENABLED" \
    DKG_VM_RECOVERY_PREFETCH_ENABLED="$BLACKBOX_DKG_VM_RECOVERY_PREFETCH_ENABLED" \
    NODE_OPTIONS="$BLACKBOX_DKG_NODE_OPTIONS" \
    "$BLACKBOX_DKG_BIN" "$@"
}

# The service an earlier install registered to supervise the node (register_boot_service):
# "systemd" (system unit), "systemd-user", "launchd", or nothing — a first install, where the
# installer runs the node itself until the service is registered at the end.
blackbox_dkg_supervisor() {
    if command -v systemctl >/dev/null 2>&1; then
        if [ -f "$BLACKBOX_SYSTEMD_DIR/blackbox-dkg.service" ] &&
            systemctl is-enabled --quiet blackbox-dkg 2>/dev/null; then
            echo systemd
            return 0
        fi
        if [ -f "$HOME/.config/systemd/user/blackbox-dkg.service" ] &&
            systemctl --user is-enabled --quiet blackbox-dkg 2>/dev/null; then
            echo systemd-user
            return 0
        fi
    fi
    if [ "$(uname -s 2>/dev/null)" = Darwin ] && [ -f "$HOME/Library/LaunchAgents/$BLACKBOX_DKG_LAUNCHD_LABEL.plist" ]; then
        echo launchd
    fi
    return 0
}

# `blackbox_dkg_control start|stop|restart` — through the supervising service when there is
# one. A supervised node stopped or started with `dkg stop`/`dkg start` behind the service's
# back makes the two fight: the service's node exits "failed", the service restarts it, and
# the unit's ExecStartPre `dkg stop` (the orphan guard) kills the copy the installer just
# started — the unit flaps, and the catch-up that follows fails "Daemon already running"
# (KI-414). The plugin restarts through the service for the same reason (FIX-0014). A stop
# through the service stays stopped (systemd does not restart a requested stop; launchd's
# job is unloaded) until the matching start.
blackbox_dkg_control() {
    local action="$1" target
    case "$(blackbox_dkg_supervisor)" in
        systemd) systemctl "$action" blackbox-dkg ;;
        systemd-user) systemctl --user "$action" blackbox-dkg ;;
        launchd)
            target="gui/$(id -u)/$BLACKBOX_DKG_LAUNCHD_LABEL"
            case "$action" in
                stop) launchctl bootout "$target" 2>/dev/null || true ;;
                start | restart)
                    if launchctl print "$target" >/dev/null 2>&1; then
                        if [ "$action" = restart ]; then
                            launchctl kickstart -k "$target"
                        else
                            launchctl kickstart "$target"
                        fi
                    else
                        launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/$BLACKBOX_DKG_LAUNCHD_LABEL.plist"
                    fi
                    ;;
            esac
            ;;
        *)
            if [ "$action" = restart ]; then
                blackbox_dkg stop && blackbox_dkg start
            else
                blackbox_dkg "$action"
            fi
            ;;
    esac
}

BLACKBOX_DKG_HANDOVER_WAIT_SECONDS="${BLACKBOX_DKG_HANDOVER_WAIT_SECONDS:-90}"   # a node start takes 10-60 s

# The pid of the process the node's service runs (`dkg start --foreground`, the DKG CLI's own
# supervisor), or nothing when the service is not running it.
blackbox_dkg_service_pid() {
    local pid=""
    case "$1" in
        systemd) pid="$(systemctl show -p MainPID --value blackbox-dkg 2>/dev/null)" ;;
        systemd-user) pid="$(systemctl --user show -p MainPID --value blackbox-dkg 2>/dev/null)" ;;
        launchd)
            pid="$(launchctl print "gui/$(id -u)/$BLACKBOX_DKG_LAUNCHD_LABEL" 2>/dev/null |
                sed -nE 's/^[[:space:]]*pid = ([0-9]+).*/\1/p' | head -n 1)"
            ;;
    esac
    pid="$(printf '%s' "$pid" | tr -dc '0-9')"
    [ "$pid" = 0 ] && pid=""   # systemd's MainPID for a unit that is not running
    printf '%s' "$pid"
}

# Whether the running node is the one the service *supervisor* runs. The node daemon writes its
# own pid to daemon.pid; under `dkg start --foreground` it is a child of the process the service
# started, so either that process or its parent is the service's.
blackbox_dkg_owned_by() {
    local service_pid node_pid parent_pid
    service_pid="$(blackbox_dkg_service_pid "$1")"
    [ -n "$service_pid" ] || return 1
    [ -f "$BLACKBOX_DKG_HOME/daemon.pid" ] || return 1
    node_pid="$(tr -dc '0-9' <"$BLACKBOX_DKG_HOME/daemon.pid")"
    [ -n "$node_pid" ] || return 1
    [ "$node_pid" = "$service_pid" ] && return 0
    parent_pid="$(ps -o ppid= -p "$node_pid" 2>/dev/null | tr -dc '0-9')"
    [ "$parent_pid" = "$service_pid" ]
}

# Where launchd keeps the node's error output: launchd has no journal, so without this a node
# that fails under the LaunchAgent leaves no trace. Errors only — the node writes its own log.
blackbox_dkg_launchd_error_log() {
    printf '%s/launchd-errors.log' "$BLACKBOX_DKG_HOME"
}

blackbox_dkg_answers() {
    curl -fsS --max-time 5 "$BLACKBOX_DKG_DAEMON_URL/api/status" >/dev/null 2>&1
}

# A first install has no service yet, so it runs the node itself (with install-only settings,
# e.g. sync-on-connect off). Registering the service does not move that node under it: launchd's
# copy exits "Daemon already running" and is relaunched for ever, systemd's is only enabled — so
# until a reboot nothing supervises the node and it keeps the install-only settings (KI-426).
# Hand it over: stop the installer's copy, start the node through its service, and confirm the
# service's process is the one serving. If the service does not take it, the node is started
# again directly so protection never drops, and the run says so.
hand_dkg_node_to_service() {
    local supervisor waited=0
    supervisor="$(blackbox_dkg_supervisor)"
    [ -n "$supervisor" ] || return 0
    if blackbox_dkg_owned_by "$supervisor" && blackbox_dkg_answers; then
        ok "The DKG node already runs under its $supervisor service"
        return 0
    fi
    step "Handing the DKG node to its $supervisor service ..."
    blackbox_dkg stop >/dev/null 2>&1 || true   # the installer's own, unsupervised copy
    blackbox_dkg_control restart >/dev/null 2>&1 || true
    while [ "$waited" -lt "$BLACKBOX_DKG_HANDOVER_WAIT_SECONDS" ]; do
        if blackbox_dkg_owned_by "$supervisor" && blackbox_dkg_answers; then
            ok "The DKG node now runs under its $supervisor service"
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done
    warn "The $supervisor service did not take over the DKG node within ${BLACKBOX_DKG_HANDOVER_WAIT_SECONDS}s."
    if [ "$supervisor" = launchd ] && [ -s "$(blackbox_dkg_launchd_error_log)" ]; then
        warn "Its last errors ($(blackbox_dkg_launchd_error_log)):"
        tail -n 5 "$(blackbox_dkg_launchd_error_log)" | sed 's/^/    /'
    fi
    if ! blackbox_dkg_answers; then
        blackbox_dkg_control stop >/dev/null 2>&1 || true   # so it does not fight the direct copy
        blackbox_dkg start >/dev/null 2>&1 || true
    fi
    warn "The node runs without its service until the next reboot or login; re-run the installer to retry."
}

# A per-user systemd service runs only while its user has a login session: without lingering,
# logging out stops the node and a reboot does not start it until that user logs in again — on a
# server nobody logs in to, it never runs (KI-428). Lingering is systemd's documented switch for
# this; most systems let a user set it for themselves, otherwise it needs root once.
ensure_user_lingering() {
    command -v loginctl >/dev/null 2>&1 || return 0
    local user
    user="$(id -un)"
    [ -e "$BLACKBOX_LINGER_DIR/$user" ] && return 0
    if loginctl enable-linger "$user" >/dev/null 2>&1 || sudo -n loginctl enable-linger "$user" >/dev/null 2>&1; then
        ok "Lingering on for $user: Blackbox's services keep running after logout and start at boot"
    else
        warn "Blackbox's services stop when $user logs out and start again only at the next login."
        warn "To keep them running: sudo loginctl enable-linger $user"
    fi
}

blackbox_has_dkg_state() {
    [ -f "$BLACKBOX_DKG_HOME/auth.token" ] || [ -f "$BLACKBOX_DKG_HOME/config.json" ]
}

prepare_blackbox_dkg_runtime_fingerprint() {
    local fingerprinter="$(blackbox_helper blackbox-dkg-runtime-fingerprint.py)"
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
    local fingerprinter="$(blackbox_helper blackbox-dkg-runtime-fingerprint.py)"
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
    local verifier="$(blackbox_helper blackbox-dkg-runtime-fingerprint.py)"
    local expected_commit
    "$VENV_DIR/bin/python" "$(blackbox_helper blackbox-native-bootstrap.py)" wait \
        "$BLACKBOX_DKG_HOME" "$BLACKBOX_DKG_DAEMON_URL" || return 1
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

# The DKG-managed Oxigraph store listens on its own loopback port, 7878 unless the node's
# config.json names one (store.options.port). Another DKG node on this machine — a second
# product, a developer's own node — very likely holds 7878 already, and two stores cannot
# share a port: Blackbox's node would fail to start its store. So a Blackbox node whose
# config names no port gets the first free one from BLACKBOX_OXIGRAPH_FIRST_PORT, written
# into its config. Prints the port to write, or nothing to leave the config as it is (a
# configured port is kept; a Blackbox node already running holds its port itself).
# The search starts ABOVE 7878: "free" is only what this moment shows, and another node's
# store is briefly down whenever that node restarts — a Mac install probed inside such a
# 2-second gap, took 7878 and failed to start (2026-10-22). Blackbox never takes the default.
BLACKBOX_OXIGRAPH_FIRST_PORT=7879
BLACKBOX_OXIGRAPH_LAST_PORT=7978
choose_blackbox_oxigraph_port() {
    local candidate
    [ "$BLACKBOX_DKG_ALREADY_RUNNING" = true ] && return 0
    for candidate in $(seq "$BLACKBOX_OXIGRAPH_FIRST_PORT" "$BLACKBOX_OXIGRAPH_LAST_PORT"); do
        if ! port_in_use "$candidate"; then
            printf '%s' "$candidate"
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
        # Only a Docker Desktop this run opens is this run's to close again; one the user
        # already had open (even with its engine stuck) is left as it is.
        if ! pgrep -f 'Docker.app/Contents/MacOS/' >/dev/null 2>&1; then
            BLACKBOX_OPENED_DOCKER_DESKTOP=true
        fi
        step "Docker Desktop's engine is not running; starting it now ..."
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
        # This run opened it, so this run closes it again: a failed start must not leave
        # a half-started Docker Desktop behind on the machine.
        if [ "${BLACKBOX_OPENED_DOCKER_DESKTOP:-false}" = true ]; then
            osascript -e 'quit app "Docker"' >/dev/null 2>&1 || true
            BLACKBOX_OPENED_DOCKER_DESKTOP=false
        fi
    fi
    if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
        BLACKBOX_DOCKER_REQUIRED=true
        docker_setup_hint
        return 1
    fi
    ok "Docker engine is ready for Blazegraph"
}

# Whether Docker can run the Blazegraph store: running now, or Docker Desktop installed on a Mac
# (require_docker_for_blazegraph starts it).
blackbox_docker_available() {
    command -v docker >/dev/null 2>&1 || return 1
    docker info >/dev/null 2>&1 && return 0
    [ "$OS" = "macos" ] && { [ -d "/Applications/Docker.app" ] || [ -d "$HOME/Applications/Docker.app" ]; }
}

use_blackbox_oxigraph() {
    BLACKBOX_DOCKER_REQUIRED=false
    BLACKBOX_DKG_SELECTED_STORE_BACKEND="oxigraph-server"
    BLACKBOX_DKG_STORE_URL=""
    BLACKBOX_DKG_STORE_MANAGED_BY_DKG=false
    warn "Using the DKG-managed Oxigraph store (no Docker container required)."
}

# Docker cannot run the Blazegraph store (not installed, its engine not answering, or the
# store's container failing to start — KI-313/KI-398): the install falls back to the
# DKG-managed Oxigraph store and never dead-ends (Amos, 2026-10-17). A person at a
# terminal is still asked, with yes as the default — Enter, or no answer within
# BLACKBOX_STORE_PROMPT_SECONDS, takes Oxigraph; only an explicit "n" stops the install
# (and the install record then removes everything this run did). With no terminal —
# an agent, a script, a server — Oxigraph is chosen automatically and the run says why.
BLACKBOX_STORE_PROMPT_SECONDS="${BLACKBOX_STORE_PROMPT_SECONDS:-30}"
confirm_oxigraph_fallback() {
    local reason="$1"
    local answer=""
    warn "$reason"
    # /dev/tty can exist and pass -r/-w while the piped `curl | bash`
    # process has no controlling terminal. Probe by opening it once and keep
    # that descriptor for both prompt and response so no shell-level
    # "Device not configured" errors leak into the install.
    if ! { exec 9<>/dev/tty; } 2>/dev/null; then
        step "No terminal to ask, so Blackbox uses the DKG-managed Oxigraph store (no Docker needed)."
        step "To move to Blazegraph later: make Docker work, then re-run the installer with --store blazegraph"
        return 0
    fi
    step "Blackbox can continue with the DKG-managed Oxigraph store, which needs no Docker."
    printf "Continue with Oxigraph? [Y/n] (yes in %ss) " "$BLACKBOX_STORE_PROMPT_SECONDS" >&9
    IFS= read -r -t "$BLACKBOX_STORE_PROMPT_SECONDS" answer <&9 || answer=""
    printf '\n' >&9
    exec 9>&-
    case "$answer" in
        n|N|no|NO|No)
            step "Stopping without installing. Make Docker work, then re-run the installer."
            return 1
            ;;
        *) return 0 ;;
    esac
}

blackbox_store_description() {
    case "$BLACKBOX_DKG_SELECTED_STORE_BACKEND" in
        native) echo "Blazegraph native verified bootstrap (DKG-managed)" ;;
        oxigraph-server) echo "Oxigraph (DKG-managed local server)" ;;
        blazegraph) echo "Blazegraph at $BLACKBOX_DKG_STORE_URL" ;;
        *) echo "${BLACKBOX_DKG_STORE_URL:-not configured}" ;;
    esac
}

provision_blackbox_store() {
    local native_helper="$(blackbox_helper blackbox-native-bootstrap.py)" native_rc=0
    "$VENV_DIR/bin/python" "$native_helper" plan "$BLACKBOX_DKG_HOME" "$BLACKBOX_DKG_CLI_DIR" \
        "$BLACKBOX_DKG_BIN" "$BLACKBOX_CONTEXT_GRAPH_ID" "$BLACKBOX_DEFAULT_CONTEXT_GRAPH_ID" \
        "$BLACKBOX_DKG_STORE_BACKEND" "$HERMES_HOME/config.yaml" || native_rc=$?
    if [ "$native_rc" -eq 0 ]; then
        BLACKBOX_DKG_SELECTED_STORE_BACKEND=native
        BLACKBOX_DKG_STORE_URL=""
        BLACKBOX_DKG_STORE_MANAGED_BY_DKG=true
        BLACKBOX_DOCKER_REQUIRED=false
        return 0
    fi
    [ "$native_rc" -eq 3 ] || return 1
    local helper="$(blackbox_helper blackbox-blazegraph.mjs)"
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
            if blackbox_dkg_control stop; then
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
    # `hermes blackbox setup` (a Hermes plugin-catalog install) needs no Docker: without it the store
    # is the DKG-managed Oxigraph, chosen here rather than asked about. The one-line installer keeps
    # asking first (founder decision 2026-10-14).
    if [ "$BLACKBOX_SETUP_ONLY" = true ] && [ "$BLACKBOX_DKG_STORE_BACKEND" = "auto" ] && ! blackbox_docker_available; then
        step "Docker is not available here, so setup uses the DKG-managed Oxigraph store (no Docker needed)."
        step "To move to Blazegraph later: install Docker, then run: hermes blackbox setup --store blazegraph"
        use_blackbox_oxigraph
        return 0
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
    local helper="$(blackbox_helper blackbox-blazegraph.mjs)"
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
    local helper="$(blackbox_helper blackbox-blazegraph.mjs)"
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
    local oxigraph_port=""
    if [ "$BLACKBOX_DKG_SELECTED_STORE_BACKEND" = "oxigraph-server" ] &&
        ! oxigraph_port="$(choose_blackbox_oxigraph_port)"; then
        err "No free port for the Oxigraph store in $BLACKBOX_OXIGRAPH_FIRST_PORT-$BLACKBOX_OXIGRAPH_LAST_PORT."
        return 1
    fi
    config_state="$("$VENV_DIR/bin/python" - "$BLACKBOX_DKG_HOME" "$BLACKBOX_DKG_PORT" "$BLACKBOX_DKG_SELECTED_STORE_BACKEND" "$BLACKBOX_DKG_STORE_URL" "$BLACKBOX_DKG_STORE_MANAGED_BY_DKG" "$BLACKBOX_CONTEXT_GRAPH_ID" "$BLACKBOX_DEFAULT_CONTEXT_GRAPH_ID" "$oxigraph_port" "${BLACKBOX_DKG_SYNC_GLOBAL_MAX_INFLIGHT:-}" "${BLACKBOX_DKG_SYNC_GLOBAL_QUEUE_LIMIT:-}" <<'PYEOF'
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
# Absent (an older caller): no graph is treated as the default, so the
# steady profile stays exactly as before.
default_context_graph_id = sys.argv[7] if len(sys.argv) > 7 else ""
# The free port the installer chose for a DKG-managed Oxigraph store; used only when the
# config names none (empty = keep the config as it is).
oxigraph_port = int(sys.argv[8]) if len(sys.argv) > 8 and sys.argv[8] else 0
# Sync slots for this machine (sync/process_limits.sync_slots): 10/20 from 8 GB, 4/8 below.
sync_inflight = int(sys.argv[9]) if len(sys.argv) > 9 and sys.argv[9] else 10
sync_queue = int(sys.argv[10]) if len(sys.argv) > 10 and sys.argv[10] else 20
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

if (store_backend == "native" and "store" in data) or (data.get("publicSnapshotBootstrap") and store_backend != "native"):
    raise SystemExit("Native bootstrap cannot convert an existing store; configuration was preserved")
data.setdefault("name", "agent-blackbox")
data["apiPort"] = api_port
data.setdefault("listenPort", 0)
data["nodeRole"] = "edge"
data.setdefault("DKG_Core_chain_cache", True)
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
# Keep native durable reconciliation resumable from the first node start. The
# foreground pinned catch-up runs before a fresh install subscribes, while an
# upgrade must not interrupt an existing checkpointed transfer.
data["syncOnConnectEnabled"] = True
data["durableSyncEnabled"] = True
# Umanitek's default graph uses the DKG 10.0.21 native profile (KI-282, the same
# profile `blackbox sync` persists in sync/managed_node.py): the node's VM
# reconciler recovers the graph and the older sync reconciler stays off so it
# does not compete with that recovery. Any other graph keeps the steady one.
native_profile = context_graph_id == default_context_graph_id
data["syncReconcilerEnabled"] = not native_profile
if native_profile:
    data["vmReconcilerEnabled"] = True
    data["vmRecoveryPrefetchEnabled"] = True
data.pop("syncAgentsMeta", None)
data["syncGlobalMaxInflight"] = sync_inflight   # verified and community data side by side, sized for the machine
data["syncGlobalQueueLimit"] = sync_queue
data.pop("restrictAutoSubscribeContextGraphs", None)
# One graph (2026-10-16): community reports live in the shared memory of the
# verified graph; ones written while this node was offline come back on connect.
data["syncSharedMemoryOnConnect"] = True
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
if store_backend == "native":
    if data.get("store"):
        raise SystemExit("Native bootstrap cannot replace an existing store")
    data["publicSnapshotBootstrap"] = json.loads((home / "public-bootstrap-plan.json").read_text())
elif store_backend == "blazegraph":
    data["store"] = {
        "backend": "blazegraph",
        "options": {"url": store_url, "managedByDkg": store_managed, "timeout": 900000},
    }
elif store_backend == "oxigraph-server":
    previous_options = store.get("options") if previous_backend == store_backend else None
    options = dict(previous_options) if isinstance(previous_options, dict) else {}
    if oxigraph_port and "port" not in options:
        options["port"] = oxigraph_port
    data["store"] = {"backend": "oxigraph-server"}
    if options:
        data["store"]["options"] = options
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
  --store MODE   Store backend: auto, blazegraph, oxigraph, or native (default: auto; fallback asks first)
  -h, --help     Show this help

Environment overrides:
  BLACKBOX_REPO_URL, BLACKBOX_REPO_BRANCH, HERMES_HOME,
  BLACKBOX_NODE_MAJOR, BLACKBOX_INSTALL_DIR, BLACKBOX_CONTEXT_GRAPH_ID,
  BLACKBOX_DKG_PORT, BLACKBOX_DKG_STORE_PORT, BLACKBOX_DKG_STORE_URL,
  BLACKBOX_DKG_HOME, BLACKBOX_DKG_CLI_DIR,
  BLACKBOX_DKG_BIN, BLACKBOX_DKG_PACKAGE, BLACKBOX_DKG_INTEGRITY,
  BLACKBOX_DKG_DAEMON_URL, BLACKBOX_DKG_CATCHUP_TIMEOUT,
  BLACKBOX_DKG_STORE_QUEUE_LIMIT, BLACKBOX_DKG_LIST_CONTEXT_GRAPHS_PROJECTION,
  BLACKBOX_CONTEXT_GRAPH_ID, BLACKBOX_GRAPH_PEER_ID,
  BLACKBOX_LLM_PROVIDER,
  BLACKBOX_LLM_MODEL, BLACKBOX_LLM_KEY_SOURCE=hermes|new, BLACKBOX_LLM_API_KEY,
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
            [ $# -ge 2 ] || { err "--store requires auto, blazegraph, oxigraph, or native"; exit 1; }
            BLACKBOX_DKG_STORE_BACKEND="$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')"
            case "$BLACKBOX_DKG_STORE_BACKEND" in
                auto|blazegraph|oxigraph|native) ;;
                *) err "Unsupported store backend: $2 (use auto, blazegraph, oxigraph, or native)"; exit 1 ;;
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

# Whether the checkout's HEAD is already part of origin/$REPO_BRANCH's history — then moving
# to the new tip loses nothing. A depth-1 clone holds none of that history, so a bounded
# stretch more is fetched to check (never the whole repository); an answer it cannot give is
# "no", which keeps the strict fast-forward and its refusal (KI-417).
BLACKBOX_HISTORY_CHECK_DEPTH=200
blackbox_head_in_branch() {
    local remote="refs/remotes/origin/$REPO_BRANCH"
    git -C "$REPO_DIR" merge-base --is-ancestor HEAD "$remote" 2>/dev/null && return 0
    [ "$(git -C "$REPO_DIR" rev-parse --is-shallow-repository 2>/dev/null)" = true ] || return 1
    git -C "$REPO_DIR" fetch -q --deepen="$BLACKBOX_HISTORY_CHECK_DEPTH" origin "$REPO_BRANCH" 2>/dev/null || return 1
    git -C "$REPO_DIR" merge-base --is-ancestor HEAD "$remote" 2>/dev/null
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
        # The clone is single-branch and shallow: its fetch rule names only the
        # branch it was cloned from, so a DIFFERENT branch would land only in
        # FETCH_HEAD and could be neither checked out nor tracked (KI-287).
        # Adding the branch to the rule (once) makes it a normal remote branch.
        local branch_rule="+refs/heads/$REPO_BRANCH:refs/remotes/origin/$REPO_BRANCH"
        if ! git -C "$REPO_DIR" config --get-all remote.origin.fetch | grep -qxF -- "$branch_rule"; then
            git -C "$REPO_DIR" remote set-branches --add origin "$REPO_BRANCH"
        fi
        # What this install last fetched: when HEAD still equals it, the install
        # holds no commits of its own (KI-294).
        local fetched_before=""
        if git -C "$REPO_DIR" rev-parse -q --verify "refs/remotes/origin/$REPO_BRANCH" >/dev/null 2>&1; then
            fetched_before="$(git -C "$REPO_DIR" rev-parse "refs/remotes/origin/$REPO_BRANCH")"
        fi
        if ! git -C "$REPO_DIR" fetch --depth 1 origin "$REPO_BRANCH"; then
            err "Could not fetch $REPO_BRANCH from $REPO_URL."
            return 1
        fi
        if ! git -C "$REPO_DIR" checkout "$REPO_BRANCH"; then
            err "Could not switch $REPO_DIR to $REPO_BRANCH (git's reason is above)."
            return 1
        fi
        # A depth-1 fetch brings the new tip WITHOUT its parent, so git cannot
        # see that it follows the installed commit and `pull --ff-only` refuses
        # every update (KI-294). When the install holds no work of its own
        # (HEAD is what it last fetched), move to the new tip; --keep still
        # refuses to overwrite uncommitted changes. Otherwise keep the strict
        # fast-forward, which stops with git's reason instead of losing work.
        # HEAD can also be an older commit of the branch that this install did not fetch last
        # (the checkout was moved outside the installer): that is still no work of its own, but
        # a depth-1 clone cannot show it (KI-417) — blackbox_head_in_branch fetches a bounded
        # stretch of history to check.
        if { [ -n "$fetched_before" ] && [ "$(git -C "$REPO_DIR" rev-parse HEAD)" = "$fetched_before" ]; } ||
            blackbox_head_in_branch; then
            if ! git -C "$REPO_DIR" reset -q --keep "refs/remotes/origin/$REPO_BRANCH"; then
                err "Could not update $REPO_DIR to origin/$REPO_BRANCH: it has uncommitted changes (git's reason is above)."
                return 1
            fi
        elif ! git -C "$REPO_DIR" pull --ff-only origin "$REPO_BRANCH"; then
            err "Could not fast-forward $REPO_DIR to origin/$REPO_BRANCH: it holds commits that are not on that branch (git's reason is above):"
            git -C "$REPO_DIR" log --oneline -3 "refs/remotes/origin/$REPO_BRANCH..HEAD" >&2
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
        # Nothing to install by hand: Hermes's own setup (setup-hermes.sh, run below) downloads a
        # pinned, sha256-verified uv and has it install Python. Stopping here sent a user to
        # `brew install python@3.12` for a step the installer does itself (2026-10-29). Only the
        # old-Hermes fallback (minimal_python_env) still needs a Python or uv, and says so there.
        step "No Python 3.11–3.13 or uv yet — Hermes's setup will download a pinned, checksum-verified uv and Python."
        PY=""
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
    # nvm is the portable path on both macOS and Linux and needs no sudo.
    export NVM_DIR="${NVM_DIR:-$HOME/.nvm}"
    # A Node that nvm installed on an earlier run is not on a fresh shell's PATH; use it
    # rather than announcing and running a second install (KI-418).
    if [ -s "$NVM_DIR/nvm.sh" ]; then
        # shellcheck disable=SC1091
        . "$NVM_DIR/nvm.sh" >/dev/null 2>&1 || true
        if nvm use "$NODE_MAJOR" >/dev/null 2>&1 && _node_ok; then
            ok "Node.js $(node -v) (installed earlier with nvm) + npm $(npm -v 2>/dev/null || echo '?')"
            HAS_NODE=true
            return 0
        fi
    fi
    warn "Node.js $NODE_MAJOR+ not found — installing it automatically (via nvm)…"
    if [ ! -s "$NVM_DIR/nvm.sh" ]; then
        step "Installing nvm into $NVM_DIR …"
        if ! install_nvm_verified; then
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

# The sha256 of a file, by whichever tool this system has (macOS: shasum; Linux: sha256sum).
_sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d' ' -f1
    else
        return 1
    fi
}

# Download nvm's installer to a file, check it against NVM_INSTALL_SHA256, and only then run it.
# Fails (non-zero) without running anything when the download fails, no sha256 tool exists, or
# the bytes differ from the pin — a mismatch is said plainly, it is never retried or skipped.
install_nvm_verified() {
    local script actual
    script="$(mktemp "${TMPDIR:-/tmp}/blackbox-nvm-install.XXXXXX")" || return 1
    if ! curl -fsSL "https://raw.githubusercontent.com/nvm-sh/nvm/${NVM_INSTALL_VERSION_PIN}/install.sh" -o "$script"; then
        rm -f "$script"
        return 1
    fi
    actual="$(_sha256_of "$script")" || { warn "No sha256 tool (sha256sum or shasum) to check nvm's installer; not running it."; rm -f "$script"; return 1; }
    if [ "$actual" != "$NVM_INSTALL_SHA256" ]; then
        warn "nvm's installer did not match its pinned checksum (expected $NVM_INSTALL_SHA256, got $actual); not running it."
        rm -f "$script"
        return 1
    fi
    local status=0
    bash "$script" >/dev/null 2>&1 || status=$?
    rm -f "$script"
    return "$status"
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
    # Fast idempotent re-run for an OLDER Hermes checkout: if a working venv/ exists,
    # don't let its setup-hermes.sh (which `rm -rf venv`s on every run) rebuild it.
    # Hermes 0.21.7+ (pm, scripts/run-in-hermes-env) never takes this shortcut: its
    # setup is itself hash-checked and quick when nothing changed, and a kept venv/
    # never learns the release's new dependencies or top-level modules — an upgraded
    # bench could not import hermes_yaml from outside the checkout.
    if [ ! -x "$REPO_DIR/scripts/run-in-hermes-env" ] && [ -x "$VENV_DIR/bin/hermes" ] \
        && "$VENV_DIR/bin/python" -c "import hermes_cli" >/dev/null 2>&1; then
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
            use_hermes_selected_venv
        elif [ -x "$REPO_DIR/scripts/run-in-hermes-env" ]; then
            # Hermes 0.21.7+ (pm): the old minimal venv/ would be built for the wrong
            # release, and every later step (attach, reviewer, sync) then fails. Its setup
            # has failed transiently (launcher publication racing a restarting dashboard),
            # so try once more, then stop with the reason rather than continue half-built.
            warn "setup-hermes.sh did not complete cleanly — trying once more."
            if HERMES_EMBEDDED_INSTALL=1 bash "$REPO_DIR/setup-hermes.sh"; then
                ok "Base environment ready via setup-hermes.sh (second try)"
                use_hermes_selected_venv
            else
                err "Hermes's own setup (setup-hermes.sh) failed twice; Blackbox was not installed."
                step "Fix the error above, then re-run this installer."
                exit 1
            fi
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

# Hermes 0.21.7+ builds its environment with pm OUTSIDE the checkout
# ($HERMES_HOME/installs/<install>/environments/<generation>/venv) instead of
# $REPO_DIR/venv. Ask Hermes which generation is selected, through its own
# runner (scripts/run-in-hermes-env + pm.environments.selected_venv), and point
# VENV_DIR there. Older checkouts have no runner and keep $REPO_DIR/venv.
use_hermes_selected_venv() {
    [ -x "$REPO_DIR/scripts/run-in-hermes-env" ] || return 0
    local selected
    selected="$(cd "$REPO_DIR" && scripts/run-in-hermes-env python3 -c \
        'from pathlib import Path; from pm.environments import selected_venv; print(selected_venv(Path(".").resolve()))' \
        2>/dev/null | tail -n 1)"
    if [ -n "$selected" ] && [ -x "$selected/bin/python" ]; then
        VENV_DIR="$selected"
        step "Hermes environment: $VENV_DIR"
    else
        warn "Could not ask Hermes where its environment is; assuming $VENV_DIR"
    fi
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
    local installed=false uv_bin
    if uv_bin="$(find_uv)"; then
        ( cd "$REPO_DIR" && VIRTUAL_ENV="$VENV_DIR" "$uv_bin" pip install -e ".[web]" >/dev/null 2>&1 ) && installed=true
    fi
    if [ "$installed" != true ] && ensure_venv_pip "$VENV_DIR"; then
        ( cd "$REPO_DIR" && "$VENV_DIR/bin/python" -m pip install -e ".[web]" >/dev/null 2>&1 ) && installed=true
    fi
    if [ "$installed" = true ] && "$VENV_DIR/bin/python" -c "import fastapi, uvicorn" >/dev/null 2>&1; then
        ok "Dashboard extras installed"
    else
        warn "Dashboard extras unavailable — 'blackbox dashboard' may not start. Retry: (cd $REPO_DIR && uv pip install -e '.[web]')"
    fi
}

# uv as setup-hermes.sh installs it: on PATH, or in ~/.local/bin / ~/.cargo/bin,
# which the installer's own PATH may not include yet (KI-042). Prints the path.
find_uv() {
    if command -v uv >/dev/null 2>&1; then command -v uv; return 0; fi
    local candidate
    for candidate in "$HOME/.local/bin/uv" "$HOME/.cargo/bin/uv"; do
        if [ -x "$candidate" ]; then printf '%s\n' "$candidate"; return 0; fi
    done
    return 1
}

# A uv-built venv ships no pip, so `python -m pip` fails with "No module named
# pip" and the install stops (KI-042, every fresh Ubuntu 24.04 bench). Bootstrap
# pip from the interpreter's own bundled copy (offline) before using it.
ensure_venv_pip() {
    local venv="$1"
    if "$venv/bin/python" -m pip --version >/dev/null 2>&1; then return 0; fi
    step "This environment has no pip yet; bootstrapping it (ensurepip) ..."
    "$venv/bin/python" -m ensurepip --upgrade >/dev/null
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
            err "Need Python 3.11–3.13 or uv to build the environment (this Hermes has no setup that fetches them)."
            case "$OS" in
                macos) step "Easiest fix: brew install uv   (or: brew install python@3.12)" ;;
                linux) step "Easiest fix: curl -LsSf https://astral.sh/uv/install.sh | sh   (or: apt install python3.12 python3.12-venv)" ;;
            esac
            exit 1
        fi
    else
        step "Reusing existing venv at $VENV_DIR"
    fi
    step "Installing Hermes + Agent Blackbox (web extras, editable) ..."
    # A uv-built venv ships no pip, so install with uv when it's available.
    local uv_bin
    if uv_bin="$(find_uv)"; then
        ( cd "$REPO_DIR" && VIRTUAL_ENV="$VENV_DIR" "$uv_bin" pip install -e ".[web]" )
    else
        ensure_venv_pip "$VENV_DIR"
        "$VENV_DIR/bin/python" -m pip install --upgrade pip >/dev/null
        ( cd "$REPO_DIR" && "$VENV_DIR/bin/python" -m pip install -e ".[web]" )
    fi
    ok "Blackbox installed (editable, with dashboard extras)"
}

# ── hermes + blackbox commands on PATH (~/.local/bin) ────────────────────────
# The `blackbox` command: a small script beside `hermes` that runs `hermes blackbox`.
# An existing `blackbox` that this installer did not write is left alone.
install_blackbox_shim() {
    local link_dir="$1"
    local blackbox_bin="$link_dir/blackbox"
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
}

# Setup-only mode: use the Hermes the caller runs in (HERMES_BIN, VENV_DIR) and put
# the `blackbox` command beside the user's `hermes` launcher. The user's `hermes` is never replaced.
# Hermes runs `hermes blackbox setup` with its own internal bin folder first on PATH, so
# `command -v hermes` there finds that inner binary, in a folder the user's shell never
# searches. Hermes publishes the user's launcher to ~/.local/bin, so that folder wins.
use_running_hermes() {
    heading "Using your Hermes"
    if [ ! -x "${HERMES_BIN:-}" ] || [ ! -x "${VENV_DIR:-}/bin/python" ]; then
        err "Setup-only mode needs the Hermes it runs in (HERMES_BIN, VENV_DIR); run it as: hermes blackbox setup"
        exit 1
    fi
    ok "Hermes: $HERMES_BIN"
    local on_path link_dir
    if [ -x "$HOME/.local/bin/hermes" ]; then
        link_dir="$HOME/.local/bin"
    else
        on_path="$(command -v hermes 2>/dev/null || true)"
        link_dir="$(dirname "${on_path:-$HERMES_BIN}")"
    fi
    if [ -w "$link_dir" ]; then
        install_blackbox_shim "$link_dir"
    else
        warn "Cannot write $link_dir: the blackbox command was not added; use: hermes blackbox"
    fi
    export PATH="$VENV_DIR/bin:$PATH"
}

# Earlier runs of this installer linked ~/.local/bin/hermes to a Hermes Python environment.
# Hermes 0.21.7+ publishes its own launcher there and will not replace a link that points
# outside its checkout ("launcher publication failed"), so every re-run stopped in Hermes's
# setup. Such a link (into some venv/bin/hermes) is removed before that setup runs; any other
# file there is left alone.
release_old_hermes_link() {
    local link="$HOME/.local/bin/hermes" target
    [ -L "$link" ] || return 0
    target="$(readlink "$link")"
    case "$target" in
        */venv/bin/hermes)
            rm -f "$link"
            step "Removed the hermes link an earlier Blackbox install made ($target); Hermes publishes its own."
            ;;
    esac
}

link_hermes() {
    local link_dir="$HOME/.local/bin"
    mkdir -p "$link_dir"
    if [ -x "$HERMES_BIN" ]; then
        if [ -x "$REPO_DIR/scripts/run-in-hermes-env" ]; then
            ok "hermes → $link_dir/hermes (Hermes's own launcher)"
        else   # an older Hermes publishes no launcher: link it
            ln -sf "$HERMES_BIN" "$link_dir/hermes"
            ok "Linked hermes → $link_dir/hermes"
        fi
        install_blackbox_shim "$link_dir"
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
# Download BLACKBOX_DKG_PACKAGE as a tarball and check ITS sha512 against the pin — the file
# npm will install, not the registry's claim about it (a registry serving a different file
# would also report a matching hash). Prints the tarball path (so its warnings go to stderr);
# the caller installs and removes it.
fetch_pinned_dkg_tarball() {
    local dir="" file="" actual=""
    dir="$(mktemp -d "${TMPDIR:-/tmp}/blackbox-dkg-pack.XXXXXX")" || return 1
    if ! file="$(npm pack "$BLACKBOX_DKG_PACKAGE" --pack-destination "$dir" --silent 2>/dev/null | tail -n 1)" ||
        [ -z "$file" ] || [ ! -f "$dir/$file" ]; then
        rm -rf "$dir"
        warn "Could not download $BLACKBOX_DKG_PACKAGE from the npm registry." >&2
        return 1
    fi
    actual="$(node -e 'const c=require("crypto"),f=require("fs");console.log("sha512-"+c.createHash("sha512").update(f.readFileSync(process.argv[1])).digest("base64"))' "$dir/$file" 2>/dev/null)"
    if [ "$actual" != "$BLACKBOX_DKG_INTEGRITY" ]; then
        rm -rf "$dir"
        warn "The downloaded $BLACKBOX_DKG_PACKAGE (${actual:-no checksum}) is not the one this Blackbox release pins; it was not installed." >&2
        return 1
    fi
    printf '%s\n' "$dir/$file"
}

install_blackbox_dkg_package() {
    if [ -f "$BLACKBOX_DKG_HOME/config.json" ]; then
        local retained_rc=0
        "$VENV_DIR/bin/python" "$(blackbox_helper blackbox-native-bootstrap.py)" retain "$BLACKBOX_DKG_HOME" "$BLACKBOX_DKG_BIN" || retained_rc=$?
        [ "$retained_rc" -ne 0 ] || { ok "Preserved the native journal's compatible DKG runtime"; return 0; }
        [ "$retained_rc" -eq 3 ] || return 1
    fi
    local backup_dir=""
    local package_json="$BLACKBOX_DKG_CLI_DIR/node_modules/@origintrail-official/dkg/package.json"
    local installed_version=""
    local npm_log="$HERMES_HOME/logs/blackbox-npm-install.log"

    if ! command -v npm >/dev/null 2>&1; then
        warn "npm is required to install the published OriginTrail DKG package."
        return 1
    fi

    # The package is downloaded first and the tarball's own sha512 compared with the pin;
    # only a tarball that matches is handed to npm install. No pin = not installed.
    local tarball=""
    case "$BLACKBOX_DKG_INTEGRITY" in
        unpinned)
            warn "BLACKBOX_DKG_INTEGRITY=unpinned: $BLACKBOX_DKG_PACKAGE is installed without a checksum check." ;;
        "")
            warn "No checksum is pinned for $BLACKBOX_DKG_PACKAGE; it was not installed. Set BLACKBOX_DKG_INTEGRITY to its sha512 (npm view $BLACKBOX_DKG_PACKAGE dist.integrity), or BLACKBOX_DKG_INTEGRITY=unpinned to skip the check knowingly."
            return 1 ;;
        *)
            tarball="$(fetch_pinned_dkg_tarball)" || return 1
            ok "DKG package checksum verified ($BLACKBOX_DKG_PACKAGE)" ;;
    esac

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
    # npm 12's allow list lives in the project's package.json: merge ours in (a package an
    # operator set to false stays denied); older npm ignores the field.
    node -e '
const fs = require("fs"); const file = process.argv[1];
let pkg = {}; try { pkg = JSON.parse(fs.readFileSync(file, "utf8")); } catch (e) {}
pkg.allowScripts = Object.assign({}, pkg.allowScripts);
for (const name of process.argv.slice(2)) if (pkg.allowScripts[name] !== false) pkg.allowScripts[name] = true;
fs.writeFileSync(file, JSON.stringify(pkg, null, 2) + "\n");
' "$BLACKBOX_DKG_CLI_DIR/package.json" "${BLACKBOX_DKG_ALLOW_SCRIPTS[@]}"
    local install_spec="$BLACKBOX_DKG_PACKAGE"
    [ -n "$tarball" ] && install_spec="$tarball"
    npm install --prefix "$BLACKBOX_DKG_CLI_DIR" --prefer-online "$install_spec" >"$npm_log" 2>&1
    local npm_status=$?
    [ -n "$tarball" ] && rm -rf "$(dirname "$tarball")"
    if [ "$npm_status" -ne 0 ]; then
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

    # A newer DKG release may need an install script this list does not name yet: npm only warns,
    # and the node would crash on start. Stop here and say which package, instead.
    if grep -q "had install scripts blocked" "$npm_log"; then
        warn "npm blocked install scripts the DKG node needs: $(grep -A4 'had install scripts blocked' "$npm_log" | grep -oE '^npm warn install-scripts +[^ ]+@[^ ]+' | awk '{print $NF}' | tr '\n' ' ')"
        step "npm log: $npm_log"
        return 1
    fi

    # The native SQLite module must load with the Node that will run the node. npm runs no
    # install script for a package it already has, so a folder an earlier run left half-built
    # (an npm that blocked the build, an interrupted install) is rebuilt here, then checked again.
    local sqlite_dir="$BLACKBOX_DKG_CLI_DIR/node_modules/better-sqlite3"
    local sqlite_probe='const DB = require(process.argv[1]); new DB(":memory:").close();'
    if [ -d "$sqlite_dir" ] && ! node -e "$sqlite_probe" "$sqlite_dir" >/dev/null 2>&1; then
        step "Building the DKG node's SQLite module for Node $(node -v) ..."
        if ! npm rebuild --prefix "$BLACKBOX_DKG_CLI_DIR" better-sqlite3 >>"$npm_log" 2>&1 ||
            ! node -e "$sqlite_probe" "$sqlite_dir" >/dev/null 2>&1; then
            warn "The DKG node's SQLite module does not load with Node $(node -v) and could not be rebuilt."
            step "npm log: $npm_log"
            return 1
        fi
        ok "SQLite module built for Node $(node -v)"
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
    if ! "$VENV_DIR/bin/python" "${BLACKBOX_PLUGIN_DIR:-$REPO_DIR/plugins/blackbox}/kernel/dkg_version.py" "$installed_version"; then
        warn "DKG $installed_version is too old for direct verified Blackbox recovery; version 10.0.9+ is required."
        return 1
    fi
    step "Using published upstream DKG $installed_version unchanged."
    ok "Published DKG npm package ready (${installed_version:-installed})"
}

install_dkg() {
    heading "Setting up the OriginTrail DKG node"
    if [ "$SKIP_DKG" = true ]; then
        # Asked for explicitly: an install without the node is what the operator chose, so it
        # is not "incomplete" and is kept (the summary still says the threat graph is not set up).
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
        blackbox_dkg_control restart || true
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
    blackbox_dkg_control start || true
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

# The first verified threat-graph sync is NOT part of the install (Amos, 2026-10-17): it
# takes about half an hour and depends on the network, so waiting for it would turn a slow
# connection into a failed install — and, all or nothing, roll back a working one. The
# dashboard's own sync worker (the dashboard is started next, by main) starts it about ten
# seconds after the dashboard starts, runs the same controlled `blackbox sync --wait
# --require-rules` the installer used to, keeps the graph current, and shows the progress.
sync_ruleset() {
    [ "${DKG_READY:-false}" = true ] || return 0
    heading "Threat graph"
    case "$BLACKBOX_AUTO_DASHBOARD" in
        0|false|never|no)
            step "The dashboard is off, so nothing syncs the threat graph yet. Start the first sync with:"
            echo "    blackbox sync --wait --require-rules"
            return 0
            ;;
    esac
    ok "The first threat-graph sync runs in the background (about 30 minutes)"
    step "Follow it on the dashboard: http://127.0.0.1:${BLACKBOX_DASHBOARD_PORT:-9700}"
    ok "DKG native reconciliation enabled; one in-flight slot; zero queue"
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
    echo "      NODE_OPTIONS=\"$BLACKBOX_DKG_NODE_OPTIONS\" DKG_HOME=\"\$BLACKBOX_DKG_HOME\" DKG_SYNC_GLOBAL_MAX_INFLIGHT=\"$BLACKBOX_DKG_SYNC_GLOBAL_MAX_INFLIGHT\" DKG_STORE_QUEUE_LIMIT=\"$BLACKBOX_DKG_STORE_QUEUE_LIMIT\" DKG_EXACT_BATCH_STREAM_ENABLED=\"$BLACKBOX_DKG_EXACT_BATCH_STREAM_ENABLED\" DKG_VM_RECOVERY_PREFETCH_ENABLED=\"$BLACKBOX_DKG_VM_RECOVERY_PREFETCH_ENABLED\" \"\$BLACKBOX_DKG_BIN\" start"
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
    if "$VENV_DIR/bin/python" - "$HERMES_HOME/config.yaml" "$DKG_NETWORK" "$BLACKBOX_CONTEXT_GRAPH_ID" "$BLACKBOX_GRAPH_PEER_ID" "$BLACKBOX_DKG_DAEMON_URL" "$BLACKBOX_DKG_HOME" "$BLACKBOX_DKG_BIN" "${BLACKBOX_PLUGIN_DIR:-$REPO_DIR}" <<'PYEOF'
import sys, os
cfg_path, network, context_graph_id, graph_peer_id, dkg_url, dkg_home, dkg_bin = sys.argv[1:8]
repo_dir = (sys.argv[8:9] + [""])[0]   # optional (older callers pass seven arguments): the checkout
try:
    try:
        import hermes_yaml as yaml  # Hermes 0.21.7+: YAML through ruamel (PyYAML left the host)
    except ImportError:
        import yaml  # older Hermes: PyYAML
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
no_explicit_snapshot_profile = "snapshot_sync" not in blackbox
# Idempotent for custom user edits, but migrate deprecated defaults that point
# at the user's shared DKG install or a retired graph.
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
# One graph (2026-10-16): community reports live in the verified graph's shared
# memory, so the separate community graph and its owner's peer id are dropped.
for key in ("community_graph_id", "community_graph_peer_id"):
    if blackbox.pop(key, None) is not None:
        added.append(f"{key} (removed)")
defaults = {
    "mode": "audit",
    "context_graph_id": context_graph_id,
    "graph_peer_id": graph_peer_id,
    "sync_interval": 3600,
    # Community sharing is OPT-IN (2026-10-16): off until the operator runs
    # `blackbox report --enable-sharing` or uses the dashboard toggle, which also
    # record the acceptance. The installer never records it. The daily cap is the
    # plugin's default bound (100 since 2026-10-12; 20 before): 0 used to mean
    # NO cap, and the plugin no longer accepts it (Refine R1).
    "report": False,
    "daily_report_limit": 100,
    "report_min_severity": "high",
    "block_severity": "critical",
    "dashboard_port": 9700,
    # Optional LLM reviewer — off until `blackbox setup-llm` fills it in.
    "llm": {"enabled": False, "provider": "", "model": "", "api_key": ""},
}
# Keep community protection and ordinary sync unless the installed plugin can
# admit a snapshot attempt; DKG authenticates cores before accepting any data.
if no_explicit_snapshot_profile:
    try:
        import runpy
        from pathlib import Path
        checkout = Path(repo_dir)
        plugin = checkout if (checkout / "plugin.yaml").is_file() else checkout / "plugins" / "blackbox"
        defaults.update(runpy.run_path(str(plugin / "setup" / "sync_defaults.py"))["defaults"](
            {**defaults, **blackbox}, os.environ.get("BLACKBOX_DKG_NETWORK", "mainnet-base")))
    except Exception:
        print("  Keeping ordinary sync: the compatible Core-cache default is not available.")
for k, v in defaults.items():
    if k not in blackbox:
        blackbox[k] = v
        added.append(k)
# KI-184: an opt-in backed by a sharing-consent record (R13) SURVIVES every
# re-run and upgrade. Only a pre-release opt-in — `report: true` with no consent
# record in force — is migrated off, because sharing without consent is invalid
# anyway. The product's own consent code decides (one implementation); if it
# cannot be imported the answer is "no consent" (fail closed = sharing off).
def _consent_in_force(checkout):
    try:
        if checkout and os.path.isfile(os.path.join(checkout, "plugin.yaml")):
            # Setup-only mode passes the plugin folder itself (a plugin-catalog install has no
            # checkout). Stock Hermes has its own `plugins` package, which would shadow ours, so
            # the plugin is loaded from its folder under a private name.
            import importlib, importlib.util
            spec = importlib.util.spec_from_file_location(
                "_installed_blackbox", os.path.join(checkout, "__init__.py"), submodule_search_locations=[checkout])
            package = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = package
            spec.loader.exec_module(package)
            return bool(importlib.import_module("_installed_blackbox.community.consent").in_force())
        if checkout:
            sys.path.insert(0, checkout)
        from plugins.blackbox.community import consent
        return bool(consent.in_force())
    except Exception:
        return False
if blackbox.get("report") is True and not _consent_in_force(repo_dir):
    blackbox["report"] = False
    added.append("report")
# Sharing is opt-in again (2026-10-16). The 2026-10-12 installers turned sharing
# on by default and wrote a `sharing_default` marker; the KI-184 rule above has
# already turned off every such install that never recorded an acceptance, and
# the marker now means nothing, so it is removed. An operator who opted in keeps
# sharing. The installer never turns sharing on.
if blackbox.pop("sharing_default", None) is not None:
    added.append("sharing_default (removed)")
# `daily_report_limit: 0` was the pre-R1 "no cap" and the plugin refuses it;
# 20 is what earlier installers wrote as the default (raised to 100 on
# 2026-10-12), so it moves with the default. Any other operator-chosen cap is kept.
if blackbox.get("daily_report_limit") in (0, "0", 20, "20"):
    blackbox["daily_report_limit"] = 100
    added.append("daily_report_limit")
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
    try:
        import hermes_yaml as yaml  # Hermes 0.21.7+: YAML through ruamel (PyYAML left the host)
    except ImportError:
        import yaml  # older Hermes: PyYAML
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

# Writes plugins.entries.blackbox.mode and prints the mode now in force. $1 is the
# requested mode ("audit" or "block"); "" keeps the mode already saved (a first
# install, with nothing saved, gets audit).
write_blackbox_mode() {
    local mode="$1"
    "$VENV_DIR/bin/python" - "$HERMES_HOME/config.yaml" "$mode" <<'PYEOF'
import sys, os
cfg_path, mode = sys.argv[1], sys.argv[2]
try:
    try:
        import hermes_yaml as yaml  # Hermes 0.21.7+: YAML through ruamel (PyYAML left the host)
    except ImportError:
        import yaml  # older Hermes: PyYAML
except Exception:
    print("  (no YAML library — could not save protection mode)", file=sys.stderr)
    sys.exit(1)
if mode not in ("audit", "block", ""):
    sys.exit(1)
os.makedirs(os.path.dirname(cfg_path), exist_ok=True)
data = {}
if os.path.exists(cfg_path):
    with open(cfg_path, encoding="utf-8-sig") as f:
        data = yaml.safe_load(f) or {}
blackbox = data.setdefault("plugins", {}).setdefault("entries", {}).setdefault("blackbox", {})
saved = str(blackbox.get("mode") or "").lower()
blackbox["mode"] = mode or (saved if saved in ("audit", "block") else "audit")
blackbox.setdefault("block_severity", "critical")
with open(cfg_path, "w", encoding="utf-8") as f:
    yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)
print(blackbox["mode"])
PYEOF
}

configure_blackbox_mode() {
    heading "Blackbox mode"
    # An explicit BLACKBOX_MODE wins. Otherwise a re-run keeps the mode the operator
    # saved — an upgrade must never turn blocking off — and a first install starts in
    # audit. (Every re-run used to write audit, so upgrading switched block off.)
    local requested
    requested="$(printf '%s' "${BLACKBOX_MODE:-}" | tr '[:upper:]' '[:lower:]')"
    case "$requested" in audit|block) ;; *) requested="" ;; esac
    BLACKBOX_SELECTED_MODE="$(write_blackbox_mode "$requested")"
    if [ -n "$BLACKBOX_SELECTED_MODE" ]; then
        ok "Blackbox runs in $BLACKBOX_SELECTED_MODE mode"
    else
        BLACKBOX_SELECTED_MODE="audit"
        warn "Could not save Blackbox mode. Set plugins.entries.blackbox.mode in config.yaml."
    fi
}

# ── Protect agents (best-effort, non-fatal) ─────────────────────────────────
# Blackbox protects the Hermes home this installer set up ($HERMES_HOME). Every
# other Hermes profile or OpenClaw workspace is its own trust and credential
# boundary, so it is attached only when the operator says so: `blackbox attach`
# lists the ones not yet protected and asks [y/N] on the terminal (/dev/tty, so
# it works under `curl | bash`); with no terminal it attaches none of them.
# Scripted installs that want every agent protected set BLACKBOX_ATTACH_ALL=1.
attach_all_agents() {
    heading "Protecting your agents"
    step "Protecting the Hermes home at $HERMES_HOME (blackbox attach) ..."
    if "$HERMES_BIN" blackbox attach "$HERMES_HOME"; then
        ok "Blackbox protects $HERMES_HOME"
    else
        warn "Could not protect $HERMES_HOME (this is non-fatal)."
        step "Re-run anytime with:  blackbox attach $HERMES_HOME"
    fi
    case "$(printf '%s' "${BLACKBOX_ATTACH_ALL:-}" | tr '[:upper:]' '[:lower:]')" in
        1|true|yes)
            step "BLACKBOX_ATTACH_ALL is set: protecting every Hermes home + OpenClaw workspace found ..."
            "$HERMES_BIN" blackbox attach --all || warn "Could not protect every agent (this is non-fatal)."
            return 0 ;;
    esac
    step "Looking for other agents on this machine (Hermes profiles, OpenClaw workspaces) ..."
    "$HERMES_BIN" blackbox attach || step "Protect others later with:  blackbox attach <home>   (or --all)"
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
        # The key travels in the environment: a command-line argument is visible
        # to every program on the machine (ps) while setup-llm runs (KI-371).
        args+=(--key-source new)
    elif [ -n "$BLACKBOX_LLM_KEY_SOURCE" ]; then
        args+=(--key-source "$BLACKBOX_LLM_KEY_SOURCE")
    fi

    if [ "${#args[@]}" -gt 0 ]; then
        step "Using BLACKBOX_LLM_* settings."
        if BLACKBOX_LLM_API_KEY="$BLACKBOX_LLM_API_KEY" "$HERMES_BIN" blackbox setup-llm "${args[@]}"; then
            ok "LLM reviewer configured"
        else
            warn "LLM reviewer setup failed from BLACKBOX_LLM_* values."
            step "Check BLACKBOX_LLM_PROVIDER, BLACKBOX_LLM_MODEL, and BLACKBOX_LLM_API_KEY, then re-run."
        fi
        return 0
    fi

    step "Trying existing Blackbox or Hermes LLM config."
    if "$HERMES_BIN" blackbox setup-llm --auto; then
        ok "LLM reviewer ready"
    else
        step "LLM reviewer not configured; this is optional and can be set up later:"
        step "  blackbox setup-llm"
    fi
}

# ── The dashboard's supervisor (KI-455) ─────────────────────────────────────
# Once a service runs the dashboard (systemd unit, or a LOADED LaunchAgent), it is started
# and restarted only through that service (LES-063). An update once launched its own copy
# beside the unit: the copy stopped the unit's dashboard, `enable --now` then started the
# unit again, the unit's dashboard replaced the copy, and the final check caught it mid-start
# and rolled a healthy update back (bb-install-1022b, 2026-10-27).
BLACKBOX_DASHBOARD_LAUNCHD_LABEL=ai.umanitek.blackbox-dashboard
# A dashboard (re)start takes 5-15 s, longer on a 2-CPU machine while the node syncs: the
# final check waits this long for an answer before calling it broken (LES-011 — still
# starting is not broken).
BLACKBOX_DASHBOARD_ANSWER_WAIT_SECONDS="${BLACKBOX_DASHBOARD_ANSWER_WAIT_SECONDS:-60}"
# Set by start_dashboard when the service must restart the dashboard (new code, or not
# answering); register_dashboard_service does it once the unit itself is current.
BLACKBOX_DASHBOARD_RESTART_PENDING=false

# Prints who runs the dashboard: systemd | systemd-user | launchd, or nothing (no service:
# the installer launches it). A LaunchAgent counts only while loaded — one registered "for
# the next login" does not run the dashboard yet.
blackbox_dashboard_supervisor() {
    if command -v systemctl >/dev/null 2>&1; then
        if [ -f "$BLACKBOX_SYSTEMD_DIR/blackbox-dashboard.service" ] &&
            systemctl is-enabled --quiet blackbox-dashboard 2>/dev/null; then
            echo systemd
            return 0
        fi
        if [ -f "$HOME/.config/systemd/user/blackbox-dashboard.service" ] &&
            systemctl --user is-enabled --quiet blackbox-dashboard 2>/dev/null; then
            echo systemd-user
            return 0
        fi
    fi
    if [ "$(uname -s 2>/dev/null)" = Darwin ] && command -v launchctl >/dev/null 2>&1 &&
        launchctl print "gui/$(id -u)/$BLACKBOX_DASHBOARD_LAUNCHD_LABEL" >/dev/null 2>&1; then
        echo launchd
    fi
    return 0
}

# `blackbox_dashboard_control restart|reload <supervisor>` — restart the dashboard through its
# service; `reload` first makes the service re-read its (rewritten or restored) definition.
blackbox_dashboard_control() {
    local action="$1" supervisor="$2" target
    local -a systemctl_cmd=(systemctl)
    case "$supervisor" in
        systemd | systemd-user)
            [ "$supervisor" = systemd-user ] && systemctl_cmd+=(--user)
            if [ "$action" = reload ]; then "${systemctl_cmd[@]}" daemon-reload || return 1; fi
            "${systemctl_cmd[@]}" restart blackbox-dashboard
            ;;
        launchd)
            target="gui/$(id -u)/$BLACKBOX_DASHBOARD_LAUNCHD_LABEL"
            if [ "$action" = reload ]; then
                launchctl bootout "$target" 2>/dev/null || true
                launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/$BLACKBOX_DASHBOARD_LAUNCHD_LABEL.plist"
            else
                launchctl kickstart -k "$target"
            fi
            ;;
        *) return 1 ;;
    esac
}

# Whether the dashboard at URL answers within WAIT seconds (polled every 2 s).
blackbox_dashboard_answers_within() {
    local url="$1" wait="$2" waited=0
    while true; do
        curl -fsS --max-time 10 "$url" >/dev/null 2>&1 && return 0
        [ "$waited" -ge "$wait" ] && return 1
        sleep 2
        waited=$((waited + 2))
    done
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

    # The code revision the running dashboard was started from (KI-300): a
    # dashboard keeps the code it loaded, so after an update the installer must
    # launch it again — `blackbox dashboard` replaces the one on its port.
    local revision_file="$HERMES_HOME/blackbox/.dashboard-revision"
    local revision="${BLACKBOX_REVISION:-}"
    if [ -z "$revision" ] && [ -n "$REPO_DIR" ] && git -C "$REPO_DIR" rev-parse -q --verify HEAD >/dev/null 2>&1; then
        revision="$(git -C "$REPO_DIR" rev-parse HEAD)"
    fi
    local supervisor
    supervisor="$(blackbox_dashboard_supervisor)"
    if command -v curl >/dev/null 2>&1 && curl -fsS "$url/" >/dev/null 2>&1; then
        if [ -z "$revision" ] || [ "$(cat "$revision_file" 2>/dev/null)" = "$revision" ]; then
            ok "Dashboard already running at $url"
            return 0
        fi
        step "Blackbox was updated: restarting the dashboard so the new code runs"
    fi

    # A service runs the dashboard: it restarts it once its own definition is current
    # (register_dashboard_service) — never a second copy launched beside it (KI-455).
    if [ -n "$supervisor" ]; then
        step "The dashboard runs under its $supervisor service; it is restarted through it below."
        BLACKBOX_DASHBOARD_RESTART_PENDING=true
        if [ -n "$revision" ]; then
            mkdir -p "$(dirname "$revision_file")" && printf '%s\n' "$revision" > "$revision_file"
        fi
        return 0
    fi

    step "Launching: blackbox dashboard"
    run_detached "$log_file" "$HERMES_BIN" blackbox dashboard
    sleep 2
    if [ -n "$revision" ]; then
        mkdir -p "$(dirname "$revision_file")" && printf '%s\n' "$revision" > "$revision_file"
    fi

    if command -v curl >/dev/null 2>&1 && ! curl -fsS "$url/" >/dev/null 2>&1; then
        warn "Dashboard process started, but $url did not respond yet."
        step "Log: $log_file"
        return 0
    fi
    ok "Dashboard running at $url"
    step "Log: $log_file"
}

# Community sharing is OPT-IN (2026-10-16): every summary says it is off unless
# the operator turned it on, what would be sent, and the one command that turns it on.
print_sharing_notice() {
    cat <<'EOF'

  Community sharing is OFF unless you turn it on (it is opt-in). When on, and
  your agent meets a threat already listed in the verified threat graph, this
  node shares a privacy-safe statement (the threat's identifier and type, the
  tool that met it, blocked or flagged, and what the threat targets; never
  prompts, commands, file paths or files) with the Blackbox community, in that
  graph's shared memory, where Umanitek's curators review it.
  Turn it on (this records your agreement to the reporter terms):

      blackbox report --enable-sharing         (or the dashboard's sharing toggle)
EOF
}

# ── Guided next steps (short — everything above already ran) ─────────────────
# Printed only after the final check passed and the install was kept: an install that is not
# complete never reaches here (it is rolled back), so there is one outcome to describe.
next_steps() {
    local docs_url="${REPO_URL%.git}"
    local path_note=""
    local mode="${BLACKBOX_SELECTED_MODE:-$(read_blackbox_mode 2>/dev/null || echo audit)}"
    local store_note="$(blackbox_store_description)"
    local graph_note="  Threat graph: the first sync runs in the background (about 30 minutes);
                the dashboard shows its progress."
    case ":$PATH:" in
        *":$HOME/.local/bin:"*) : ;;
        *) path_note=$'\n  First reload your shell so `blackbox` is on PATH:  exec $SHELL -l' ;;
    esac
    if [ "$BLACKBOX_THREAT_GRAPH_INCOMPLETE" = true ]; then
        graph_note="  Threat graph: not set up (--skip-dkg). Run the installer without it to add the DKG node."
    fi
    heading "Blackbox is ready ($mode mode)."
    cat <<EOF
${path_note}
  Dashboard:  http://127.0.0.1:${BLACKBOX_DASHBOARD_PORT:-9700}
  DKG node:   $BLACKBOX_DKG_DAEMON_URL
  DKG home:   $BLACKBOX_DKG_HOME
  DKG CLI:    $BLACKBOX_DKG_BIN
  Store:      $store_note
${graph_note}
  Docs:        $docs_url
EOF
    print_sharing_notice
    echo ""
}

# ── Pre-flight: everything that can be known before the first change ────────
# A check that would fail half-way through the install fails here instead, while nothing
# has been downloaded or written: free disk, the network sources the install pulls from,
# and the DKG store (Docker for Blazegraph, else the built-in Oxigraph — decided now, so a
# person is asked at the start rather than after Hermes is already installed).
# Measured 2026-10-17 on bb-trader-1: a complete install holds ~7 GB (checkout 2.1 GB,
# Hermes 0.9 GB, DKG package 0.6 GB, the synced graph 2.3 GB, Node 0.2 GB).
BLACKBOX_MIN_FREE_GB_FRESH=8
BLACKBOX_MIN_FREE_GB_UPGRADE=2
BLACKBOX_PREFLIGHT_NETWORK_SECONDS=20
BLACKBOX_NPM_REGISTRY_PING="https://registry.npmjs.org/-/ping"

preflight_install() {
    heading "Checking this machine can take the whole install"
    preflight_disk
    preflight_network
    preflight_store_choice
    ok "Pre-flight passed; installing"
}

# Free kilobytes on the filesystem that holds PATH (or its nearest existing parent).
free_kb_at() {
    local dir="$1"
    while [ ! -d "$dir" ]; do dir="$(dirname "$dir")"; done
    df -Pk "$dir" | awk 'NR == 2 { print $4 }'
}

preflight_disk() {
    local need_gb="$BLACKBOX_MIN_FREE_GB_FRESH" free_kb
    [ -d "$BLACKBOX_DKG_HOME" ] && need_gb="$BLACKBOX_MIN_FREE_GB_UPGRADE"
    free_kb="$(free_kb_at "$BLACKBOX_INSTALL_ROOT")"
    if [ -n "$free_kb" ] && [ "$free_kb" -lt $((need_gb * 1024 * 1024)) ]; then
        err "Not enough disk space: $((free_kb / 1024 / 1024)) GB free where Blackbox installs, $need_gb GB needed."
        step "Free some space (or set BLACKBOX_INSTALL_DIR to a bigger disk), then run the installer again."
        exit 1
    fi
    ok "Disk: $((free_kb / 1024 / 1024)) GB free ($need_gb GB needed)"
}

# Whether this script runs from inside the checkout it installs (no clone, no fetch).
install_uses_local_checkout() {
    [ -n "$BLACKBOX_INSTALL_SCRIPT" ] && [ -f "$BLACKBOX_INSTALL_SCRIPT" ] &&
        [ "$(cd "$(dirname "$BLACKBOX_INSTALL_SCRIPT")/.." && pwd)" = "$BLACKBOX_INSTALL_ROOT" ]
}

preflight_network() {
    if [ "$BLACKBOX_SETUP_ONLY" != true ] && ! install_uses_local_checkout; then
        if ! GIT_TERMINAL_PROMPT=0 git ls-remote --exit-code --heads "$REPO_URL" "$REPO_BRANCH" >/dev/null 2>&1; then
            err "Cannot reach branch $REPO_BRANCH of $REPO_URL."
            step "Check the internet connection (and BLACKBOX_REPO_URL / BLACKBOX_REPO_BRANCH), then run the installer again."
            exit 1
        fi
        ok "Network: $REPO_URL ($REPO_BRANCH) reachable"
    fi
    [ "$SKIP_DKG" = true ] && return 0
    if command -v curl >/dev/null 2>&1 &&
        ! curl -fsS --max-time "$BLACKBOX_PREFLIGHT_NETWORK_SECONDS" "$BLACKBOX_NPM_REGISTRY_PING" >/dev/null 2>&1; then
        err "Cannot reach the npm registry, where the DKG node is downloaded from."
        step "Check the internet connection (or proxy), then run the installer again."
        exit 1
    fi
    ok "Network: npm registry reachable"
}

# Decide the DKG store now. An existing node keeps its store, an explicit choice is kept,
# and setup-only mode keeps its own rule (Oxigraph whenever Docker is absent). Otherwise
# Blazegraph when Docker works; when it does not, Oxigraph (confirm_oxigraph_fallback asks
# a person at a terminal, defaulting to yes, and chooses it on its own with no terminal).
preflight_store_choice() {
    [ "$SKIP_DKG" = true ] && return 0
    [ "$BLACKBOX_DKG_STORE_URL_EXPLICIT" = true ] && return 0
    [ "$BLACKBOX_DKG_STORE_BACKEND" = "oxigraph" ] && return 0
    [ "$BLACKBOX_DKG_STORE_BACKEND" = "native" ] && return 0
    [ -f "$BLACKBOX_DKG_HOME/config.json" ] && return 0
    [ "$BLACKBOX_SETUP_ONLY" = true ] && [ "$BLACKBOX_DKG_STORE_BACKEND" = "auto" ] &&
        ! blackbox_docker_available && return 0
    if require_docker_for_blazegraph; then
        return 0
    fi
    if [ "$BLACKBOX_DKG_STORE_BACKEND" = "auto" ] &&
        confirm_oxigraph_fallback "Docker cannot run the Blazegraph store on this machine."; then
        BLACKBOX_DKG_STORE_BACKEND="oxigraph"
        BLACKBOX_DOCKER_REQUIRED=false
        ok "Store: DKG-managed Oxigraph (no Docker needed)"
        return 0
    fi
    err "Stopped before installing anything: the Blazegraph store needs a working Docker."
    exit 1
}

# ── The finish line: installed, running and checked ─────────────────────────
# The install counts only when every part answers. Anything less exits non-zero, and the
# install record puts the machine back the way it was.
blackbox_store_answers() {
    local status store_url
    status="$(curl -fsS --max-time 5 "$BLACKBOX_DKG_DAEMON_URL/api/status" 2>/dev/null)" || return 1
    store_url="$(printf '%s' "$status" | "$VENV_DIR/bin/python" -c \
        'import json, sys; print(json.load(sys.stdin).get("storeUrl") or "")' 2>/dev/null)"
    # A node that reports no store address passed blackbox_dkg_answers with its store up.
    [ -n "$store_url" ] || return 0
    curl -fsS --max-time 10 -H 'Accept: application/sparql-results+json' \
        --data-urlencode 'query=ASK {}' "$store_url" >/dev/null 2>&1
}

verify_install() {
    local failed=false supervisor dashboard_url="http://127.0.0.1:${BLACKBOX_DASHBOARD_PORT:-9700}/"
    heading "Checking the install"
    verify_part() {   # verify_part "what" command…: report one part; remember any failure
        local what="$1"; shift
        if "$@" >/dev/null 2>&1; then ok "$what"; else err "$what — NOT working"; failed=true; fi
    }
    [ "$BLACKBOX_INSTALL_INCOMPLETE" = true ] && { err "A step above did not complete."; failed=true; }
    verify_part "Hermes runs" "$HERMES_BIN" --version
    verify_part "Hermes loads the Blackbox plugin" "$HERMES_BIN" blackbox --help
    if [ "$SKIP_DKG" != true ]; then
        verify_part "DKG node answers at $BLACKBOX_DKG_DAEMON_URL" blackbox_dkg_answers
        verify_part "DKG store answers" blackbox_store_answers
        supervisor="$(blackbox_dkg_supervisor)"
        [ -z "$supervisor" ] || verify_part "DKG node runs under its $supervisor service" blackbox_dkg_owned_by "$supervisor"
    fi
    case "$BLACKBOX_AUTO_DASHBOARD" in
        0|false|never|no) ;;
        *) verify_part "Dashboard answers at $dashboard_url" \
            blackbox_dashboard_answers_within "$dashboard_url" "$BLACKBOX_DASHBOARD_ANSWER_WAIT_SECONDS" ;;
    esac
    unset -f verify_part
    if [ "$failed" = true ]; then
        err "The install is not complete, so it will not be kept."
        exit 1
    fi
    ok "Everything is installed, running and checked"
}

# ── All or nothing: the install record and its rollback ─────────────────────
# Founder decision 2026-10-17: an install either finishes completely — Hermes, the plugin,
# the DKG node, its store, the dashboard and their services all running and checked — or
# leaves the machine as it was before it started. A Mac install that stopped half-way
# (Docker never came up) had left Hermes installed with no Blackbox in it.
#
# Pattern: a before-image transaction (Memento). install_record_begin notes, BEFORE the
# first change, which paths this installer may create already exist, and copies the small
# files it rewrites. Every exit that is not install_record_commit — an error, `set -e`,
# Ctrl-C, a failed final check — runs rollback_install: stop what this run started,
# unregister the services it registered, remove the Docker store it created, remove what
# did not exist before and put back what it rewrote. Large state that already existed (an
# upgrade's synced graph, a user's own Hermes home in setup-only mode) is never deleted:
# only the files this run changes inside it are restored.
INSTALL_RECORD_DIR=""
INSTALL_RECORD_COMMITTED=false
BLACKBOX_OPENED_DOCKER_DESKTOP=false   # set when this run opened Docker Desktop (rollback closes it)
# The user's command folder: Hermes's setup can add tools there (uv, launchers) besides hermes.
BLACKBOX_USER_BIN_DIR="$HOME/.local/bin"
BLACKBOX_LAUNCHD_LABELS="ai.umanitek.blackbox-dkg ai.umanitek.blackbox-dashboard"
BLACKBOX_SERVICE_NAMES="blackbox-dkg blackbox-dashboard blackbox-curator blackbox-curate-watch blackbox-lab-tunnel blackbox-console"
BLACKBOX_STORE_CONTAINER_PREFIX="dkg-blazegraph-"
# Top-level folders no rollback may ever remove, whatever a variable expanded to.
# no-tmp: ok — a list of folders the rollback refuses to delete, not scratch space
BLACKBOX_PROTECTED_ROOTS="/Users /home /root /usr /etc /var /opt /tmp /private /Applications /Library /System /bin /sbin"

# Paths removed on rollback only when this run created them; when they already existed
# they are left exactly as they are (their changed files are in install_rewritten_files).
install_created_paths() {
    printf '%s\n' "$BLACKBOX_INSTALL_ROOT" "$HERMES_HOME" "$BLACKBOX_HOME" "$HOME/.nvm" \
        "$HOME/.local/bin/hermes" "$HOME/.local/bin/blackbox"
}

# Files (and the small plugin folder) this run may rewrite: copied before the first change
# and put back on rollback; removed on rollback when they did not exist.
install_rewritten_files() {
    local name label
    printf '%s\n' "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile" \
        "$HERMES_HOME/config.yaml" "$HERMES_HOME/.env" "$HERMES_HOME/plugins/blackbox" \
        "$BLACKBOX_DKG_HOME/config.json" \
        "$BLACKBOX_DKG_CLI_DIR/package.json" "$BLACKBOX_DKG_CLI_DIR/package-lock.json"
    for label in $BLACKBOX_LAUNCHD_LABELS; do
        printf '%s\n' "$HOME/Library/LaunchAgents/$label.plist"
    done
    for name in $BLACKBOX_SERVICE_NAMES; do
        printf '%s\n' "$HOME/.config/systemd/user/$name.service" "$BLACKBOX_SYSTEMD_DIR/$name.service"
    done
}

install_path_exists() {
    [ -e "$1" ] || [ -L "$1" ]
}

# Whether rollback may delete PATH: absolute, at least two levels deep, never $HOME or a
# protected top-level folder. A guard against an empty or wrong variable, not a policy.
install_path_removable() {
    local path="$1" root
    case "$path" in
        /*/*) ;;
        *) return 1 ;;
    esac
    path="${path%/}"
    [ "$path" != "$HOME" ] || return 1
    for root in $BLACKBOX_PROTECTED_ROOTS; do
        [ "$path" != "$root" ] || return 1
    done
    return 0
}

# Record PATH before the first change. A missing path is recorded as its top-most missing
# folder too (~/.local when even that is missing), so rollback leaves no empty folders behind.
install_record_note() {
    local path="$1" kind="$2" copy top
    if ! install_path_exists "$path"; then
        top="$path"
        while ! install_path_exists "$(dirname "$top")" && install_path_removable "$(dirname "$top")"; do
            top="$(dirname "$top")"
        done
        printf '%s\n' "$top" >>"$INSTALL_RECORD_DIR/absent"
        [ "$top" = "$path" ] || printf '%s\n' "$path" >>"$INSTALL_RECORD_DIR/absent"
    elif [ "$kind" = rewritten ]; then
        copy="$INSTALL_RECORD_DIR/copies/$(printf '%s' "$path" | cksum | cut -d' ' -f1)"
        if cp -pRP "$path" "$copy" 2>/dev/null; then
            printf '%s\t%s\n' "$path" "$copy" >>"$INSTALL_RECORD_DIR/saved"
        fi
    fi
}

# Run a command, giving up after SECONDS (macOS has no timeout(1)). Returns its exit code,
# or non-zero when it had to be stopped.
run_with_timeout() {
    local seconds="$1" pid watcher rc
    shift
    "$@" &
    pid=$!
    ( sleep "$seconds"; kill "$pid" 2>/dev/null ) &
    watcher=$!
    wait "$pid"
    rc=$?
    kill "$watcher" 2>/dev/null
    wait "$watcher" 2>/dev/null
    return "$rc"
}

# A half-started Docker Desktop can leave `docker info` hanging; ten seconds is an answer.
BLACKBOX_DOCKER_PROBE_SECONDS=10
docker_answers() {
    command -v docker >/dev/null 2>&1 &&
        run_with_timeout "$BLACKBOX_DOCKER_PROBE_SECONDS" docker info >/dev/null 2>&1
}

# Names of Docker containers and volumes that look like a DKG store, one per line.
blackbox_store_docker_objects() {
    docker_answers || return 0
    docker ps -a --format '{{.Names}}' 2>/dev/null | grep "^$BLACKBOX_STORE_CONTAINER_PREFIX" | sed 's/^/container /'
    docker volume ls --format '{{.Name}}' 2>/dev/null | grep "^$BLACKBOX_STORE_CONTAINER_PREFIX" | sed 's/^/volume /'
}

install_record_begin() {
    local path
    INSTALL_RECORD_DIR="$(mktemp -d)"
    mkdir -p "$INSTALL_RECORD_DIR/copies"
    : >"$INSTALL_RECORD_DIR/absent"
    : >"$INSTALL_RECORD_DIR/saved"
    : >"$INSTALL_RECORD_DIR/started-pids"
    while IFS= read -r path; do install_record_note "$path" created; done < <(install_created_paths)
    while IFS= read -r path; do install_record_note "$path" rewritten; done < <(install_rewritten_files)
    blackbox_store_docker_objects >"$INSTALL_RECORD_DIR/docker-before" || true
    if [ -d "$BLACKBOX_USER_BIN_DIR" ]; then
        ls -A "$BLACKBOX_USER_BIN_DIR" >"$INSTALL_RECORD_DIR/user-bin-before"
    fi
    if [ -d "$BLACKBOX_INSTALL_ROOT/.git" ]; then
        git -C "$BLACKBOX_INSTALL_ROOT" rev-parse -q --verify HEAD >"$INSTALL_RECORD_DIR/repo-head" 2>/dev/null || true
    fi
    # Blackbox's own node, not whatever else answers on its port (a foreign node is moved off).
    if blackbox_has_dkg_state && blackbox_dkg_answers 2>/dev/null; then
        : >"$INSTALL_RECORD_DIR/node-was-running"
    fi
    if [ -n "${USER:-}" ] && [ -e "$BLACKBOX_LINGER_DIR/$USER" ]; then
        : >"$INSTALL_RECORD_DIR/linger-was-on"
    fi
    trap install_record_on_exit EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
}

# A process this run started outside any service (the dashboard before its service exists, a
# direct node start) — stopped on rollback. Only pids recorded here are ever signalled.
install_record_started_pid() {
    [ -n "$INSTALL_RECORD_DIR" ] && [ -n "${1:-}" ] || return 0
    printf '%s\n' "$1" >>"$INSTALL_RECORD_DIR/started-pids"
}

install_record_commit() {
    INSTALL_RECORD_COMMITTED=true
    trap - EXIT INT TERM
    [ -n "$INSTALL_RECORD_DIR" ] && rm -rf "$INSTALL_RECORD_DIR"
    INSTALL_RECORD_DIR=""
}

install_record_on_exit() {
    local code=$?
    trap - EXIT INT TERM
    if [ -n "$INSTALL_RECORD_DIR" ] && [ "$INSTALL_RECORD_COMMITTED" != true ]; then
        [ "$code" -ne 0 ] || code=1
        set +e
        rollback_install
        rm -rf "$INSTALL_RECORD_DIR"
    fi
    exit "$code"
}

rollback_install() {
    echo ""
    err "Blackbox was not installed. Putting this machine back the way it was ..."
    rollback_stop_started
    rollback_services
    rollback_docker_store
    rollback_docker_desktop
    rollback_files
    rollback_repo_head
    rollback_restart_previous
    rollback_restart_dashboard
    ok "Nothing from this install attempt was left behind."
    step "Fix the reason shown above, then run the installer again."
}

rollback_stop_started() {
    local pid
    while IFS= read -r pid; do
        [ -n "$pid" ] && kill "$pid" 2>/dev/null
    done <"$INSTALL_RECORD_DIR/started-pids"
    if [ ! -e "$INSTALL_RECORD_DIR/node-was-running" ] && [ -x "$BLACKBOX_DKG_BIN" ]; then
        blackbox_dkg_control stop >/dev/null 2>&1
        blackbox_dkg stop >/dev/null 2>&1
    fi
}

install_record_was_absent() {
    grep -qxF -- "$1" "$INSTALL_RECORD_DIR/absent"
}

# Unregister every service whose definition this run created (its file comes off in
# rollback_files). A service that existed before keeps running; its file is restored.
rollback_services() {
    local label name unit
    for label in $BLACKBOX_LAUNCHD_LABELS; do
        if install_record_was_absent "$HOME/Library/LaunchAgents/$label.plist" &&
            command -v launchctl >/dev/null 2>&1; then
            launchctl bootout "gui/$(id -u)/$label" >/dev/null 2>&1
        fi
    done
    command -v systemctl >/dev/null 2>&1 || return 0
    for name in $BLACKBOX_SERVICE_NAMES; do
        unit="$HOME/.config/systemd/user/$name.service"
        if install_record_was_absent "$unit" && [ -e "$unit" ]; then
            systemctl --user disable --now "$name" >/dev/null 2>&1
        fi
        unit="$BLACKBOX_SYSTEMD_DIR/$name.service"
        if install_record_was_absent "$unit" && [ -e "$unit" ]; then
            systemctl disable --now "$name" >/dev/null 2>&1
        fi
    done
    systemctl --user daemon-reload >/dev/null 2>&1
    [ -w "$BLACKBOX_SYSTEMD_DIR" ] && systemctl daemon-reload >/dev/null 2>&1
    if [ ! -e "$INSTALL_RECORD_DIR/linger-was-on" ] && [ -n "${USER:-}" ] &&
        [ -e "$BLACKBOX_LINGER_DIR/$USER" ] && command -v loginctl >/dev/null 2>&1; then
        loginctl disable-linger "$USER" >/dev/null 2>&1
    fi
    return 0
}

# Remove the Docker store containers and volumes this run created (never one that existed).
rollback_docker_store() {
    local kind name
    docker_answers || return 0
    blackbox_store_docker_objects | while read -r kind name; do
        grep -qxF -- "$kind $name" "$INSTALL_RECORD_DIR/docker-before" && continue
        case "$kind" in
            container) docker rm -f "$name" >/dev/null 2>&1 ;;
            volume) docker volume rm -f "$name" >/dev/null 2>&1 ;;
        esac
    done
    return 0
}

# Docker Desktop that this run opened is closed again (its store containers are already gone).
rollback_docker_desktop() {
    [ "${BLACKBOX_OPENED_DOCKER_DESKTOP:-false}" = true ] || return 0
    osascript -e 'quit app "Docker"' >/dev/null 2>&1
    return 0
}

# Put back every rewritten file, then remove every path that did not exist, deepest first.
rollback_files() {
    local path copy
    while IFS="$(printf '\t')" read -r path copy; do
        if [ -z "$path" ] || ! install_path_removable "$path"; then
            continue
        fi
        rm -rf "$path"
        mkdir -p "$(dirname "$path")"
        cp -pRP "$copy" "$path" || warn "Could not restore $path (a copy is in $copy)."
    done <"$INSTALL_RECORD_DIR/saved"
    # New commands in a command folder that already existed (a folder this run created is
    # in the absent list and goes as a whole).
    if [ -f "$INSTALL_RECORD_DIR/user-bin-before" ] && [ -d "$BLACKBOX_USER_BIN_DIR" ]; then
        ls -A "$BLACKBOX_USER_BIN_DIR" | while IFS= read -r name; do
            grep -qxF -- "$name" "$INSTALL_RECORD_DIR/user-bin-before" || rm -rf "${BLACKBOX_USER_BIN_DIR:?}/$name"
        done
    fi
    sort -r "$INSTALL_RECORD_DIR/absent" | while IFS= read -r path; do
        if install_path_removable "$path"; then
            rm -rf "$path"
        fi
    done
    return 0
}

# An existing checkout that this run moved to a new commit goes back to the commit it had.
rollback_repo_head() {
    local before
    [ -s "$INSTALL_RECORD_DIR/repo-head" ] && [ -d "$BLACKBOX_INSTALL_ROOT/.git" ] || return 0
    before="$(cat "$INSTALL_RECORD_DIR/repo-head")"
    [ "$(git -C "$BLACKBOX_INSTALL_ROOT" rev-parse -q --verify HEAD 2>/dev/null)" = "$before" ] && return 0
    git -C "$BLACKBOX_INSTALL_ROOT" reset -q --keep "$before" 2>/dev/null ||
        warn "Could not move $BLACKBOX_INSTALL_ROOT back to ${before:0:12}."
    return 0
}

# An upgrade whose node was running before runs again on its restored settings.
rollback_restart_previous() {
    [ -e "$INSTALL_RECORD_DIR/node-was-running" ] || return 0
    blackbox_dkg_control restart >/dev/null 2>&1 || blackbox_dkg start >/dev/null 2>&1 ||
        warn "Could not restart the Blackbox DKG node that was running before."
    return 0
}

# A dashboard service that existed before this run is restarted once the files are back:
# it may have loaded this run's code, and would keep running it beside the restored plugin
# copy (KI-455). A service this run created is already gone (rollback_services + files).
rollback_restart_dashboard() {
    local supervisor
    supervisor="$(blackbox_dashboard_supervisor)"
    [ -n "$supervisor" ] || return 0
    blackbox_dashboard_control reload "$supervisor" >/dev/null 2>&1 ||
        warn "Could not restart the Blackbox dashboard; restart its $supervisor service."
    return 0
}

# ── Main ────────────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------
# Boot persistence (B10 / KI-022): the DKG node must survive a reboot, or
# "install once -> always protected and contributing" is only true until the
# machine restarts (fail-open would hide the dead node). Registers a system
# service on Linux (systemd) and a LaunchAgent on macOS. Idempotent: re-runs
# overwrite the unit in place. Disable anytime:
#   Linux:  systemctl disable --now blackbox-dkg
#   macOS:  launchctl unload ~/Library/LaunchAgents/ai.umanitek.blackbox-dkg.plist
# ---------------------------------------------------------------------------
# A value placed inside a launchd plist <string> must be XML text. sed, not
# ${value//</&lt;}: bash 5.2+ reads "&" in that replacement as the matched text
# (patsub_replacement), so it produced "<lt;" on Linux and Homebrew bash.
xml_escape() {
    printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
}

register_boot_service() {
    heading "Registering the DKG node to start on boot"
    # No node to start (--skip-dkg, or its install failed): a boot service would
    # only fail at every login (launchd exit 78) or restart-loop under systemd.
    if [ ! -x "$BLACKBOX_DKG_BIN" ]; then
        warn "No DKG node at $BLACKBOX_DKG_BIN — not registering a boot service."
        return 0
    fi
    local node_bin_dir
    node_bin_dir="$(dirname "$(command -v node)")"
    secure_dkg_token_perms
    case "$(uname -s)" in
        Linux)
            if ! command -v systemctl >/dev/null 2>&1; then
                warn "systemd not found — the DKG node will NOT auto-start after a reboot."
                warn "Start it manually after reboots: DKG_HOME=\"$BLACKBOX_DKG_HOME\" \"$BLACKBOX_DKG_BIN\" start"
                return 0
            fi
            local unit=/etc/systemd/system/blackbox-dkg.service
            if [ ! -w /etc/systemd/system ] && [ "$(id -u)" != 0 ]; then
                unit="$HOME/.config/systemd/user/blackbox-dkg.service"
                mkdir -p "$(dirname "$unit")"
            fi
            cat > "$unit" <<UNIT
[Unit]
Description=Agent Blackbox DKG node (threat-graph sync + community sharing)
After=network-online.target

[Service]
Type=simple
Environment=PATH=$node_bin_dir:$BLACKBOX_SERVICE_SYSTEM_PATH
Environment=DKG_HOME=$BLACKBOX_DKG_HOME
# Connection-time sync stays ON: the meta sync on connect is what delivers
# context-graph authority to subscribers — with it off, community-graph
# subscribes fail closed (KI-044). The =0 values used during install bootstrap
# are for that one supervised transfer only and must never leak into the boot
# service. The periodic sync reconciler is NOT set here: config.json decides it
# per graph (sync/managed_node.py), and an environment value would override it.
Environment=DKG_SYNC_ON_CONNECT_ENABLED=1
# DKG 10.0.21+ recovery speed-ups (KI-282). The exact batch stream is read ONLY
# from the environment: without this line a service-started node recovers the
# graph about 8x slower. The reconciler choice itself lives in config.json.
Environment=DKG_EXACT_BATCH_STREAM_ENABLED=$BLACKBOX_DKG_EXACT_BATCH_STREAM_ENABLED
Environment=DKG_VM_RECOVERY_PREFETCH_ENABLED=$BLACKBOX_DKG_VM_RECOVERY_PREFETCH_ENABLED
# The node's safety limits are ALSO environment-only (no config.json key): the
# V8 heap cap and the store queue limit. Without them a reboot brings the node
# back on Node's ~4 GB default heap (KI-308). The graph-list projection is NOT
# set here: it is install-time only — with it on, the running node's listing
# omits the verified graph and Blackbox reads it as "not subscribed".
Environment="NODE_OPTIONS=$BLACKBOX_DKG_NODE_OPTIONS"
Environment=DKG_STORE_QUEUE_LIMIT=$BLACKBOX_DKG_STORE_QUEUE_LIMIT
# Clear any orphaned daemon before starting: DKG CLI commands auto-spawn a
# detached daemon when none is running; that orphan holds daemon.pid and
# would crash-loop this unit forever ("Daemon already running", KI-045).
ExecStartPre=-/bin/sh -c 'PATH=$node_bin_dir:$BLACKBOX_SERVICE_SYSTEM_PATH DKG_HOME=$BLACKBOX_DKG_HOME $BLACKBOX_DKG_BIN stop >/dev/null 2>&1; sleep 2'
ExecStart=$BLACKBOX_DKG_BIN start --foreground
ExecStop=$BLACKBOX_DKG_BIN stop
TimeoutStopSec=30
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target default.target
UNIT
            if [ "$unit" = /etc/systemd/system/blackbox-dkg.service ]; then
                systemctl daemon-reload && systemctl enable blackbox-dkg >/dev/null 2>&1 \
                    && ok "systemd service registered (blackbox-dkg) — the node survives reboots" \
                    || warn "could not enable blackbox-dkg service; enable manually: systemctl enable blackbox-dkg"
            else
                if systemctl --user daemon-reload && systemctl --user enable blackbox-dkg >/dev/null 2>&1; then
                    ok "systemd user service registered (blackbox-dkg)"
                    ensure_user_lingering
                else
                    warn "could not enable the user service; enable manually: systemctl --user enable blackbox-dkg"
                fi
            fi
            ;;
        Darwin)
            local plist="$HOME/Library/LaunchAgents/$BLACKBOX_DKG_LAUNCHD_LABEL.plist"
            mkdir -p "$HOME/Library/LaunchAgents"
            cat > "$plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$BLACKBOX_DKG_LAUNCHD_LABEL</string>
  <key>ProgramArguments</key><array>
    <string>$BLACKBOX_DKG_BIN</string><string>start</string><string>--foreground</string>
  </array>
  <key>EnvironmentVariables</key><dict>
    <key>PATH</key><string>$(xml_escape "$node_bin_dir:$BLACKBOX_SERVICE_SYSTEM_PATH")</string>
    <key>DKG_HOME</key><string>$(xml_escape "$BLACKBOX_DKG_HOME")</string>
    <key>DKG_SYNC_ON_CONNECT_ENABLED</key><string>1</string>
    <key>DKG_EXACT_BATCH_STREAM_ENABLED</key><string>$(xml_escape "$BLACKBOX_DKG_EXACT_BATCH_STREAM_ENABLED")</string>
    <key>DKG_VM_RECOVERY_PREFETCH_ENABLED</key><string>$(xml_escape "$BLACKBOX_DKG_VM_RECOVERY_PREFETCH_ENABLED")</string>
    <key>NODE_OPTIONS</key><string>$(xml_escape "$BLACKBOX_DKG_NODE_OPTIONS")</string>
    <key>DKG_STORE_QUEUE_LIMIT</key><string>$(xml_escape "$BLACKBOX_DKG_STORE_QUEUE_LIMIT")</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>StandardErrorPath</key><string>$(xml_escape "$(blackbox_dkg_launchd_error_log)")</string>
</dict></plist>
PLIST
            : >"$(blackbox_dkg_launchd_error_log)" 2>/dev/null || true   # this registration's errors only
            launchctl unload "$plist" >/dev/null 2>&1 || true
            launchctl load "$plist" >/dev/null 2>&1 \
                && ok "LaunchAgent registered — the node survives reboots" \
                || warn "could not load the LaunchAgent; load manually: launchctl load $plist"
            ;;
        *)
            warn "Unknown OS — boot persistence not configured; start the node manually after reboots."
            ;;
    esac
    hand_dkg_node_to_service
}

# Boot persistence for the DASHBOARD (KI-296). The dashboard is what keeps a
# node's protection current: its worker refreshes the verified rules and its
# health poll drives the community pulse. Registering only the DKG node meant a
# rebooted machine came back with the node running but Blackbox frozen until an
# agent happened to run (bench swm21-b, 2026-10-07). Same shape as the node's
# service; it starts after the node. Skipped when dashboard auto-start is off.
# Disable anytime:
#   Linux:  systemctl disable --now blackbox-dashboard
#   macOS:  launchctl unload ~/Library/LaunchAgents/ai.umanitek.blackbox-dashboard.plist
register_dashboard_service() {
    case "$BLACKBOX_AUTO_DASHBOARD" in
        0|false|never|no) return 0 ;;
    esac
    if [ -z "${HERMES_BIN:-}" ] || [ ! -x "$HERMES_BIN" ]; then
        warn "hermes not found — the dashboard will NOT restart after a reboot; start it with: blackbox dashboard"
        return 0
    fi
    local node_bin_dir
    node_bin_dir="$(dirname "$(command -v node)")"
    case "$(uname -s)" in
        Linux)
            command -v systemctl >/dev/null 2>&1 || return 0   # register_boot_service already warned
            local unit=/etc/systemd/system/blackbox-dashboard.service before="" start_action=start
            local -a systemctl_cmd=(systemctl)
            if [ ! -w /etc/systemd/system ] && [ "$(id -u)" != 0 ]; then
                unit="$HOME/.config/systemd/user/blackbox-dashboard.service"
                systemctl_cmd+=(--user)
                mkdir -p "$(dirname "$unit")"
            fi
            [ -f "$unit" ] && before="$(cat "$unit")"
            cat > "$unit" <<DASHUNIT
[Unit]
Description=Agent Blackbox dashboard (rule refresh + community pulse)
After=network-online.target blackbox-dkg.service
Wants=blackbox-dkg.service

[Service]
Type=simple
Environment=HOME=$HOME
Environment=HERMES_HOME=$HERMES_HOME
Environment=PATH=$HOME/.local/bin:$node_bin_dir:$BLACKBOX_SERVICE_SYSTEM_PATH
ExecStart=$HERMES_BIN blackbox dashboard
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target default.target
DASHUNIT
            # Enabled AND started: the dashboard runs under systemd from this moment (restarted
            # on a crash), not only after the next reboot; on a first install it replaces the
            # copy the installer launched on the same port. A running service keeps the code
            # and unit it started with, so after an update or a changed unit it is RESTARTED —
            # through systemd only (KI-455). verify_install waits for it to answer.
            if [ "$BLACKBOX_DASHBOARD_RESTART_PENDING" = true ] || [ "$(cat "$unit")" != "$before" ]; then
                start_action=restart
            fi
            if "${systemctl_cmd[@]}" daemon-reload && "${systemctl_cmd[@]}" enable blackbox-dashboard >/dev/null 2>&1 &&
                "${systemctl_cmd[@]}" "$start_action" blackbox-dashboard >/dev/null 2>&1; then
                if [ "$unit" = /etc/systemd/system/blackbox-dashboard.service ]; then
                    ok "systemd service registered (blackbox-dashboard) — protection stays current after reboots"
                else
                    ok "systemd user service registered (blackbox-dashboard)"
                fi
            else
                warn "could not enable blackbox-dashboard; enable manually: ${systemctl_cmd[*]} enable --now blackbox-dashboard"
            fi
            ;;
        Darwin)
            local plist="$HOME/Library/LaunchAgents/$BLACKBOX_DASHBOARD_LAUNCHD_LABEL.plist" before="" action=""
            mkdir -p "$HOME/Library/LaunchAgents"
            [ -f "$plist" ] && before="$(cat "$plist")"
            cat > "$plist" <<DASHPLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>ai.umanitek.blackbox-dashboard</string>
  <key>ProgramArguments</key><array>
    <string>$HERMES_BIN</string><string>blackbox</string><string>dashboard</string>
  </array>
  <key>EnvironmentVariables</key><dict>
    <key>PATH</key><string>$(xml_escape "$HOME/.local/bin:$node_bin_dir:$BLACKBOX_SERVICE_SYSTEM_PATH")</string>
    <key>HERMES_HOME</key><string>$HERMES_HOME</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
</dict></plist>
DASHPLIST
            if [ "$(blackbox_dashboard_supervisor)" != launchd ]; then
                # Registered for the next login only: the dashboard started above keeps
                # running now, and loading the agent here would start a second one.
                ok "LaunchAgent registered (blackbox-dashboard) — starts at your next login"
                return 0
            fi
            # Loaded: the agent runs the dashboard now. It takes a rewritten plist only when
            # reloaded, and new code only when restarted — both through launchd (KI-455).
            if [ "$(cat "$plist")" != "$before" ]; then
                action=reload
            elif [ "$BLACKBOX_DASHBOARD_RESTART_PENDING" = true ]; then
                action=restart
            fi
            if [ -z "$action" ] || blackbox_dashboard_control "$action" launchd >/dev/null 2>&1; then
                ok "LaunchAgent registered (blackbox-dashboard) — the dashboard runs under it"
            else
                warn "could not restart the dashboard's LaunchAgent; run: launchctl kickstart -k gui/$(id -u)/$BLACKBOX_DASHBOARD_LAUNCHD_LABEL"
            fi
            ;;
    esac
}

# KI-032: any local process that can read the DKG auth token can bypass every
# Blackbox gate at the node. The token must be owner-only.
secure_dkg_token_perms() {
    local token
    for token in "$BLACKBOX_DKG_HOME/auth.token" "$BLACKBOX_DKG_HOME"/auth*.token; do
        if [ -f "$token" ]; then
            chmod 600 "$token" 2>/dev/null \
                && step "  auth token permissions: 600 ($token)" \
                || warn "could not tighten $token permissions — check ownership"
        fi
    done
}

# ---------------------------------------------------------------------------
# Node service units (curator nodes and benches) — Linux + systemd only, each
# OPT-IN behind its own flag. blackbox-install.ps1 has no mirror on purpose:
# these units exist only on the Ubuntu curator nodes and benches.
# ---------------------------------------------------------------------------
have_systemd() {
    [ "$(uname -s)" = Linux ] && command -v systemctl >/dev/null 2>&1
}

# A system unit when this user may write one, otherwise a user unit.
can_write_system_units() {
    [ -w "$BLACKBOX_SYSTEMD_DIR" ] || [ "$(id -u)" = 0 ]
}

# install_node_unit NAME LABEL <<UNIT … UNIT — write NAME.service from stdin,
# enable it and (re)start it; LABEL names it in the messages ("curator service
# registered (NAME)"). Restart, not `enable --now`: a re-run that changes a flag
# (e.g. adds --publisher) must reach a unit that is already running (KI-317).
install_node_unit() {
    local name="$1" label="$2" unit
    if can_write_system_units; then
        unit="$BLACKBOX_SYSTEMD_DIR/$name.service"
        cat > "$unit"
        if systemctl daemon-reload && systemctl enable "$name" >/dev/null 2>&1 \
                && systemctl restart "$name" >/dev/null 2>&1; then
            ok "$label service registered ($name)"
        else
            warn "could not enable the $label service; enable manually: systemctl enable --now $name"
        fi
    else
        unit="$HOME/.config/systemd/user/$name.service"
        mkdir -p "$(dirname "$unit")"
        cat > "$unit"
        if systemctl --user daemon-reload && systemctl --user enable "$name" >/dev/null 2>&1 \
                && systemctl --user restart "$name" >/dev/null 2>&1; then
            ok "$label user service registered ($name)"
        else
            warn "could not enable the user service; enable manually: systemctl --user enable --now $name"
        fi
    fi
}

# ---------------------------------------------------------------------------
# The curator service (Community Curation C9) — OPT-IN, curator nodes only.
# An ordinary protected agent never runs it; nothing here is registered unless
# the installer is told this machine is a curator node:
#   BLACKBOX_CURATOR_SERVICE=1 BLACKBOX_CURATOR_PEERS="peer-a,peer-b" bash blackbox-install.sh
# BLACKBOX_CURATOR_PUBLISHER=1 adds `--publisher` (beat step 8, the batch
# publisher): ONLY on the node that holds the publishing wallet (D27).
# The service runs `blackbox curate run` as its own process (never inside an
# agent). It SIGNS NOTHING until the operator has read and accepted the
# automation policy on this machine:
#   blackbox curate policy                    (read it)
#   blackbox curate policy --accept --code <code shown under the text>
# Linux (systemd) only. Disable anytime:  systemctl disable --now blackbox-curator
# ---------------------------------------------------------------------------
register_curator_service() {
    [ "${BLACKBOX_CURATOR_SERVICE:-0}" = 1 ] || return 0
    heading "Registering the curator service (this machine is a curator node)"
    local peer peer_args="" old_ifs="$IFS"
    IFS=','
    for peer in ${BLACKBOX_CURATOR_PEERS:-}; do
        IFS="$old_ifs"
        case "$peer" in
            ""|*[!A-Za-z0-9._:-]*)
                warn "ignoring curator peer '$peer' (letters, digits, . _ : - only)" ;;
            *) peer_args="$peer_args --peer $peer" ;;
        esac
        IFS=','
    done
    IFS="$old_ifs"
    [ -n "$peer_args" ] || warn "no curator peers given (BLACKBOX_CURATOR_PEERS): proposals will wait until a peer is configured"
    local publisher_arg=""
    if [ "${BLACKBOX_CURATOR_PUBLISHER:-0}" = 1 ]; then
        publisher_arg=" --publisher"
    fi
    if ! have_systemd; then
        warn "the curator service unit is provided for Linux with systemd only."
        warn "Start it yourself on this machine:  blackbox curate run$peer_args$publisher_arg"
        return 0
    fi
    install_node_unit blackbox-curator curator <<CURATOR_UNIT
[Unit]
Description=Agent Blackbox curator service (routine curation for the community graph)
After=network-online.target blackbox-dkg.service
Wants=blackbox-dkg.service

[Service]
Type=simple
Environment=HERMES_HOME=$HERMES_HOME
Environment=BLACKBOX_HOME=$BLACKBOX_HOME
ExecStart=$HERMES_BIN blackbox curate run$peer_args$publisher_arg
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target default.target
CURATOR_UNIT
    step "  It signs nothing until you accept the automation policy:  blackbox curate policy"
    if [ -n "$publisher_arg" ]; then
        step "  This node is the batch publisher (--publisher): run it on the wallet holder only"
    fi
}

# ---------------------------------------------------------------------------
# The curate watcher (W3) — OPT-IN: alarms and NEW threats to this node's own
# channel. The URL is a credential (a Slack webhook URL is a bearer secret), so
# it is written to <curate home>/alarm_sink.json (mode 600, never replaced once
# there) and never into the world-readable unit or the process's arguments:
#   BLACKBOX_CURATOR_WEBHOOK="https://hooks.slack.com/services/…" bash blackbox-install.sh
# On a bench this registers blackbox-curate-watch, a long-running
# `curate watch --interval` (never a `--once` timer: the watcher keeps when it
# last posted metrics in memory). On a curator node (BLACKBOX_CURATOR_SERVICE=1)
# the beat already polls the same alarms, so only the sink is written.
# Disable anytime:  systemctl disable --now blackbox-curate-watch
# ---------------------------------------------------------------------------
register_curate_watch() {
    local url="${BLACKBOX_CURATOR_WEBHOOK:-}"
    [ -n "$url" ] || return 0
    heading "Setting up this node's alarm channel"
    # Only characters that need no JSON escaping and no systemd/shell quoting.
    local allowed='A-Za-z0-9._~:/?#@=&%+-'
    case "$url" in
        https://?*) ;;
        *) warn "refused BLACKBOX_CURATOR_WEBHOOK: it must be an https:// URL"; return 0 ;;
    esac
    case "$url" in
        *[!$allowed]*) warn "refused BLACKBOX_CURATOR_WEBHOOK: it holds a character outside $allowed"; return 0 ;;
    esac
    local kind=webhook sink="$BLACKBOX_HOME/curate/alarm_sink.json"
    case "$url" in
        https://hooks.slack.com/*) kind=slack ;;
    esac
    if [ -e "$sink" ]; then
        step "  kept the existing $sink (edit it to change the channel)"
    elif (umask 077 && mkdir -p "$(dirname "$sink")" && printf '{"kind": "%s", "url": "%s"}\n' "$kind" "$url" > "$sink"); then
        ok "alarm channel written ($kind, $sink, mode 600)"
    else
        warn "could not write $sink; the watcher has no channel until it exists"
        return 0
    fi
    if [ "${BLACKBOX_CURATOR_SERVICE:-0}" = 1 ]; then
        step "  the curator service's beat posts this node's alarms; no separate watcher is registered"
        return 0
    fi
    if ! have_systemd; then
        warn "the curate watch unit is provided for Linux with systemd only."
        warn "Start it yourself on this machine:  blackbox curate watch --interval 60"
        return 0
    fi
    install_node_unit blackbox-curate-watch "curate watch" <<WATCH_UNIT
[Unit]
Description=Agent Blackbox curate watcher (alarms and new threats to this node's channel)
After=network-online.target blackbox-dkg.service
Wants=blackbox-dkg.service

[Service]
Type=simple
Environment=HERMES_HOME=$HERMES_HOME
Environment=BLACKBOX_HOME=$BLACKBOX_HOME
ExecStart=$HERMES_BIN blackbox curate watch --interval 60
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target default.target
WATCH_UNIT
}

# A TCP port a service may own: digits only, 1024-65535.
valid_service_port() {
    case "$1" in
        ""|*[!0-9]*|??????*) return 1 ;;
    esac
    [ "$1" -ge 1024 ] && [ "$1" -le 65535 ]
}

# ---------------------------------------------------------------------------
# The lab tunnel (§03.5) — OPT-IN, the node that runs the lab controller only:
#   BLACKBOX_LAB_TUNNEL=lab@lab-1.example bash blackbox-install.sh
# An autossh forward from 127.0.0.1:<BLACKBOX_LAB_TUNNEL_PORT, default 8790> to
# the lab API on the lab host's own loopback (<BLACKBOX_LAB_PORT, default 8790>,
# `python -m threat_lab serve`), with the lab-only key (BLACKBOX_LAB_TUNNEL_KEY,
# default <curate home>/lab/tunnel_key) and nothing else. The lab host's key is
# pinned (StrictHostKeyChecking=yes): connect once by hand first to accept it.
# The lab controller then reaches the lab at http://127.0.0.1:<tunnel port>.
# Disable anytime:  systemctl disable --now blackbox-lab-tunnel
# ---------------------------------------------------------------------------
register_lab_tunnel() {
    local host="${BLACKBOX_LAB_TUNNEL:-}"
    [ -n "$host" ] || return 0
    heading "Registering the lab tunnel"
    local local_port="${BLACKBOX_LAB_TUNNEL_PORT:-8790}" lab_port="${BLACKBOX_LAB_PORT:-8790}"
    local key="${BLACKBOX_LAB_TUNNEL_KEY:-$BLACKBOX_HOME/curate/lab/tunnel_key}"
    # A leading '-' would reach ssh as an option; one optional user@ only.
    case "$host" in
        -*|@*|*@|*@*@*|*[!A-Za-z0-9._@-]*)
            warn "refused BLACKBOX_LAB_TUNNEL '$host': [user@]host with letters, digits, . _ - only"; return 0 ;;
    esac
    if ! valid_service_port "$local_port" || ! valid_service_port "$lab_port"; then
        warn "refused the lab tunnel ports ($local_port, $lab_port): each must be a number from 1024 to 65535"
        return 0
    fi
    case "$key" in
        /*) ;;
        *) warn "refused BLACKBOX_LAB_TUNNEL_KEY '$key': it must be an absolute path"; return 0 ;;
    esac
    case "$key" in
        *[!A-Za-z0-9._/-]*) warn "refused BLACKBOX_LAB_TUNNEL_KEY '$key': letters, digits, . _ - / only"; return 0 ;;
    esac
    local forward="-o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -i $key -L 127.0.0.1:$local_port:127.0.0.1:$lab_port $host"
    if ! have_systemd; then
        warn "the lab tunnel unit is provided for Linux with systemd only."
        warn "Start it yourself on this machine:  autossh -M 0 -N $forward"
        return 0
    fi
    local autossh
    autossh="$(command -v autossh || true)"
    if [ -z "$autossh" ]; then
        warn "autossh is not installed (sudo apt-get install autossh); re-run the installer after installing it"
        return 0
    fi
    [ -f "$key" ] || warn "no lab-only key at $key yet: the tunnel retries until it is there"
    install_node_unit blackbox-lab-tunnel "lab tunnel" <<TUNNEL_UNIT
[Unit]
Description=Agent Blackbox lab tunnel (SSH forward to the threat lab's loopback API)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=AUTOSSH_GATETIME=0
ExecStart=$autossh -M 0 -N $forward
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target default.target
TUNNEL_UNIT
    step "  first connection: ssh -i $key $host once by hand to pin the lab host's key"
}

# ---------------------------------------------------------------------------
# The key console (§03.2, C3) — OPT-IN, the node that holds root A only:
#   sudo BLACKBOX_KEY_CONSOLE=1 bash blackbox-install.sh
# A SYSTEM unit (root needed): `curate console` on 127.0.0.1:9710 as its own
# system user, with no new privileges, a read-only system, no writable+executable
# memory and no core dumps. ProtectHome is left off because the Hermes install
# and the curate home live under a home folder. Operator steps (printed below):
#   - kernel.yama.ptrace_scope >= 2 on the host, so no process of any uid but
#     root can read the console's memory while it holds a decrypted key;
#   - give blackbox-console access to the curate home and the Hermes install;
#   - <curate home>/console_settings.json (see curate/console/commands.py);
#   - tailscale serve --bg http://127.0.0.1:9710 (never Funnel; needs tailnet admin).
# Disable anytime:  systemctl disable --now blackbox-console
# ---------------------------------------------------------------------------
register_key_console() {
    [ "${BLACKBOX_KEY_CONSOLE:-0}" = 1 ] || return 0
    heading "Registering the key console (this node holds root A)"
    local port=9710 user=blackbox-console
    if ! have_systemd || [ "$(id -u)" != 0 ]; then
        warn "the key console is a systemd SYSTEM unit on Linux: re-run the installer as root with BLACKBOX_KEY_CONSOLE=1."
        warn "Nothing was registered; the console is not running."
        return 0
    fi
    if ! id "$user" >/dev/null 2>&1 \
            && ! useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$user"; then
        warn "could not create the $user system user; the key console was not registered"
        return 0
    fi
    install_node_unit blackbox-console "key console" <<CONSOLE_UNIT
[Unit]
Description=Agent Blackbox key console (root A; reached only through tailscale serve)
After=network-online.target

[Service]
Type=simple
User=$user
Group=$user
Environment=HERMES_HOME=$HERMES_HOME
Environment=BLACKBOX_HOME=$BLACKBOX_HOME
ExecStart=$HERMES_BIN blackbox curate console --port $port
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=$BLACKBOX_HOME/curate
MemoryDenyWriteExecute=yes
LimitCORE=0
PrivateTmp=yes
RestrictSUIDSGID=yes
LockPersonality=yes
UMask=0077
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
CONSOLE_UNIT
    local scope
    scope="$(cat "$BLACKBOX_PTRACE_SCOPE_FILE" 2>/dev/null || true)"
    case "$scope" in
        2|3) ok "kernel.yama.ptrace_scope is $scope" ;;
        *) warn "kernel.yama.ptrace_scope is ${scope:-unavailable}; the key console needs 2 or more. On this host run:"
           step "  set kernel.yama.ptrace_scope = 2 in a file under /etc/sysctl.d/ (for example 60-blackbox-ptrace.conf), then run: sysctl --system" ;;
    esac
    step "  give $user access:  setfacl -R -m u:$user:rwX $BLACKBOX_HOME/curate  (and read access to the Hermes install)"
    step "  write $BLACKBOX_HOME/curate/console_settings.json (tailscaleLogin, magicDnsHost, loginPassphraseHash)"
    step "  then, as the tailnet admin:  tailscale serve --bg http://127.0.0.1:$port   (never Funnel)"
}

main() {
    banner
    heading "Checking your system"
    detect_os
    install_record_begin
    preflight_install
    if [ "$BLACKBOX_SETUP_ONLY" = true ]; then
        ensure_node
        use_running_hermes
    else
        check_git
        check_python
        ensure_node

        resolve_repo
        release_old_hermes_link
        install_python_env
        link_hermes
        refresh_blackbox_plugin_copy
        run_hermes_setup
    fi
    install_dkg
    enable_and_configure
    configure_blackbox_mode
    attach_all_agents
    setup_llm
    sync_ruleset
    start_dashboard
    register_boot_service
    register_dashboard_service
    register_curator_service
    register_curate_watch
    register_lab_tunnel
    register_key_console
    verify_install
    install_record_commit
    next_steps
}

main "$@"
