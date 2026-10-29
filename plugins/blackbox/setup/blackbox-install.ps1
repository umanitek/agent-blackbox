# ============================================================================
# Agent Blackbox - one-command installer (Windows / PowerShell)
# ============================================================================
# Mirror of blackbox-install.sh. Wires up the Blackbox threat-graph plugin,
# installs the OriginTrail DKG node CLI (Windows-native), bootstraps a mainnet
# node, enables the plugin, and writes config defaults.
#
# NOTE: The Hermes agent itself is best run under WSL2 on Windows. The DKG CLI
# (dkg) is Windows-native. This installer sets up the Python environment and
# DKG node; if you hit issues running `hermes`, use WSL2 (guidance printed at
# the end).
#
# Usage:
#   iwr -useb blackbox-w.umanitek.ai | iex
#   # or, from a clone:
#   .\scripts\blackbox-install.ps1 [-SkipDkg]
#
# Idempotent: safe to re-run. If the DKG node or initial threat-graph sync
# cannot complete, the installer exits non-zero and prints clear next steps
# instead of claiming Blackbox is fully ready with an empty ruleset.
# ============================================================================

param(
    [switch]$SkipDkg,
    [ValidateSet("auto", "blazegraph", "oxigraph", "native")]
    [string]$StoreBackend = "auto",
    [switch]$Help
)

# Mainnet only.
$Network = if ($env:BLACKBOX_DKG_NETWORK) { $env:BLACKBOX_DKG_NETWORK } else { "mainnet-base" }

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# ── Configuration (override via env) ────────────────────────────────────────
$RepoUrl     = if ($env:BLACKBOX_REPO_URL)    { $env:BLACKBOX_REPO_URL }    else { "https://github.com/umanitek/agent-blackbox.git" }
$RepoBranch  = if ($env:BLACKBOX_REPO_BRANCH) { $env:BLACKBOX_REPO_BRANCH } else { "main" }
$DkgTaskName = "Agent Blackbox DKG node"   # the node's logon task (Register-ScheduledTask below)
# Setup-only mode: Blackbox is already installed as a plugin (the Hermes plugin catalog), and
# `hermes blackbox setup` runs this script for everything after Hermes, in the Hermes it runs in.
# The caller passes HERMES_BIN, VENV_DIR, BLACKBOX_INSTALL_DIR, BLACKBOX_HELPER_DIR and
# BLACKBOX_PLUGIN_DIR (the same contract as blackbox-install.sh).
$SetupOnly = $env:BLACKBOX_SETUP_ONLY -eq "true"
$RepoDir = ""   # set by Resolve-Repo; setup-only mode has no checkout
$HermesHome  = if ($env:HERMES_HOME)          { $env:HERMES_HOME }          else { "$env:USERPROFILE\.hermes" }
# Keep the managed npm DKG package and state in the Agent Blackbox checkout. When
# invoked from a clone, use that clone; when piped through iex, default to an
# agent-blackbox child of the invocation directory. BLACKBOX_INSTALL_DIR remains
# the explicit override.
if ($env:BLACKBOX_INSTALL_DIR) {
    $DefaultRepoDir = $env:BLACKBOX_INSTALL_DIR
} elseif (
    (Test-Path "$(Get-Location)\pyproject.toml") -and
    (Test-Path "$(Get-Location)\plugins\blackbox")
) {
    $DefaultRepoDir = [string](Get-Location)
} else {
    $DefaultRepoDir = Join-Path ([string](Get-Location)) "agent-blackbox"
}
if ($PSCommandPath) {
    $candidateRepoDir = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
    if ((Test-Path "$candidateRepoDir\pyproject.toml") -and (Test-Path "$candidateRepoDir\plugins\blackbox")) {
        $DefaultRepoDir = $candidateRepoDir
    }
}
$BlackboxHome = if ($env:BLACKBOX_HOME)       { $env:BLACKBOX_HOME }        else { Join-Path $HermesHome "blackbox" }
$DkgPortExplicit = [bool]$env:BLACKBOX_DKG_PORT
$DkgStoreUrlExplicit = [bool]$env:BLACKBOX_DKG_STORE_URL
$DkgPort     = if ($env:BLACKBOX_DKG_PORT)    { [int]$env:BLACKBOX_DKG_PORT } else { 9320 }
$DkgStorePort = if ($env:BLACKBOX_DKG_STORE_PORT) { [int]$env:BLACKBOX_DKG_STORE_PORT } else { 9999 }
$DkgStoreUrl = if ($env:BLACKBOX_DKG_STORE_URL) { $env:BLACKBOX_DKG_STORE_URL } else { "" }
$DkgStoreManagedByDkg = $false
$script:DkgStoreNamespace = "agent-blackbox"
$script:DkgSelectedStoreBackend = ""
$script:DockerRequired = $false
$DkgAcceptStoreReset = $false
$DkgHome     = Join-Path $DefaultRepoDir ".dkg"
$DkgCliDir   = Join-Path $DefaultRepoDir "dkg"
$DkgBin      = Join-Path $DkgCliDir "node_modules\.bin\dkg.cmd"
# The DKG release this Blackbox installs and the sha512 the downloaded tarball must have; another
# package needs its own BLACKBOX_DKG_INTEGRITY, or "unpinned" to skip the check knowingly (see the .sh).
$DkgDefaultPackage = "@origintrail-official/dkg@10.0.26"
$DkgDefaultIntegrity = "sha512-QlCW/5UvL2UHaR2QGAemQzvu+ZtBKfefwuitoX2hGr/XZAgkFXsln1NHitzftQM99qTrlKBq8CFfDSfDFAbMHg=="
$DkgPackage  = if ($env:BLACKBOX_DKG_PACKAGE) { $env:BLACKBOX_DKG_PACKAGE } else { $DkgDefaultPackage }
$DkgIntegrity = if ($env:BLACKBOX_DKG_INTEGRITY) { $env:BLACKBOX_DKG_INTEGRITY } elseif ($DkgPackage -eq $DkgDefaultPackage) { $DkgDefaultIntegrity } else { "" }
# Packages whose install scripts the DKG node needs; npm 12 runs only those listed under
# "allowScripts" in the project's package.json (see the .sh for the whole story).
$DkgAllowScripts = @("@origintrail-official/dkg", "better-sqlite3", "@openuidev/lang-core")
$DkgDaemonUrl = "http://127.0.0.1:$DkgPort"
$DkgStoreQueueLimit = if ($env:BLACKBOX_DKG_STORE_QUEUE_LIMIT) { [int]$env:BLACKBOX_DKG_STORE_QUEUE_LIMIT } else { 512 }
$DkgListContextGraphsProjection = if ($env:BLACKBOX_DKG_LIST_CONTEXT_GRAPHS_PROJECTION) { $env:BLACKBOX_DKG_LIST_CONTEXT_GRAPHS_PROJECTION } else { "1" }
# The node's own sync defaults (DKG 10.0.25: 10 sync jobs, queue 20), so verified data and community
# data sync side by side (bench 2026-10-22; was 1/1 from the original installer).
$DkgSyncGlobalMaxInflight = "10"
$DkgSyncGlobalQueueLimit = "20"
$script:DkgDurableSyncEnabled = if ($env:BLACKBOX_DKG_DURABLE_SYNC_ENABLED) { $env:BLACKBOX_DKG_DURABLE_SYNC_ENABLED } else { "1" }
$DkgCatchupMaxConcurrentPeers = "1"
$DkgStoreQueueWaitTimeoutMs = "300000"
$script:DkgNodeOptions = ""
$NodeMajor   = if ($env:BLACKBOX_NODE_MAJOR)  { [int]$env:BLACKBOX_NODE_MAJOR } else { 22 }
$DefaultContextGraphId = "0x37b1Fdfd134e2b17583bCBdD3034F91504cD9C70/agent-blackbox-vm"
$ContextGraphId = if ($env:BLACKBOX_CONTEXT_GRAPH_ID) { $env:BLACKBOX_CONTEXT_GRAPH_ID } else { $DefaultContextGraphId }
# DKG 10.0.21+ recovery speed-ups (KI-282), both off by default in the node. The exact
# batch stream is read ONLY from the environment, so the node launch below passes it.
$DkgExactBatchStreamEnabled = if ($env:BLACKBOX_DKG_EXACT_BATCH_STREAM_ENABLED) { $env:BLACKBOX_DKG_EXACT_BATCH_STREAM_ENABLED } else { "1" }
$DkgVmRecoveryPrefetchEnabled = if ($env:BLACKBOX_DKG_VM_RECOVERY_PREFETCH_ENABLED) { $env:BLACKBOX_DKG_VM_RECOVERY_PREFETCH_ENABLED } else { "1" }
$GraphPeerId = if ($env:BLACKBOX_GRAPH_PEER_ID) { $env:BLACKBOX_GRAPH_PEER_ID } else { "12D3KooWBJskzr2unXQG9mR3LRZFUJoxWr1PN6hTbyWyKndHXjZM" }
$CatchupTimeout = if ($env:BLACKBOX_DKG_CATCHUP_TIMEOUT) { [int]$env:BLACKBOX_DKG_CATCHUP_TIMEOUT } else { 3600 }
$script:InstallIncomplete = $false
$script:DkgAlreadyRunning = $false
$script:DkgFreshState = $false
$script:DkgForeignEndpoint = $false
$script:DkgRestartRequired = $false
$script:DkgRuntimeMarker = Join-Path $DkgHome ".blackbox-runtime.sha256"
$script:DkgNodePathMarker = Join-Path $DkgHome ".blackbox-node-path"
$script:DkgStoreResetMarker = Join-Path $DkgHome ".blackbox-store-reset-pending"
$script:DkgRuntimeFingerprint = ""

# ── Echo helpers (DRY) ──────────────────────────────────────────────────────
function Write-Step    { param($m) Write-Host "-> $m" -ForegroundColor Cyan }
function Write-Ok      { param($m) Write-Host "[OK] $m" -ForegroundColor Green }
function Write-Warn2   { param($m) Write-Host "[!] $m" -ForegroundColor Yellow }
function Write-Err2    { param($m) Write-Host "[X] $m" -ForegroundColor Red }
function Write-Heading { param($m) Write-Host ""; Write-Host $m -ForegroundColor Green }

function Write-Banner {
    Write-Host ""
    Write-Host "  +-----------------------------------------------------------+" -ForegroundColor Green
    Write-Host "  |        [S] Agent Blackbox - installer            |" -ForegroundColor Green
    Write-Host "  +-----------------------------------------------------------+" -ForegroundColor Green
    Write-Host "  |  A threat-graph immune system for your AI agent.          |" -ForegroundColor Green
    Write-Host "  |  Detect prompt injection, tool escalation & bad deps -    |" -ForegroundColor Green
    Write-Host "  |  shared across agents via the OriginTrail DKG.            |" -ForegroundColor Green
    Write-Host "  +-----------------------------------------------------------+" -ForegroundColor Green
    Write-Host ""
}

function Show-Usage {
    @"
Agent Blackbox installer (Windows)

Usage: blackbox-install.ps1 [-SkipDkg] [-StoreBackend auto|blazegraph|oxigraph] [-Help]

Options:
  -SkipDkg          Skip DKG setup; plugin installs but first-run protection is incomplete
  -StoreBackend     Store backend (default: auto; Blazegraph preferred, Oxigraph fallback asks first)
  -Help             Show this help and exit

The DKG node bootstraps on mainnet. The default context graph is public, and
subscribing and reading need no funds.

Environment overrides:
	  BLACKBOX_REPO_URL, BLACKBOX_REPO_BRANCH, HERMES_HOME, BLACKBOX_NODE_MAJOR,
	  BLACKBOX_CONTEXT_GRAPH_ID, BLACKBOX_GRAPH_PEER_ID,
	  BLACKBOX_DKG_PORT, BLACKBOX_DKG_STORE_PORT,
	  BLACKBOX_DKG_STORE_URL, BLACKBOX_DKG_HOME,
	  BLACKBOX_DKG_CLI_DIR, BLACKBOX_DKG_BIN, BLACKBOX_DKG_PACKAGE,
	  BLACKBOX_DKG_DAEMON_URL,
	  BLACKBOX_DKG_STORE_QUEUE_LIMIT, BLACKBOX_DKG_LIST_CONTEXT_GRAPHS_PROJECTION,
	  BLACKBOX_DKG_CATCHUP_TIMEOUT

Blackbox uses its own DKG home and port by default:
  DKG home: $DkgHome
  DKG CLI:  $DkgBin
  DKG URL:  $DkgDaemonUrl
  Store:    auto (Blazegraph preferred; Oxigraph requires confirmation)

Note: Run the Hermes agent under WSL2 on Windows for best results.
This installer is idempotent. If DKG setup or the first ruleset sync cannot
complete, it exits non-zero and prints the command to retry.
"@ | Write-Host
}

if ($Help) { Show-Usage; exit 0 }
if ($StoreBackend -eq "oxigraph" -and $DkgStoreUrlExplicit) {
    Write-Err2 "BLACKBOX_DKG_STORE_URL cannot be combined with -StoreBackend oxigraph."
    exit 1
}

# ── Prerequisite checks ─────────────────────────────────────────────────────
function Test-Git {
    if (Get-Command git -ErrorAction SilentlyContinue) {
        Write-Ok "git $((git --version) -replace 'git version ','')"
    } else {
        Write-Err2 "git not found."
        Write-Step "Install: winget install Git.Git   (or https://git-scm.com/download/win)"
        exit 1
    }
}

function Resolve-Python {
    # Accept 3.11-3.13. Try py launcher pins, then python.
    $candidates = @("py -3.13", "py -3.12", "py -3.11", "python")
    foreach ($c in $candidates) {
        $parts = $c.Split(" ")
        $exe = $parts[0]
        if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) { continue }
        try {
            $args = @()
            if ($parts.Count -gt 1) { $args += $parts[1] }
            $args += @("-c", "import sys; raise SystemExit(0 if (3,11)<=sys.version_info[:2]<=(3,13) else 1)")
            & $exe @args 2>$null
            if ($LASTEXITCODE -eq 0) {
                $script:PyExe = $exe
                $script:PyArgs = if ($parts.Count -gt 1) { @($parts[1]) } else { @() }
                $ver = (& $exe @($script:PyArgs + @("-V")) 2>&1)
                Write-Ok "Python $ver ($c)"
                return
            }
        } catch { }
    }
    Write-Err2 "Python 3.11-3.13 not found."
    Write-Step "Install: winget install Python.Python.3.11   (or https://python.org/downloads)"
    exit 1
}

function Test-NodeOk {
    if (-not (Get-Command node -ErrorAction SilentlyContinue)) { return $false }
    $maj = [int]((node -v) -replace '^v','' -replace '\..*$','')
    return ($maj -ge $NodeMajor)
}

function Test-NodeJs {
    if (Test-NodeOk) {
        Write-Ok "Node.js $(node -v) + npm $(npm -v 2>$null)"
        $script:HasNode = $true
        return
    }
    if ($SkipDkg) { $script:HasNode = $false; return }
    Write-Warn2 "Node.js $NodeMajor+ not found - installing it automatically (winget) ..."
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        try {
            winget install --id OpenJS.NodeJS.LTS --silent --accept-source-agreements --accept-package-agreements | Out-Null
            # Refresh PATH so node/npm resolve in this session.
            $env:Path = [System.Environment]::GetEnvironmentVariable('Path','Machine') + ';' +
                        [System.Environment]::GetEnvironmentVariable('Path','User')
        } catch { Write-Warn2 "winget Node install did not complete." }
    } else {
        Write-Warn2 "winget not available for automatic Node install."
    }
    if (Test-NodeOk) {
        Write-Ok "Node.js $(node -v) installed"
        $script:HasNode = $true
    } else {
        $script:HasNode = $false
        Write-Step "Install Node ${NodeMajor} manually: winget install OpenJS.NodeJS.LTS (then re-run this installer)."
        Write-Step "The Blackbox plugin still works; the DKG node is added once Node is present."
    }
}

function Initialize-BlackboxDkgProcessEnvironment {
    $helper = Get-BlackboxHelper "blackbox-dkg-runtime-fingerprint.py"
    if (-not (Test-Path $helper)) {
        Write-Warn2 "DKG runtime settings helper is missing: $helper"
        return $false
    }
    $heapOutput = @(& $script:VenvPython $helper heap 8192 2>&1)
    $heapMb = "$($heapOutput | Select-Object -Last 1)".Trim()
    if ($LASTEXITCODE -ne 0 -or $heapMb -notmatch '^[1-9][0-9]*$') {
        if ($heapOutput) { $heapOutput | ForEach-Object { Write-Warn2 "$_" } }
        Write-Warn2 "Could not resolve a safe Node.js heap limit for the DKG daemon."
        return $false
    }
    $existingOptions = if ($env:NODE_OPTIONS) { $env:NODE_OPTIONS.Trim() } else { "" }
    $nodeOptionsOutput = @(& $script:VenvPython $helper node-options $heapMb $existingOptions 2>&1)
    if ($LASTEXITCODE -ne 0) {
        if ($nodeOptionsOutput) { $nodeOptionsOutput | ForEach-Object { Write-Warn2 "$_" } }
        Write-Warn2 "Could not prepare Node.js options for the DKG daemon."
        return $false
    }
    $script:DkgNodeOptions = "$($nodeOptionsOutput | Select-Object -Last 1)".Trim()
    # Sync transfers at once, by the machine's memory (see the .sh): 10 from 8 GB, 4 below.
    $slotsOutput = @(& $script:VenvPython $helper sync-slots 2>&1)
    $slots = "$($slotsOutput | Select-Object -Last 1)".Trim()
    if ($LASTEXITCODE -eq 0 -and $slots -match '^([0-9]+) ([0-9]+)$') {
        $script:DkgSyncGlobalMaxInflight = $Matches[1]
        $script:DkgSyncGlobalQueueLimit = $Matches[2]
    } else {
        Write-Warn2 "Could not size the node's sync slots for this machine; using the node's defaults."
    }
    # Record them so Blackbox's own node restarts relaunch with the same limits
    # (sync/process_limits.py). Not fatal: without the record they are recomputed.
    $limitsOutput = @(& $script:VenvPython $helper write-limits $DkgHome $script:DkgNodeOptions "$DkgStoreQueueLimit" 2>&1)
    if ($LASTEXITCODE -ne 0) {
        if ($limitsOutput) { $limitsOutput | ForEach-Object { Write-Warn2 "$_" } }
        Write-Warn2 "Could not record the DKG node limits; Blackbox restarts will recompute them."
    }
    Write-Ok "DKG safety limits: V8 heap ${heapMb}MB; $DkgSyncGlobalMaxInflight syncs at once"
    return $true
}

# The logon task an earlier install registered to run the node: it holds `dkg start --foreground`
# and retries a failed run, so it supervises the node. Stopping or starting that node with
# `dkg stop`/`dkg start` behind the task's back makes the two fight (KI-414; the systemd and
# launchd services in blackbox-install.sh behave the same way). Returns the task, or $null on a
# first install, before the task is registered.
function Get-BlackboxDkgTask {
    if (-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) { return $null }
    $task = Get-ScheduledTask -TaskName $DkgTaskName -ErrorAction SilentlyContinue
    if ($task -and $task.State -ne "Disabled") { return $task }
    return $null
}

# Start, stop or restart the node: through its logon task when there is one, else with the DKG
# CLI. Stopping the task first is a requested stop (no retry); the CLI stop that follows ends a
# node left behind by the task's process. Sets $LASTEXITCODE like the CLI, so every caller
# checks one result either way.
function Invoke-BlackboxDkgControl {
    param([ValidateSet("start", "stop", "restart")][string]$Action)
    if ($null -eq (Get-BlackboxDkgTask)) {
        if ($Action -eq "restart") {
            Invoke-BlackboxDkg stop
            if ($LASTEXITCODE -eq 0) { Invoke-BlackboxDkg start }
        } else {
            Invoke-BlackboxDkg $Action
        }
        return
    }
    try {
        if ($Action -ne "start") {
            Stop-ScheduledTask -TaskName $DkgTaskName -ErrorAction Stop
            Invoke-BlackboxDkg stop
        }
        if ($Action -ne "stop") { Start-ScheduledTask -TaskName $DkgTaskName -ErrorAction Stop }
        $global:LASTEXITCODE = 0
    } catch {
        Write-Warn2 "Could not $Action the DKG node through its task: $($_.Exception.Message)"
        $global:LASTEXITCODE = 1
    }
}

# Whether the checkout's HEAD is already part of origin/$RepoBranch's history - then moving to
# the new tip loses nothing. A depth-1 clone holds none of that history, so a bounded stretch
# more is fetched to check (never the whole repository); an answer it cannot give is "no",
# which keeps the strict fast-forward and its refusal (KI-417; mirrors blackbox-install.sh).
$HistoryCheckDepth = 200
function Test-BlackboxHeadInBranch {
    $remote = "refs/remotes/origin/$RepoBranch"
    & git -C $RepoDir merge-base --is-ancestor HEAD $remote 2>$null
    if ($LASTEXITCODE -eq 0) { return $true }
    if ((& git -C $RepoDir rev-parse --is-shallow-repository 2>$null) -ne "true") { return $false }
    & git -C $RepoDir fetch -q "--deepen=$HistoryCheckDepth" origin $RepoBranch 2>$null
    if ($LASTEXITCODE -ne 0) { return $false }
    & git -C $RepoDir merge-base --is-ancestor HEAD $remote 2>$null
    return ($LASTEXITCODE -eq 0)
}

function Invoke-BlackboxDkg {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
    # These process-level guards wrap the DKG entrypoint, so they apply equally
    # to external Blazegraph and the daemon-managed Oxigraph server.
    $names = @(
        "DKG_HOME",
        "DKG_ACCEPT_STORE_RESET",
        "DKG_STORE_QUEUE_LIMIT",
        "DKG_LIST_CONTEXT_GRAPHS_PROJECTION",
        "DKG_SYNC_ON_CONNECT_ENABLED",
        "DKG_SYNC_RECONCILER_ENABLED",
        "DKG_DURABLE_SYNC_ENABLED",
        "DKG_SYNC_GLOBAL_MAX_INFLIGHT",
        "DKG_SYNC_GLOBAL_QUEUE_LIMIT",
        "DKG_CATCHUP_MAX_CONCURRENT_PEERS",
        "DKG_STORE_QUEUE_WAIT_TIMEOUT_MS",
        "DKG_SYNC_TOTAL_TIMEOUT_MS",
        "DKG_SWM_RECOVERY_TIMEOUT_MS",
        "DKG_EXACT_BATCH_STREAM_ENABLED",
        "DKG_VM_RECOVERY_PREFETCH_ENABLED",
        "NODE_OPTIONS",
        "Path"
    )
    $previous = @{}
    foreach ($name in $names) {
        $previous[$name] = [System.Environment]::GetEnvironmentVariable($name, "Process")
    }
    try {
        $nodeCommand = Get-Command node -ErrorAction SilentlyContinue
        if ($nodeCommand -and $nodeCommand.Source) {
            $env:Path = "$(Split-Path -Parent $nodeCommand.Source);$env:Path"
        }
        $env:DKG_HOME = $DkgHome
        $env:DKG_ACCEPT_STORE_RESET = if (
            $script:DkgAcceptStoreReset -or (Test-Path $script:DkgStoreResetMarker)
        ) { "1" } else { "0" }
        $env:DKG_STORE_QUEUE_LIMIT = "$DkgStoreQueueLimit"
        $env:DKG_LIST_CONTEXT_GRAPHS_PROJECTION = "$DkgListContextGraphsProjection"
        $env:DKG_SYNC_ON_CONNECT_ENABLED = "0"
        $env:DKG_SYNC_RECONCILER_ENABLED = "0"
        $env:DKG_DURABLE_SYNC_ENABLED = $script:DkgDurableSyncEnabled
        $env:DKG_SYNC_GLOBAL_MAX_INFLIGHT = "$DkgSyncGlobalMaxInflight"
        $env:DKG_SYNC_GLOBAL_QUEUE_LIMIT = "$DkgSyncGlobalQueueLimit"
        $env:DKG_CATCHUP_MAX_CONCURRENT_PEERS = "$DkgCatchupMaxConcurrentPeers"
        $env:DKG_STORE_QUEUE_WAIT_TIMEOUT_MS = "$DkgStoreQueueWaitTimeoutMs"
        # No effect: the node reads neither of the next two (DKG 10.0.25 has its
        # sync limits built in).
        $env:DKG_SYNC_TOTAL_TIMEOUT_MS = "1800000"
        $env:DKG_SWM_RECOVERY_TIMEOUT_MS = "3600000"
        $env:DKG_EXACT_BATCH_STREAM_ENABLED = "$DkgExactBatchStreamEnabled"
        $env:DKG_VM_RECOVERY_PREFETCH_ENABLED = "$DkgVmRecoveryPrefetchEnabled"
        $env:NODE_OPTIONS = $script:DkgNodeOptions
        & $DkgBin @Args
    } finally {
        foreach ($name in $names) {
            if ($null -eq $previous[$name]) {
                Remove-Item "Env:$name" -ErrorAction SilentlyContinue
            } else {
                Set-Item "Env:$name" $previous[$name]
            }
        }
    }
}

function Test-BlackboxDkgState {
    return ((Test-Path (Join-Path $DkgHome "auth.token")) -or (Test-Path (Join-Path $DkgHome "config.json")))
}

function Prepare-BlackboxDkgRuntimeFingerprint {
    $fingerprinter = Get-BlackboxHelper "blackbox-dkg-runtime-fingerprint.py"
    if (-not (Test-Path $fingerprinter)) {
        $script:InstallIncomplete = $true
        Write-Warn2 "DKG runtime fingerprint helper is missing; loaded npm runtime cannot be verified."
        return $false
    }
    $nodeCommand = Get-Command node -ErrorAction SilentlyContinue
    if (-not $nodeCommand -or -not $nodeCommand.Source) {
        $script:InstallIncomplete = $true
        Write-Warn2 "Could not resolve the Node.js runtime for DKG fingerprinting."
        return $false
    }
    $fingerprintOutput = @(& $script:VenvPython $fingerprinter compute $DkgCliDir $DkgHome $nodeCommand.Source $DkgBin $DkgStoreQueueLimit $DkgListContextGraphsProjection $DkgSyncGlobalMaxInflight $script:DkgNodeOptions $DkgCatchupMaxConcurrentPeers $DkgStoreQueueWaitTimeoutMs 2>&1)
    if ($LASTEXITCODE -ne 0) {
        $script:InstallIncomplete = $true
        if ($fingerprintOutput) {
            $fingerprintOutput | ForEach-Object { Write-Warn2 "$_" }
        }
        Write-Warn2 "Could not fingerprint the configured DKG runtime; setup is incomplete."
        return $false
    }
    $script:DkgRuntimeFingerprint = "$($fingerprintOutput | Select-Object -Last 1)".Trim()
    $applied = if (Test-Path $script:DkgRuntimeMarker) {
        (Get-Content -Raw $script:DkgRuntimeMarker).Trim()
    } else {
        ""
    }
    if ($applied -ne $script:DkgRuntimeFingerprint) {
        $script:DkgRestartRequired = $true
    }
    return $true
}

function Save-BlackboxDkgRuntimeFingerprint {
    $fingerprinter = Get-BlackboxHelper "blackbox-dkg-runtime-fingerprint.py"
    if (-not $script:DkgRuntimeFingerprint) {
        $script:InstallIncomplete = $true
        Write-Warn2 "DKG runtime fingerprint is empty after restart."
        return $false
    }
    & $script:VenvPython $fingerprinter record $script:DkgRuntimeMarker $script:DkgRuntimeFingerprint
    if ($LASTEXITCODE -ne 0) {
        $script:InstallIncomplete = $true
        Write-Warn2 "DKG restarted, but its applied runtime fingerprint could not be recorded."
        return $false
    }
    $nodeCommand = Get-Command node -ErrorAction SilentlyContinue
    if ($nodeCommand -and $nodeCommand.Source) {
        Set-Content -LiteralPath $script:DkgNodePathMarker -Value $nodeCommand.Source
    }
    return $true
}

function Wait-BlackboxDkgRuntime {
    & $script:VenvPython (Get-BlackboxHelper "blackbox-native-bootstrap.py") wait $DkgHome $DkgDaemonUrl
    if ($LASTEXITCODE -ne 0) { return $false }
    $verifier = Get-BlackboxHelper "blackbox-dkg-runtime-fingerprint.py"
    $expectedCommit = (& $script:VenvPython $verifier commit $DkgCliDir).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $expectedCommit) {
        $script:InstallIncomplete = $true
        Write-Warn2 "Could not resolve the published DKG build commit."
        return $false
    }
    $null = & $script:VenvPython $verifier wait $DkgDaemonUrl $expectedCommit 90
    if ($LASTEXITCODE -ne 0) {
        $script:InstallIncomplete = $true
        Write-Warn2 "The DKG daemon did not activate npm build $($expectedCommit.Substring(0, 12))."
        return $false
    }
    Write-Ok "DKG daemon is ready on npm build $($expectedCommit.Substring(0, 12))"
    return $true
}

function Move-LegacyBlackboxDkgHome {
    $legacyHome = Join-Path $HOME ".hermes\blackbox\dkg"
    $legacyBin = Join-Path $HOME ".hermes\blackbox\dkg-cli\node_modules\.bin\dkg.cmd"
    if ([System.IO.Path]::GetFullPath($legacyHome) -eq [System.IO.Path]::GetFullPath($DkgHome)) { return $true }
    if (-not (Test-Path (Join-Path $legacyHome "config.json"))) { return $true }

    $pidPath = Join-Path $legacyHome "daemon.pid"
    $legacyPid = if (Test-Path $pidPath) { (Get-Content -Raw $pidPath).Trim() } else { "" }
    $legacyProcess = if ($legacyPid -match '^\d+$') {
        Get-Process -Id ([int]$legacyPid) -ErrorAction SilentlyContinue
    } else { $null }
    if ($legacyProcess) {
        if (-not (Test-Path $legacyBin)) {
            $script:InstallIncomplete = $true
            Write-Warn2 "The deprecated Blackbox DKG is running, but its stop command is missing: $legacyBin"
            return $false
        }
        Write-Step "Stopping the deprecated Blackbox DKG at $legacyHome ..."
        $previousHome = $env:DKG_HOME
        try {
            $env:DKG_HOME = $legacyHome
            & $legacyBin stop
            if ($LASTEXITCODE -ne 0) { throw "legacy dkg stop exit $LASTEXITCODE" }
            if (Get-Process -Id ([int]$legacyPid) -ErrorAction SilentlyContinue) {
                throw "legacy DKG process is still running"
            }
        } catch {
            $script:InstallIncomplete = $true
            Write-Warn2 "Could not stop the deprecated Blackbox DKG safely."
            return $false
        } finally {
            if ($null -eq $previousHome) { Remove-Item Env:DKG_HOME -ErrorAction SilentlyContinue }
            else { $env:DKG_HOME = $previousHome }
        }
    }

    if (-not (Test-Path $DkgHome)) {
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $DkgHome) | Out-Null
        Move-Item $legacyHome $DkgHome
        Write-Ok "Migrated the Blackbox DKG identity and graph state into this checkout"
    } else {
        Write-Warn2 "Deprecated DKG state remains at $legacyHome (stopped); current state is $DkgHome."
    }
    return $true
}

function Set-BlackboxDkgPort {
    param([int]$Port)
    $script:DkgPort = $Port
    $script:DkgDaemonUrl = "http://127.0.0.1:$Port"
}

function Test-PortInUse {
    param([int]$Port)
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $async = $client.BeginConnect("127.0.0.1", $Port, $null, $null)
        if ($async.AsyncWaitHandle.WaitOne(500)) {
            $client.EndConnect($async)
            return $true
        }
        return $false
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

function Select-BlackboxDkgPort {
    for ($candidate = $DkgPort; $candidate -le 9399; $candidate++) {
        if (-not (Test-PortInUse $candidate)) {
            Set-BlackboxDkgPort $candidate
            Write-Ok "Using Blackbox DKG port $DkgPort"
            return $true
        }
    }
    return $false
}

function Test-BlackboxDkgPort {
    try {
        Invoke-WebRequest -Uri "$DkgDaemonUrl/api/status" -UseBasicParsing -TimeoutSec 3 | Out-Null
        if (Test-BlackboxDkgState) {
            Write-Ok "Blackbox DKG endpoint already responds at $DkgDaemonUrl"
            $script:DkgAlreadyRunning = $true
            return $true
        }
        Write-Warn2 "Port $DkgPort already has a DKG endpoint, but $DkgHome has no Blackbox node state."
        $script:DkgForeignEndpoint = $true
        if ($DkgPortExplicit) {
            $script:InstallIncomplete = $true
            Write-Step "Set BLACKBOX_DKG_PORT to a free port or stop the process on $DkgDaemonUrl."
            return $false
        }
        Write-Step "Choosing a different Blackbox-owned port so the existing DKG node is untouched."
        if (Select-BlackboxDkgPort) { return $true }
        $script:InstallIncomplete = $true
        Write-Warn2 "Could not find a free Blackbox DKG port in 9320-9399."
        return $false
    } catch { }

    if (Test-PortInUse $DkgPort) {
        Write-Warn2 "Port $DkgPort is already in use, but it did not answer as a DKG node at $DkgDaemonUrl."
        if ($DkgPortExplicit) {
            $script:InstallIncomplete = $true
            Write-Step "Set BLACKBOX_DKG_PORT to a free port and re-run the installer."
            return $false
        }
        Write-Step "Choosing a different Blackbox-owned port."
        if (Select-BlackboxDkgPort) { return $true }
        $script:InstallIncomplete = $true
        Write-Warn2 "Could not find a free Blackbox DKG port in 9320-9399."
        return $false
    }
    return $true
}

function Test-BlackboxBlazegraph {
    $helper = Get-BlackboxHelper "blackbox-blazegraph.mjs"
    Write-Step "Checking the Blazegraph SPARQL endpoint ..."
    try {
        $output = @(& node $helper check $DkgCliDir $DkgStoreUrl 2>&1)
        $code = $LASTEXITCODE
    } catch {
        $output = @($_)
        $code = 1
    }
    if ($code -ne 0) {
        $output | ForEach-Object { Write-Err2 ([string]$_) }
        Write-Err2 "Blazegraph is unavailable or returned an error at $DkgStoreUrl."
        return $false
    }
    Write-Ok "Blazegraph SPARQL endpoint is healthy at $DkgStoreUrl"
    return $true
}

function Show-DockerSetupHint {
    Write-Heading "Docker is required for the Blazegraph store"
    Write-Err2 "Docker Desktop is not installed or its engine is not running."
    Write-Step "Install Docker Desktop, start it, wait until it reports Ready, then re-run Blackbox:"
    Write-Host ""
    Write-Host "    winget install -e --id Docker.DockerDesktop --accept-source-agreements --accept-package-agreements" -ForegroundColor Yellow
    Write-Host '    Start-Process "$Env:ProgramFiles\Docker\Docker\Docker Desktop.exe"' -ForegroundColor Yellow
    Write-Host ""
    Write-Step "Docker's official guide: https://docs.docker.com/desktop/setup/install/windows-install/"
    Write-Step "Verify Docker before retrying: docker info"
}

function Test-DockerForBlazegraph {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        $script:DockerRequired = $true
        Show-DockerSetupHint
        return $false
    }
    try {
        & docker info *> $null
        if ($LASTEXITCODE -ne 0) { throw "docker info exit $LASTEXITCODE" }
    } catch {
        $script:DockerRequired = $true
        Show-DockerSetupHint
        return $false
    }
    Write-Ok "Docker engine is ready for Blazegraph"
    return $true
}

function Use-BlackboxOxigraph {
    $script:DockerRequired = $false
    $script:DkgSelectedStoreBackend = "oxigraph-server"
    $script:DkgStoreUrl = ""
    $script:DkgStoreManagedByDkg = $false
    Write-Warn2 "Using the DKG-managed Oxigraph store (no Docker container required)."
}

function Confirm-OxigraphFallback {
    param([string]$Reason)
    Write-Warn2 $Reason
    Write-Step "Recommended default: stop here, install/start or repair Docker, then re-run Blackbox with Blazegraph."
    Write-Step "Alternative: type y to continue now with the DKG-managed Oxigraph store."
    try {
        $answer = Read-Host "Continue with Oxigraph instead? [y/N]"
    } catch {
        Write-Warn2 "No interactive terminal is available, so Oxigraph was not selected."
        Write-Step "To choose it explicitly, re-run with: -StoreBackend oxigraph"
        return $false
    }
    if ($answer -match '^(y|yes)$') { return $true }
    Write-Step "Keeping Blazegraph as the default. Set up Docker and re-run the installer."
    return $false
}

function Get-BlackboxStoreDescription {
    if ($script:DkgSelectedStoreBackend -eq "native") { return "Blazegraph native verified bootstrap (DKG-managed)" }
    if ($script:DkgSelectedStoreBackend -eq "oxigraph-server") {
        return "Oxigraph (DKG-managed local server)"
    }
    if ($script:DkgSelectedStoreBackend -eq "blazegraph") {
        return "Blazegraph at $DkgStoreUrl"
    }
    if ($DkgStoreUrl) { return $DkgStoreUrl }
    return "not configured"
}

function Initialize-BlackboxStore {
    $nativeHelper = Get-BlackboxHelper "blackbox-native-bootstrap.py"
    & $script:VenvPython $nativeHelper plan $DkgHome $DkgCliDir $DkgBin $ContextGraphId $DefaultContextGraphId $StoreBackend (Join-Path $HermesHome "config.yaml")
    if ($LASTEXITCODE -eq 0) {
        $script:DkgSelectedStoreBackend = "native"
        $script:DkgStoreUrl = ""
        $script:DkgStoreManagedByDkg = $true
        $script:DockerRequired = $false
        return $true
    }
    if ($LASTEXITCODE -ne 3) { return $false }
    $helper = Get-BlackboxHelper "blackbox-blazegraph.mjs"
    $namespace = "agent-blackbox"
    $existingBackend = ""
    $existingUrl = ""
    $existingManaged = $false
    $configPath = Join-Path $DkgHome "config.json"
    if (Test-Path $configPath) {
        try {
            $existing = Get-Content -Raw $configPath | ConvertFrom-Json
            if ($existing.name) { $namespace = [string]$existing.name }
            if ($existing.store.backend) { $existingBackend = [string]$existing.store.backend }
            if ($existing.store.options.url) { $existingUrl = [string]$existing.store.options.url }
            $existingManaged = $existing.store.options.managedByDkg -eq $true
        } catch { }
    }
    $script:DkgStoreNamespace = $namespace

    if ($StoreBackend -eq "oxigraph") {
        Use-BlackboxOxigraph
        return $true
    }
    if ($DkgStoreUrlExplicit) {
        $script:DkgSelectedStoreBackend = "blazegraph"
        $script:DkgStoreManagedByDkg = $false
        Write-Step "Using operator-managed Blazegraph at $DkgStoreUrl"
        return (Test-BlackboxBlazegraph)
    }
    if ($StoreBackend -eq "auto" -and $existingBackend -eq "oxigraph-server") {
        Write-Step "Preserving the existing DKG-managed Oxigraph store."
        Use-BlackboxOxigraph
        return $true
    }
    if ($existingBackend -eq "blazegraph" -and -not $existingManaged -and $existingUrl) {
        $script:DkgSelectedStoreBackend = "blazegraph"
        $script:DkgStoreUrl = $existingUrl
        $script:DkgStoreManagedByDkg = $false
        Write-Step "Reusing operator-managed Blazegraph at $DkgStoreUrl"
        return (Test-BlackboxBlazegraph)
    }
    if ($existingBackend -eq "blazegraph" -and $existingManaged -and $existingUrl) {
        $script:DkgSelectedStoreBackend = "blazegraph"
        $script:DkgStoreUrl = $existingUrl
        $script:DkgStoreManagedByDkg = $true
        if (Test-BlackboxBlazegraph) { return $true }
        if ($script:DkgAlreadyRunning) {
            Write-Step "Pausing DKG so its overloaded store can pass recovery checks ..."
            Invoke-BlackboxDkgControl stop
            if ($LASTEXITCODE -eq 0) {
                $script:DkgAlreadyRunning = $false
                if (Test-BlackboxBlazegraph) { return $true }
                $managedContainer = "dkg-blazegraph-$namespace"
                $storeRestarted = $false
                Write-Step "Restarting the unresponsive managed Blazegraph container ..."
                & docker restart $managedContainer | Out-Null
                if ($LASTEXITCODE -eq 0) {
                    $storeRestarted = $true
                } else {
                    # A wedged JVM can leave the container stopped even though
                    # Docker reports a failed graceful restart. Start the same
                    # container so its graph volume remains intact.
                    $running = (& docker inspect -f '{{.State.Running}}' $managedContainer 2>$null)
                    if ($LASTEXITCODE -eq 0 -and "$running".Trim() -eq "false") {
                        & docker start $managedContainer | Out-Null
                        if ($LASTEXITCODE -eq 0) { $storeRestarted = $true }
                    }
                    if (-not $storeRestarted) {
                        Write-Warn2 "Could not restart managed container $managedContainer."
                    }
                }
                if ($storeRestarted -and (Test-BlackboxBlazegraph)) {
                    return $true
                }
            } else {
                Write-Warn2 "Could not pause the Blackbox DKG daemon before store recovery."
            }
        }
        Write-Warn2 "The managed Blazegraph endpoint is down; attempting Docker recovery."
    }
    # `hermes blackbox setup` (a Hermes plugin-catalog install) needs no Docker: without it the store is
    # the DKG-managed Oxigraph, chosen rather than asked about. The iex installer keeps asking first.
    $dockerRunning = $false
    if (Get-Command docker -ErrorAction SilentlyContinue) {
        & docker info *> $null
        $dockerRunning = ($LASTEXITCODE -eq 0)
    }
    if ($SetupOnly -and $StoreBackend -eq "auto" -and -not $dockerRunning) {
        Write-Step "Docker is not available here, so setup uses the DKG-managed Oxigraph store (no Docker needed)."
        Write-Step "To move to Blazegraph later: install Docker, then run: hermes blackbox setup --store blazegraph"
        Use-BlackboxOxigraph
        return $true
    }
    if (-not (Test-DockerForBlazegraph)) {
        if ($StoreBackend -eq "auto" -and
            (Confirm-OxigraphFallback "Blazegraph cannot be installed because Docker is unavailable.")) {
            Use-BlackboxOxigraph
            return $true
        }
        return $false
    }
    if (-not (Test-Path $helper)) {
        Write-Warn2 "Blazegraph provisioner helper is missing: $helper"
        if ($StoreBackend -eq "auto" -and
            (Confirm-OxigraphFallback "Blazegraph provisioning cannot continue without its helper.")) {
            Use-BlackboxOxigraph
            return $true
        }
        return $false
    }

    Write-Step "Provisioning Blazegraph through the DKG Docker provisioner ..."
    try {
        $output = @(& node $helper $DkgCliDir $namespace $DkgStorePort)
        if ($LASTEXITCODE -ne 0) { throw "Blazegraph helper exit $LASTEXITCODE" }
        $result = ($output | Select-Object -Last 1) | ConvertFrom-Json
        $script:DkgStoreUrl = [string]$result.url
        $script:DkgStorePort = [int]$result.port
        $script:DkgSelectedStoreBackend = "blazegraph"
        $script:DkgStoreManagedByDkg = $true
        if (Test-BlackboxBlazegraph) { return $true }
        if ($StoreBackend -eq "auto" -and
            (Confirm-OxigraphFallback "Blazegraph did not pass its SPARQL health check.")) {
            Use-BlackboxOxigraph
            return $true
        }
        return $false
    } catch {
        if ($StoreBackend -eq "auto" -and
            (Confirm-OxigraphFallback "Blazegraph provisioning failed even though Docker is available.")) {
            Use-BlackboxOxigraph
            return $true
        }
        Write-Warn2 "Could not provision Blazegraph."
        return $false
    }
}

function Reset-FreshManagedBlazegraph {
    if (-not $script:DkgFreshState) { return $true }
    if ($script:DkgSelectedStoreBackend -ne "blazegraph") { return $true }
    if (-not $script:DkgStoreManagedByDkg) { return $true }
    if ($DkgStoreUrlExplicit) { return $true }
    if ($script:DkgForeignEndpoint) {
        Write-Err2 "Refusing to reset the Blackbox namespace while an unrelated DKG endpoint is running."
        Write-Step "Stop that DKG node or set BLACKBOX_DKG_STORE_URL to an operator-managed store."
        return $false
    }
    $helper = Get-BlackboxHelper "blackbox-blazegraph.mjs"
    Write-Step "Clearing the installer-managed Blazegraph namespace for the fresh DKG identity ..."
    try {
        & node $helper reset $DkgCliDir $DkgStoreUrl $script:DkgStoreNamespace *> $null
        if ($LASTEXITCODE -ne 0) { throw "Blazegraph reset exit $LASTEXITCODE" }
    } catch {
        Write-Err2 "Could not clear the stale installer-managed Blackbox namespace."
        return $false
    }
    Write-Ok "Fresh Blackbox store is empty and ready for the new DKG identity"
    return $true
}

function Ensure-BlackboxDkgConfig {
    $writer = @'
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
# Relay reachability (see the .sh installer for the full rationale): DKG builds
# its relay set from `relayPeers`; empty -> network-isolation denies every
# relayed connection and the node holds 0 reservations, so no one can reach it.
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
# does not compete for the single sync slot. Any other graph keeps the steady one.
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
'@
    $writerFile = Join-Path $env:TEMP "blackbox_dkg_config.py"
    Set-Content -Path $writerFile -Value $writer -Encoding UTF8
    try {
        $configState = & $VenvPython $writerFile $DkgHome $DkgPort $script:DkgSelectedStoreBackend $DkgStoreUrl $DkgStoreManagedByDkg $ContextGraphId $DefaultContextGraphId "" "$DkgSyncGlobalMaxInflight" "$DkgSyncGlobalQueueLimit"
        if ($LASTEXITCODE -ne 0) { throw "dkg config exit $LASTEXITCODE" }
        $configResult = $configState | Select-Object -Last 1
        if ($configResult -eq "switched") {
            $script:DkgAcceptStoreReset = $true
            $script:DkgRestartRequired = $true
            Write-Warn2 "Switching DKG storage to $script:DkgSelectedStoreBackend; the previous store will not be deleted."
            Write-Step "Backup config: $DkgHome\config.json.pre-$script:DkgSelectedStoreBackend"
        } elseif ($configResult -eq "changed") {
            $script:DkgRestartRequired = $true
        }
    } finally {
        Remove-Item $writerFile -Force -ErrorAction SilentlyContinue
    }
}

# ── Locate (or fetch) the repo ──────────────────────────────────────────────
function Test-BlackboxRepoCheckout {
    param([string]$Path)
    if (-not (Test-Path "$Path\.git")) { return $false }
    if (-not (Test-Path "$Path\pyproject.toml")) { return $false }
    if (-not (Test-Path "$Path\plugins\blackbox")) { return $false }
    try {
        & git -C $Path rev-parse --verify HEAD *> $null
        return $LASTEXITCODE -eq 0
    } catch {
        return $false
    }
}

function Move-BrokenBlackboxRepoAside {
    param([string]$Path)
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $backup = "$Path.broken-$stamp-$PID"
    Write-Warn2 "Existing install at $Path is incomplete or not an Agent Blackbox checkout."
    Move-Item -LiteralPath $Path -Destination $backup
    Write-Step "Preserved it at $backup"
}

function Resolve-Repo {
    $scriptDir = Split-Path -Parent $PSCommandPath
    if ($scriptDir) {
        $d = Split-Path -Parent $scriptDir
        if ((Test-Path "$d\pyproject.toml") -and (Test-Path "$d\plugins\blackbox")) {
            $script:RepoDir = $d
            Write-Step "Using existing checkout at $RepoDir"
            return
        }
    }
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Err2 "git is required to download Blackbox. Install git and re-run."
        exit 1
    }
    $script:RepoDir = $DefaultRepoDir
    if ((Test-Path $RepoDir) -and -not (Test-BlackboxRepoCheckout $RepoDir)) {
        Move-BrokenBlackboxRepoAside $RepoDir
    }
    if (Test-BlackboxRepoCheckout $RepoDir) {
        Write-Step "Updating existing clone at $RepoDir"
        # Single-branch shallow clone: add the branch to the fetch rule once, so a
        # DIFFERENT branch becomes a normal remote branch to check out (KI-287).
        $branchRule = "+refs/heads/${RepoBranch}:refs/remotes/origin/${RepoBranch}"
        $fetchRules = @(& git -C $RepoDir config --get-all remote.origin.fetch)
        if ($fetchRules -notcontains $branchRule) { & git -C $RepoDir remote set-branches --add origin $RepoBranch }
        # What this install last fetched: HEAD equal to it = no local commits (KI-294).
        $fetchedBefore = (& git -C $RepoDir rev-parse -q --verify "refs/remotes/origin/$RepoBranch" 2>$null)
        & git -C $RepoDir fetch --depth 1 origin $RepoBranch
        if ($LASTEXITCODE -ne 0) { throw "Could not fetch $RepoBranch from $RepoUrl" }
        & git -C $RepoDir checkout $RepoBranch
        if ($LASTEXITCODE -ne 0) { throw "Could not switch $RepoDir to $RepoBranch (git's reason is above)" }
        # A depth-1 fetch brings the new tip without its parent, so `pull --ff-only`
        # refuses every update (KI-294): move to the new tip when the install holds
        # no work of its own (--keep still refuses uncommitted changes).
        # HEAD can also be an older commit of the branch this install did not fetch last (the
        # checkout was moved outside the installer): still no work of its own, but a depth-1
        # clone cannot show it (KI-417) - Test-BlackboxHeadInBranch fetches a bounded stretch.
        $head = (& git -C $RepoDir rev-parse HEAD)
        if (($fetchedBefore -and $head -eq $fetchedBefore) -or (Test-BlackboxHeadInBranch)) {
            & git -C $RepoDir reset -q --keep "refs/remotes/origin/$RepoBranch"
            if ($LASTEXITCODE -ne 0) { throw "Could not update $RepoDir to origin/${RepoBranch}: it has uncommitted changes (git's reason is above)" }
        } else {
            & git -C $RepoDir pull --ff-only origin $RepoBranch
            if ($LASTEXITCODE -ne 0) {
                $own = (& git -C $RepoDir log --oneline -3 "refs/remotes/origin/$RepoBranch..HEAD" 2>$null) -join "; "
                throw "Could not fast-forward $RepoDir to origin/${RepoBranch}: it holds commits that are not on that branch: $own"
            }
        }
    } else {
        Write-Step "Cloning $RepoUrl -> $RepoDir"
        & git clone --depth 1 --branch $RepoBranch $RepoUrl $RepoDir
        if ($LASTEXITCODE -ne 0) { throw "Could not clone $RepoUrl into $RepoDir" }
    }
    if (-not (Test-BlackboxRepoCheckout $RepoDir)) {
        throw "$RepoDir is not a complete Agent Blackbox Python project"
    }
    Write-Ok "Repo ready at $RepoDir"
}

# ── Python venv + editable install ──────────────────────────────────────────
function Install-PythonEnv {
    Write-Heading "Installing Hermes + Blackbox (Python)"
    $script:VenvDir = "$RepoDir\venv"
    $script:VenvPython = "$VenvDir\Scripts\python.exe"
    if (-not (Test-Path $VenvDir)) {
        Write-Step "Creating virtual environment ..."
        & $script:PyExe @($script:PyArgs + @("-m", "venv", $VenvDir))
    } else {
        Write-Step "Reusing existing venv at $VenvDir"
    }
    Write-Step "Upgrading pip and installing Hermes + Agent Blackbox (web extras, editable) ..."
    & $VenvPython -m pip install --upgrade pip | Out-Null
    Push-Location $RepoDir
    try {
        & $VenvPython -m pip install -e ".[web]"
    } finally {
        Pop-Location
    }
    Write-Ok "Blackbox installed (editable, with dashboard extras)"
    $script:HermesBin = "$VenvDir\Scripts\hermes.exe"
}

# ── Global blackbox command (per-user shim) ─────────────────────────────────
# A helper script shipped beside this installer: scripts\ in a checkout, the plugin's setup\
# folder in setup-only mode (BLACKBOX_HELPER_DIR).
function Get-BlackboxHelper([string]$Name) {
    if ($env:BLACKBOX_HELPER_DIR) { return Join-Path $env:BLACKBOX_HELPER_DIR $Name }
    return Join-Path $RepoDir "scripts\$Name"
}

# Setup-only mode: use the Hermes the caller runs in (HERMES_BIN, VENV_DIR).
function Use-RunningHermes {
    Write-Heading "Using your Hermes"
    $script:VenvDir = $env:VENV_DIR
    $script:VenvPython = Join-Path $env:VENV_DIR "Scripts\python.exe"
    $script:HermesBin = $env:HERMES_BIN
    if (-not ($script:HermesBin -and (Test-Path $script:HermesBin)) -or -not (Test-Path $script:VenvPython)) {
        Write-Err2 "Setup-only mode needs the Hermes it runs in (HERMES_BIN, VENV_DIR); run it as: hermes blackbox setup"
        exit 1
    }
    Write-Ok "Hermes: $script:HermesBin"
}

function Install-BlackboxCommand {
    $shimDir = Join-Path $HOME ".local\bin"
    $shimPath = Join-Path $shimDir "blackbox.cmd"
    New-Item -ItemType Directory -Force -Path $shimDir | Out-Null

    $managedMarker = "managed-by: agent-blackbox-installer"
    if ((Test-Path $shimPath) -and -not (Select-String -Path $shimPath -SimpleMatch $managedMarker -Quiet)) {
        Write-Warn2 "Not replacing existing command at $shimPath; remove or rename it, then re-run the installer."
        return
    }

    $launcher = @"
@echo off
@rem managed-by: agent-blackbox-installer
"$HermesBin" blackbox %*
exit /b %ERRORLEVEL%
"@
    [IO.File]::WriteAllText($shimPath, $launcher, [Text.Encoding]::ASCII)
    Write-Ok "Installed blackbox -> hermes blackbox ($shimPath)"

    $normalizedShim = $shimDir.TrimEnd('\')
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $userEntries = @($userPath -split ';' | ForEach-Object { $_.Trim().TrimEnd('\') })
    if ($userEntries -notcontains $normalizedShim) {
        try {
            $newUserPath = if ([string]::IsNullOrWhiteSpace($userPath)) {
                $shimDir
            } else {
                "$shimDir;$userPath"
            }
            [Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
            Write-Ok "Added $shimDir to the user PATH"
        } catch {
            Write-Warn2 "Could not add $shimDir to the user PATH automatically: $_"
        }
    }
    $processEntries = @($env:Path -split ';' | ForEach-Object { $_.Trim().TrimEnd('\') })
    if ($processEntries -notcontains $normalizedShim) {
        $env:Path = "$shimDir;$env:Path"
    }
}

# ── DKG node CLI + bootstrap ────────────────────────────────────────────────
function Install-BlackboxDkgPackage {
    if (Test-Path (Join-Path $DkgHome "config.json")) {
        & $script:VenvPython (Get-BlackboxHelper "blackbox-native-bootstrap.py") retain $DkgHome $DkgBin
        if ($LASTEXITCODE -eq 0) { Write-Ok "Preserved the native journal's compatible DKG runtime"; return $true }
        if ($LASTEXITCODE -ne 3) { return $false }
    }
    $backupDir = ""
    $packageJson = Join-Path $DkgCliDir "node_modules\@origintrail-official\dkg\package.json"
    $npmLog = Join-Path $HermesHome "logs\blackbox-npm-install.log"
    $npmCommand = Get-Command npm -ErrorAction SilentlyContinue
    if (-not $npmCommand) {
        Write-Warn2 "npm is required to install the published OriginTrail DKG package."
        return $false
    }

    # The package is downloaded first and the tarball's own sha512 compared with the pin; only a
    # tarball that matches is handed to npm install. No pin = not installed (see the .sh).
    $tarball = ""
    if ($DkgIntegrity -eq "unpinned") {
        Write-Warn2 "BLACKBOX_DKG_INTEGRITY=unpinned: $DkgPackage is installed without a checksum check."
    } elseif (-not $DkgIntegrity) {
        Write-Warn2 "No checksum is pinned for $DkgPackage; it was not installed. Set BLACKBOX_DKG_INTEGRITY to its sha512 (npm view $DkgPackage dist.integrity), or BLACKBOX_DKG_INTEGRITY=unpinned to skip the check knowingly."
        return $false
    } else {
        $packDir = Join-Path $env:TEMP ("blackbox-dkg-pack-" + [System.IO.Path]::GetRandomFileName())
        New-Item -ItemType Directory -Force -Path $packDir | Out-Null
        $packed = @(& npm pack $DkgPackage --pack-destination $packDir --silent 2>$null)
        $packedFile = "$($packed | Select-Object -Last 1)".Trim()
        if ($LASTEXITCODE -ne 0 -or -not $packedFile -or -not (Test-Path (Join-Path $packDir $packedFile))) {
            Remove-Item $packDir -Recurse -Force -ErrorAction SilentlyContinue
            Write-Warn2 "Could not download $DkgPackage from the npm registry."
            return $false
        }
        $tarball = Join-Path $packDir $packedFile
        $sha512 = [System.Security.Cryptography.SHA512]::Create()
        $actual = "sha512-" + [Convert]::ToBase64String($sha512.ComputeHash([System.IO.File]::ReadAllBytes($tarball)))
        if ($actual -ne $DkgIntegrity) {
            Remove-Item $packDir -Recurse -Force -ErrorAction SilentlyContinue
            Write-Warn2 "The downloaded $DkgPackage ($actual) is not the one this Blackbox release pins; it was not installed."
            return $false
        }
        Write-Ok "DKG package checksum verified ($DkgPackage)"
    }

    if (Test-Path (Join-Path $DkgCliDir ".git")) {
        $backupDir = "$DkgCliDir.custom-backup-$(Get-Date -Format yyyyMMddHHmmss)"
        Write-Step "Moving the custom DKG checkout to $backupDir"
        try {
            Move-Item $DkgCliDir $backupDir
        } catch {
            Write-Warn2 "Could not preserve the custom DKG checkout before installing npm DKG: $_"
            return $false
        }
    }

    New-Item -ItemType Directory -Force -Path $DkgCliDir | Out-Null
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $npmLog) | Out-Null
    # npm 12's allow list lives in the project's package.json: merge ours in (a package an
    # operator set to false stays denied); older npm ignores the field.
    $allowScriptsMerge = @'
const fs = require("fs"); const file = process.argv[1];
let pkg = {}; try { pkg = JSON.parse(fs.readFileSync(file, "utf8")); } catch (e) {}
pkg.allowScripts = Object.assign({}, pkg.allowScripts);
for (const name of process.argv.slice(2)) if (pkg.allowScripts[name] !== false) pkg.allowScripts[name] = true;
fs.writeFileSync(file, JSON.stringify(pkg, null, 2) + "\n");
'@
    & node -e $allowScriptsMerge (Join-Path $DkgCliDir "package.json") @DkgAllowScripts
    $installSpec = if ($tarball) { $tarball } else { $DkgPackage }
    try {
        & npm install --prefix $DkgCliDir --prefer-online $installSpec 2>&1 | Tee-Object -FilePath $npmLog | Out-Null
        if ($tarball) { Remove-Item (Split-Path -Parent $tarball) -Recurse -Force -ErrorAction SilentlyContinue }
        if ($LASTEXITCODE -ne 0) { throw "npm install exit $LASTEXITCODE" }
    } catch {
        if ($backupDir) {
            Remove-Item $DkgCliDir -Recurse -Force -ErrorAction SilentlyContinue
            Move-Item $backupDir $DkgCliDir
        }
        Write-Warn2 "Could not install the published DKG package ${DkgPackage}: $_"
        Write-Step "npm log: $npmLog"
        return $false
    }

    # A newer DKG release may need an install script the list does not name yet: stop and say which.
    if (Select-String -Path $npmLog -SimpleMatch "had install scripts blocked" -Quiet) {
        Write-Warn2 "npm blocked install scripts the DKG node needs (see the list in $npmLog)."
        return $false
    }

    # The native SQLite module must load with the Node that will run the node; a folder an earlier
    # run left half-built is rebuilt here, then checked again (see the .sh).
    $sqliteDir = Join-Path $DkgCliDir "node_modules\better-sqlite3"
    $sqliteProbe = 'const DB = require(process.argv[1]); new DB(":memory:").close();'
    if (Test-Path $sqliteDir) {
        & node -e $sqliteProbe $sqliteDir 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Step "Building the DKG node's SQLite module for Node $(& node -v) ..."
            & npm rebuild --prefix $DkgCliDir better-sqlite3 2>&1 | Add-Content -Path $npmLog
            & node -e $sqliteProbe $sqliteDir 2>$null | Out-Null
            if ($LASTEXITCODE -ne 0) {
                Write-Warn2 "The DKG node's SQLite module does not load with Node $(& node -v) and could not be rebuilt (npm log: $npmLog)."
                return $false
            }
            Write-Ok "SQLite module built for Node $(& node -v)"
        }
    }

    if (-not (Test-Path $DkgBin) -or -not (Test-Path $packageJson)) {
        if ($backupDir) {
            Remove-Item $DkgCliDir -Recurse -Force -ErrorAction SilentlyContinue
            Move-Item $backupDir $DkgCliDir
        }
        Write-Warn2 "npm completed, but the DKG CLI entrypoint is missing at $DkgBin."
        return $false
    }
    $installedVersion = (& node -p "require(process.argv[1]).version" $packageJson 2>$null)
    if (-not $installedVersion) {
        Write-Warn2 "Could not determine the installed DKG package version."
        return $false
    }
    $pluginDir = if ($env:BLACKBOX_PLUGIN_DIR) { $env:BLACKBOX_PLUGIN_DIR } else { Join-Path $RepoDir "plugins\blackbox" }
    & $script:VenvPython (Join-Path $pluginDir "kernel\dkg_version.py") $installedVersion
    if ($LASTEXITCODE -ne 0) {
        Write-Warn2 "DKG $installedVersion is too old for direct verified Blackbox recovery; version 10.0.9+ is required."
        return $false
    }
    Write-Step "Using published upstream DKG $installedVersion unchanged."
    Write-Ok "Published DKG npm package ready ($installedVersion)"
    return $true
}

function Install-Dkg {
    Write-Heading "Setting up the OriginTrail DKG node"
    if ($SkipDkg) {
        $script:InstallIncomplete = $true
        Write-Warn2 "Skipping DKG node setup (-SkipDkg)."
        Show-DkgManualHint
        return
    }
    if (-not $script:HasNode) {
        $script:InstallIncomplete = $true
        Write-Warn2 "Node.js $NodeMajor+ not available - cannot set up the DKG node or sync the threat graph."
        Show-DkgManualHint
        return
    }
    if (-not (Initialize-BlackboxDkgProcessEnvironment)) {
        $script:InstallIncomplete = $true
        Show-DkgManualHint
        return
    }

    Write-Step "Installing the published OriginTrail DKG package ($DkgPackage) ..."
    Write-Step "  npm prefix: $DkgCliDir"
    if (-not (Install-BlackboxDkgPackage)) {
        $script:InstallIncomplete = $true
        Show-DkgManualHint
        return
    }

    if (-not (Move-LegacyBlackboxDkgHome)) {
        Show-DkgManualHint
        return
    }

    $script:DkgFreshState = -not (Test-BlackboxDkgState)
    New-Item -ItemType Directory -Force -Path $DkgHome | Out-Null
    if (-not (Test-BlackboxDkgPort)) {
        Show-DkgManualHint
        return
    }
    if (-not (Initialize-BlackboxStore)) {
        if ($script:DockerRequired) {
            Write-Err2 "Installation stopped before changing the DKG store. Set up Docker and re-run the installer."
            exit 1
        }
        Write-Err2 "Blazegraph setup did not complete and Oxigraph was not confirmed. Installation stopped."
        exit 1
    }
    if (-not (Reset-FreshManagedBlazegraph)) {
        Write-Err2 "Installation stopped before creating a DKG identity against stale graph state."
        exit 1
    }
    if ($script:DkgAlreadyRunning) {
        Ensure-BlackboxDkgConfig
        if (-not (Prepare-BlackboxDkgRuntimeFingerprint)) {
            Show-DkgManualHint
            return
        }
        if (-not $script:DkgRestartRequired) {
            $script:DkgReady = $true
            return
        }
        Write-Step "Restarting the Blackbox-owned DKG node to activate sync and relay updates ..."
        try {
            Invoke-BlackboxDkgControl restart
            if ($LASTEXITCODE -ne 0) { throw "dkg restart exit $LASTEXITCODE" }
            if (-not (Wait-BlackboxDkgRuntime)) { throw "DKG runtime verification failed" }
            Remove-Item $script:DkgStoreResetMarker -Force -ErrorAction SilentlyContinue
            Write-Ok "Blackbox DKG node restarted with the current sync settings"
            if (-not (Save-BlackboxDkgRuntimeFingerprint)) {
                Show-DkgManualHint
                return
            }
            $script:DkgReady = $true
        } catch {
            $script:InstallIncomplete = $true
            Write-Warn2 "Could not restart the Blackbox DKG node; the updated sync settings are not active."
            Show-DkgManualHint
        }
        return
    }
    Ensure-BlackboxDkgConfig
    if (-not (Prepare-BlackboxDkgRuntimeFingerprint)) {
        Show-DkgManualHint
        return
    }

    Write-Step "Bootstrapping a Blackbox-owned $Network node at $DkgDaemonUrl ..."
    Write-Step "  DKG home: $DkgHome"
    Write-Step "  DKG CLI:  $DkgBin"
    Write-Step "  Store:    $(Get-BlackboxStoreDescription)"
    Write-Step "  (non-interactive; subscribing and reading need no wallet funding)"
    try {
        Invoke-BlackboxDkgControl start
        if (-not (Wait-BlackboxDkgRuntime)) { throw "DKG runtime verification failed" }
        Remove-Item $script:DkgStoreResetMarker -Force -ErrorAction SilentlyContinue
        Write-Ok "DKG node bootstrapped on $Network"
        if (-not (Save-BlackboxDkgRuntimeFingerprint)) {
            Show-DkgManualHint
            return
        }
        $script:DkgReady = $true
    } catch {
        $script:InstallIncomplete = $true
        Write-Warn2 "DKG node bootstrap did not complete. Threat-graph sync is not active yet."
        Show-DkgManualHint
    }
}

# Pull the verified ruleset now so detection is live immediately after install.
function Sync-Ruleset {
    if (-not $script:DkgReady) { return }
    Write-Heading "Syncing the threat ruleset"
    Write-Step "Requesting one controlled verified graph catch-up ..."
    $out = & $script:HermesBin blackbox sync --wait --timeout $CatchupTimeout --require-rules 2>&1
    $code = $LASTEXITCODE
    if ($out) { $out | ForEach-Object { Write-Host $_ } }
    if ($code -eq 0) {
        Write-Ok "Ruleset synced - Blackbox is watching with the latest threats"
    } else {
        $script:InstallIncomplete = $true
        Write-Err2 "Initial verified threat-graph sync did not complete."
        Write-Step "A partial verified ruleset may already be active, but setup is incomplete until the curator snapshot settles."
        Write-Step "Retry the full sync with: blackbox sync --wait --require-rules"
    }
    Write-Ok "DKG native reconciliation enabled; one in-flight slot; zero queue"
}

function Show-DkgManualHint {
    Write-Step "To set up the DKG node later:"
    Write-Host "      node -v  # must be v$NodeMajor or newer"
    Write-Host "      New-Item -ItemType Directory -Force -Path `"$DkgCliDir`""
    Write-Host "      npm install --prefix `"$DkgCliDir`" `"$DkgPackage`""
    Write-Host "      `$env:BLACKBOX_DKG_HOME = `"$DkgHome`""
    Write-Host "      `$env:BLACKBOX_DKG_BIN = `"$DkgBin`""
    Write-Host "      `$env:BLACKBOX_DKG_PORT = `"$DkgPort`""
    if ($script:DkgSelectedStoreBackend -eq "blazegraph") {
        Write-Host "      `$env:BLACKBOX_DKG_STORE_URL = `"$DkgStoreUrl`""
    }
    Write-Host "      `$env:BLACKBOX_DKG_DAEMON_URL = `"$DkgDaemonUrl`""
    Write-Host "      # create config.json/auth.token as in scripts/blackbox-install.ps1, then:"
    Write-Host "      `$env:DKG_HOME = `$env:BLACKBOX_DKG_HOME"
    Write-Host "      `$env:NODE_OPTIONS = `"$($script:DkgNodeOptions)`""
    Write-Host "      `$env:DKG_SYNC_GLOBAL_MAX_INFLIGHT = `"$DkgSyncGlobalMaxInflight`""
    Write-Host "      `$env:DKG_STORE_QUEUE_LIMIT = `"$DkgStoreQueueLimit`""
    Write-Host "      & `$env:BLACKBOX_DKG_BIN start"
    Write-Host "      # then re-run:  blackbox sync --wait --require-rules"
}

# ── Enable plugin + write config defaults (idempotent) ──────────────────────
function Enable-AndConfigure {
    Write-Heading "Enabling and configuring Blackbox"

    Write-Step "Enabling the blackbox plugin without privileged tool overrides ..."
    try {
        & $HermesBin plugins enable blackbox --no-allow-tool-override 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "hermes exit $LASTEXITCODE" }
        Write-Ok "Plugin enabled"
    } catch {
        Write-Warn2 "Could not run 'hermes plugins enable blackbox --no-allow-tool-override' automatically."
        Write-Step "Run it yourself after the install: hermes plugins enable blackbox --no-allow-tool-override"
    }

    Write-Step "Writing plugins.entries.blackbox defaults to $HermesHome\config.yaml ..."
    $configWriter = @'
import sys, os
cfg_path, dkg_url, dkg_home, dkg_bin, context_graph_id, graph_peer_id = sys.argv[1:7]
repo_dir = sys.argv[7] if len(sys.argv) > 7 else ""
try:
    try:
        import hermes_yaml as yaml  # Hermes 0.21.7+: YAML through ruamel (PyYAML left the host)
    except ImportError:
        import yaml  # older Hermes: PyYAML
except Exception:
    print("  (PyYAML unavailable - skipping config update; run 'blackbox status' to configure)")
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
legacy_dkg_urls = {"http://127.0.0.1:9200", "http://localhost:9200"}
legacy_graphs = {"0x37b1Fdfd134e2b17583bCBdD3034F91504cD9C70/agent-blackbox", "umanitek/blackbox-threats-staging", "umanitek/guardian-threats-staging", "umanitek/guardian-threats"}
legacy_peers = {"12D3KooWAuEHYTWbD3R3yPTcECCYZnrjHNpJmrUw5b4D5T3m5Kr3", "12D3KooWBY9jmNATMPv1DZcKbFas5RtjpkhT69pPwvkUBY2MMnDX", "12D3KooWQHQd1SNecrRxwceqPJkXS" + "K" + "EYn8vrV4QyJ2AfqeYwXz1E", "12D3KooWBJskzr2unXQG9mR3LRZFUJoxWr1PN6hTbyWyKndHXjZM"}
default_dkg_home = os.path.abspath(os.path.expanduser("~/.dkg"))
legacy_blackbox_dkg_home = os.path.abspath(os.path.expanduser("~/.hermes/blackbox/dkg"))
legacy_blackbox_dkg_bin = os.path.abspath(os.path.expanduser("~/.hermes/blackbox/dkg-cli/node_modules/.bin/dkg.cmd"))
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
    os.path.join(os.path.dirname(current_dkg_home_abs), "dkg", "node_modules", ".bin", "dkg.cmd")
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
# KI-184: an opt-in backed by a sharing-consent record (R13) survives every
# re-run and upgrade; only a pre-release opt-in (no consent record in force) is
# migrated off. The product's own consent code decides; if it cannot be
# imported the answer is "no consent" (fail closed = sharing off).
def _consent_in_force(checkout):
    try:
        if checkout and os.path.isfile(os.path.join(checkout, "plugin.yaml")):
            # Setup-only mode passes the plugin folder itself (see blackbox-install.sh).
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
# 0 was the pre-R1 "no cap" (refused); 20 was the earlier installers' default, raised to 100 on 2026-10-12.
if blackbox.get("daily_report_limit") in (0, "0", 20, "20"):
    blackbox["daily_report_limit"] = 100
    added.append("daily_report_limit")
with open(cfg_path, "w") as f:
    yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)
print("  configured: " + ", ".join(added) if added else "  already configured - no changes")
'@
    $configFile = Join-Path $env:TEMP "blackbox_configure.py"
    Set-Content -Path $configFile -Value $configWriter -Encoding UTF8
    try {
        & $VenvPython $configFile "$HermesHome\config.yaml" $DkgDaemonUrl $DkgHome $DkgBin $ContextGraphId $GraphPeerId $(if ($env:BLACKBOX_PLUGIN_DIR) { $env:BLACKBOX_PLUGIN_DIR } else { $RepoDir })
        if ($LASTEXITCODE -ne 0) { throw "config update exit $LASTEXITCODE" }
        Write-Ok "Config defaults written (audit mode - blocking is opt-in)"
    } catch {
        Write-Warn2 "Could not write config automatically. Run 'blackbox status' to verify configuration."
    } finally {
        Remove-Item $configFile -Force -ErrorAction SilentlyContinue
    }
}

function Get-BlackboxMode {
    $reader = @'
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
mode = data.get("plugins", {}).get("entries", {}).get("blackbox", {}).get("mode", "audit")
mode = str(mode).lower()
print(mode if mode in ("audit", "block") else "audit")
'@
    $readerFile = Join-Path $env:TEMP "blackbox_mode_read.py"
    Set-Content -Path $readerFile -Value $reader -Encoding UTF8
    try {
        $out = (& $VenvPython $readerFile "$HermesHome\config.yaml" 2>$null | Select-Object -Last 1)
        if ($out -eq "block") { return "block" }
        return "audit"
    } finally {
        Remove-Item $readerFile -Force -ErrorAction SilentlyContinue
    }
}

function Set-BlackboxMode {
    param([string]$Mode)
    $writer = @'
import sys, os
cfg_path, mode = sys.argv[1], sys.argv[2]
try:
    try:
        import hermes_yaml as yaml  # Hermes 0.21.7+: YAML through ruamel (PyYAML left the host)
    except ImportError:
        import yaml  # older Hermes: PyYAML
except Exception:
    print("  (PyYAML unavailable - could not save protection mode)")
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
'@
    $writerFile = Join-Path $env:TEMP "blackbox_mode_write.py"
    Set-Content -Path $writerFile -Value $writer -Encoding UTF8
    try {
        & $VenvPython $writerFile "$HermesHome\config.yaml" $Mode
        return ($LASTEXITCODE -eq 0)
    } finally {
        Remove-Item $writerFile -Force -ErrorAction SilentlyContinue
    }
}

function Configure-BlackboxMode {
    Write-Heading "Choosing Blackbox enforcement mode"
    $current = if ($env:BLACKBOX_MODE) { $env:BLACKBOX_MODE.ToLowerInvariant() } else { "" }
    if (($current -ne "audit") -and ($current -ne "block")) {
        $current = Get-BlackboxMode
    }
    if ($current -ne "block") { $current = "audit" }

    if ([Console]::IsInputRedirected) {
        $script:BlackboxSelectedMode = $current
        Write-Step "Non-interactive install - keeping Blackbox in $current mode."
        return
    }

    Write-Host "  Choose how Blackbox should react when it finds threats."
    Write-Host "    1) Audit - log and report findings, but do not stop actions. [recommended]"
    Write-Host "    2) Block - stop confirmed threats at/above the configured severity."
    $ans = Read-Host "  Protection mode [1/2, Enter keeps $current]"
    switch -Regex ($ans) {
        '^(2|b|block)$' { $script:BlackboxSelectedMode = "block"; break }
        '^(1|a|audit)?$' { $script:BlackboxSelectedMode = $current; break }
        default {
            Write-Warn2 "Unknown protection mode '$ans' - keeping $current."
            $script:BlackboxSelectedMode = $current
        }
    }

    if (Set-BlackboxMode $script:BlackboxSelectedMode) {
        Write-Ok "Blackbox protection mode set to: $script:BlackboxSelectedMode"
    } else {
        Write-Warn2 "Could not save Blackbox protection mode. Set it later in the dashboard or config.yaml."
    }
}

# ── Protect agents (best-effort, non-fatal) ─────────────────────────────────
# Blackbox protects the Hermes home this installer set up ($HermesHome). Every
# other Hermes profile or OpenClaw workspace is its own trust and credential
# boundary, so it is attached only when the operator says so: `blackbox attach`
# lists the ones not yet protected and asks [y/N] on the console; with no console
# it attaches none of them. Scripted installs set BLACKBOX_ATTACH_ALL=1.
function Protect-AllAgents {
    Write-Heading "Protecting your agents"
    Write-Step "Protecting the Hermes home at $HermesHome (blackbox attach) ..."
    try {
        & $HermesBin blackbox attach $HermesHome
        if ($LASTEXITCODE -ne 0) { throw "hermes exit $LASTEXITCODE" }
        Write-Ok "Blackbox protects $HermesHome"
    } catch {
        Write-Warn2 "Could not protect $HermesHome (this is non-fatal)."
        Write-Step "Re-run anytime with:  blackbox attach $HermesHome"
    }
    if (@('1', 'true', 'yes') -contains "$env:BLACKBOX_ATTACH_ALL".ToLower()) {
        Write-Step "BLACKBOX_ATTACH_ALL is set: protecting every Hermes home + OpenClaw workspace found ..."
        & $HermesBin blackbox attach --all
        if ($LASTEXITCODE -ne 0) { Write-Warn2 "Could not protect every agent (this is non-fatal)." }
        return
    }
    Write-Step "Looking for other agents on this machine (Hermes profiles, OpenClaw workspaces) ..."
    & $HermesBin blackbox attach
    if ($LASTEXITCODE -ne 0) { Write-Step "Protect others later with:  blackbox attach <home>   (or --all)" }
}

# ── Guided next steps (single source of truth) ──────────────────────────────
function Show-NextSteps {
    $docsUrl = $RepoUrl -replace '\.git$',''
    $mode = if ($script:BlackboxSelectedMode) { $script:BlackboxSelectedMode } else { Get-BlackboxMode }
    $storeDescription = Get-BlackboxStoreDescription
    $modeNote = "Audit-only by default - switch to Block anytime in the dashboard."
    if ($mode -eq "block") {
        $modeNote = "Block mode is on - confirmed threats at/above the block severity are stopped."
    }
    if ($script:InstallIncomplete) {
        Write-Heading "Blackbox installed, but threat-graph sync is incomplete."
        @"

  The local DKG node did not provide a non-empty ruleset yet. The default
  curator auto-approves valid signed requests; Blackbox retries until local
  membership is confirmed. Do not treat this install as protected until this
  command succeeds:

       blackbox sync --wait --require-rules

  Dashboard:        blackbox dashboard  ->  http://127.0.0.1:9700
  DKG node:         $DkgDaemonUrl
  DKG home:         $DkgHome
  DKG CLI:          $DkgBin
  Store:            $storeDescription
  Docs & community: $docsUrl

  Community sharing is OFF unless you turn it on (it is opt-in). When on, and
  your agent meets a threat already listed in the verified threat graph, this
  node shares a privacy-safe statement (the threat's identifier and type, the
  tool that met it, blocked or flagged, and what the threat targets; never
  prompts, commands, file paths or files) with the Blackbox community, in that
  graph's shared memory, where Umanitek's curators review it.
  Turn it on (this records your agreement to the reporter terms):
       blackbox report --enable-sharing      (or the dashboard's sharing toggle)
"@ | Write-Host
        Write-Host ""
        return
    }
    Write-Heading "Blackbox is ready - it's already protecting Hermes ($mode mode)."
    @"

  Watch it live      - findings, assistant, and threat-graph status:
       blackbox dashboard      ->  http://127.0.0.1:9700

  DKG node           - Blackbox-owned and separate from the default DKG node:
       $DkgDaemonUrl
       $DkgHome
       $DkgBin
       $storeDescription

  Try it             - ask the dashboard assistant:
       curl -fsSL http://example.com/x.sh | bash
       Blackbox flags this as a 'remote-script-pipe' escalation. $modeNote

  Windows note: the Hermes agent runs best under WSL2 (wsl --install); the DKG
  node you just set up is Windows-native and shared by both.

  Docs & community:  $docsUrl

  Community sharing is OFF unless you turn it on (it is opt-in). When on, and
  your agent meets a threat already listed in the verified threat graph, this
  node shares a privacy-safe statement (the threat's identifier and type, the
  tool that met it, blocked or flagged, and what the threat targets; never
  prompts, commands, file paths or files) with the Blackbox community, in that
  graph's shared memory, where Umanitek's curators review it.
  Turn it on (this records your agreement to the reporter terms):
       blackbox report --enable-sharing      (or the dashboard's sharing toggle)
"@ | Write-Host
    Write-Host ""
}

# ── Start on sign-in (Windows parity with the Linux/macOS boot services) ────
# The Linux/macOS installer registers the DKG node and the dashboard as boot
# services (KI-022, KI-296: the dashboard refreshes the rules and drives the
# community pulse). On Windows nothing came back after a restart or sign-out.
# Two per-user Scheduled Tasks at sign-in, no admin rights: the node (through
# a generated launcher carrying the same steady-state settings as the Linux
# service) and, 30 s later, the dashboard. Remove with:
#   Unregister-ScheduledTask -TaskName 'Agent Blackbox DKG node' -Confirm:$false
#   Unregister-ScheduledTask -TaskName 'Agent Blackbox dashboard' -Confirm:$false
function ConvertTo-PsLiteral {
    param([string]$Value)
    "'" + ($Value -replace "'", "''") + "'"
}

function New-BlackboxDkgLauncherLines {
    # The node launcher's lines. Connection-time sync stays ON (it delivers
    # context-graph authority to subscribers, KI-044); the periodic reconciler is
    # left to config.json, as in the Linux unit; the stream/prefetch switches and
    # the installer's safety limits ride along (KI-282). The graph-list projection
    # stays install-time only: with it on, the running node's listing omits the
    # verified graph and Blackbox reads it as "not subscribed".
    param([string]$NodeDir = "")
    $lines = @(
        "# managed-by: agent-blackbox-installer -- starts the Blackbox DKG node at sign-in; rewritten on every install.",
        "`$env:DKG_HOME = $(ConvertTo-PsLiteral $DkgHome)",
        "`$env:DKG_SYNC_ON_CONNECT_ENABLED = '1'",
        "`$env:DKG_DURABLE_SYNC_ENABLED = $(ConvertTo-PsLiteral $script:DkgDurableSyncEnabled)",
        "`$env:DKG_STORE_QUEUE_LIMIT = $(ConvertTo-PsLiteral "$DkgStoreQueueLimit")",
        "`$env:DKG_EXACT_BATCH_STREAM_ENABLED = $(ConvertTo-PsLiteral "$DkgExactBatchStreamEnabled")",
        "`$env:DKG_VM_RECOVERY_PREFETCH_ENABLED = $(ConvertTo-PsLiteral "$DkgVmRecoveryPrefetchEnabled")"
    )
    if ($script:DkgNodeOptions) { $lines += "`$env:NODE_OPTIONS = $(ConvertTo-PsLiteral $script:DkgNodeOptions)" }
    if ($NodeDir) { $lines += "`$env:Path = $(ConvertTo-PsLiteral "$NodeDir;") + `$env:Path" }
    $lines += "& $(ConvertTo-PsLiteral $DkgBin) start --foreground"
    return $lines
}

function Register-BlackboxStartupTasks {
    Write-Heading "Starting Blackbox when you sign in"
    if (-not (Get-Command Register-ScheduledTask -ErrorAction SilentlyContinue)) {
        Write-Warn2 "Scheduled Tasks are unavailable: after a restart, start the node and run 'blackbox dashboard' yourself."
        return
    }
    if (-not (Test-Path $DkgBin)) {
        Write-Warn2 "The DKG node is not installed; nothing to start at sign-in."
        return
    }
    $nodeDir = ""
    $nodeCommand = Get-Command node -ErrorAction SilentlyContinue
    if ($nodeCommand -and $nodeCommand.Source) { $nodeDir = Split-Path -Parent $nodeCommand.Source }
    New-Item -ItemType Directory -Force -Path $DkgHome | Out-Null
    $nodeLauncher = Join-Path $DkgHome "start-blackbox-dkg.ps1"
    Set-Content -Path $nodeLauncher -Value (New-BlackboxDkgLauncherLines -NodeDir $nodeDir) -Encoding UTF8
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
    $hidden = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File"
    try {
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "$hidden `"$nodeLauncher`""
        Register-ScheduledTask -TaskName $DkgTaskName -Action $action -Trigger $trigger `
            -Principal $principal -Settings $settings -Force | Out-Null
        Write-Ok "The DKG node starts when you sign in (task 'Agent Blackbox DKG node')"
    } catch {
        Write-Warn2 "Could not register the DKG node task: $($_.Exception.Message)"
        return
    }
    if (-not ($script:HermesBin -and (Test-Path $script:HermesBin))) {
        Write-Warn2 "hermes was not found; run 'blackbox dashboard' yourself after a restart."
        return
    }
    New-Item -ItemType Directory -Force -Path $BlackboxHome | Out-Null
    $dashLauncher = Join-Path $BlackboxHome "start-blackbox-dashboard.ps1"
    Set-Content -Path $dashLauncher -Encoding UTF8 -Value @(
        "# managed-by: agent-blackbox-installer -- starts the Blackbox dashboard at sign-in (rule refresh + community pulse).",
        "`$env:HERMES_HOME = $(ConvertTo-PsLiteral $HermesHome)",
        "& $(ConvertTo-PsLiteral $script:HermesBin) blackbox dashboard"
    )
    try {
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
        $trigger.Delay = "PT30S"   # after the node
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "$hidden `"$dashLauncher`""
        Register-ScheduledTask -TaskName "Agent Blackbox dashboard" -Action $action -Trigger $trigger `
            -Principal $principal -Settings $settings -Force | Out-Null
        Write-Ok "The dashboard starts when you sign in (task 'Agent Blackbox dashboard')"
    } catch {
        Write-Warn2 "Could not register the dashboard task: $($_.Exception.Message)"
    }
}

# ── Main ────────────────────────────────────────────────────────────────────
function Main {
    Write-Banner
    Write-Heading "Checking your system"
    Write-Ok "Detected Windows ($env:PROCESSOR_ARCHITECTURE)"
    if ($SetupOnly) {
        Test-NodeJs
        Use-RunningHermes
    } else {
        Test-Git
        Resolve-Python
        Test-NodeJs

        Resolve-Repo
        Install-PythonEnv
    }
    Install-BlackboxCommand
    Install-Dkg
    Enable-AndConfigure
    Configure-BlackboxMode
    Protect-AllAgents
    Sync-Ruleset
    Register-BlackboxStartupTasks
    Show-NextSteps
    if ($script:InstallIncomplete) {
        exit 1
    }
}

Main
