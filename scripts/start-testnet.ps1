# start-testnet.ps1
#
# Launches the local 4-node ML-DSA devnet (alice / bob / carol / dave) in
# separate PowerShell windows.
#
# Uses tests\devnet\genesis-4node-mldsa.json (ML-DSA-65 consensus keys,
# ML-DSA-only user accounts) and the public test keys in
# tests\devnet\keys\mldsa\. Ports API 19080-19083 / P2P 28000-28003 and the
# data folders C:\tmp\qcb-mldsa-* never touch the legacy devnet's ports or
# data. The keys are public: test use only. For a devnet anyone relies on,
# generate fresh keys (docs\devnet-upgrade-phase-0-5.md).
#
# Usage:
#   .\scripts\start-testnet.ps1              # fresh start (clears its own data dirs)
#   .\scripts\start-testnet.ps1 -Resume      # restart from persisted state
#   .\scripts\start-testnet.ps1 -LogLevel debug
#
# Requirements:
#   - Run from the repo root: cd C:\Dev\chain-forge-engine
#   - Binary must be built: cargo build --release -p chain-forge-node
#     (or pass -Binary .\target\debug\chain-forge-node.exe)

param(
    [switch]$Resume,
    [string]$LogLevel  = "info",
    [string]$Genesis   = "tests\devnet\genesis-4node-mldsa.json",
    [string]$KeysDir   = "tests\devnet\keys\mldsa",
    [string]$DataRoot  = "C:\tmp",
    [string]$Binary    = ".\target\release\chain-forge-node.exe"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# --- Sanity checks -----------------------------------------------------------

if (-not (Test-Path $Binary)) {
    Write-Error "Binary not found: $Binary`nRun: cargo build --release -p chain-forge-node"
}
if (-not (Test-Path $Genesis)) {
    Write-Error "Genesis file not found: $Genesis`nRun from the repo root."
}

# --- Node definitions --------------------------------------------------------

$nodes = @(
    @{ Name = "alice"; ApiPort = 19080; P2pPort = 28000 },
    @{ Name = "bob";   ApiPort = 19081; P2pPort = 28001 },
    @{ Name = "carol"; ApiPort = 19082; P2pPort = 28002 },
    @{ Name = "dave";  ApiPort = 19083; P2pPort = 28003 }
)
foreach ($n in $nodes) {
    $n.Validator = "qcb1$($n.Name)"
    $n.DataDir   = "$DataRoot\qcb-mldsa-$($n.Name)"
    $n.KeyFile   = "$KeysDir\$($n.Name).key.json"
    if (-not (Test-Path $n.KeyFile)) {
        Write-Error "Key file not found: $($n.KeyFile)"
    }
}
$bootstrap = "/ip4/127.0.0.1/tcp/$($nodes[0].P2pPort)"

# --- Clear this devnet's data dirs unless resuming ---------------------------

if (-not $Resume) {
    Write-Host "Clearing data directories..." -ForegroundColor Yellow
    foreach ($n in $nodes) {
        if (Test-Path $n.DataDir) {
            Remove-Item -Recurse -Force $n.DataDir
            Write-Host "  Removed $($n.DataDir)"
        }
    }
}

# --- Write per-node launcher scripts -----------------------------------------
# Start-Process passes -File verbatim, so each node gets a small .ps1.

$tmpDir = "$env:TEMP\qcb-testnet-mldsa"
New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null

$bin = (Resolve-Path $Binary).Path
$gen = (Resolve-Path $Genesis).Path

foreach ($node in $nodes) {
    $key = (Resolve-Path $node.KeyFile).Path
    $lines = @()
    $lines += "`$env:RUST_LOG = '$LogLevel'"
    $lines += "& '$bin' ``"
    $lines += "  --genesis '$gen' ``"
    $lines += "  --validator $($node.Validator) ``"
    $lines += "  --key-file '$key' ``"
    $lines += "  --api-port $($node.ApiPort) ``"
    $lines += "  --p2p-port $($node.P2pPort) ``"
    if ($node.Name -ne "alice") {
        $lines += "  --bootstrap '$bootstrap' ``"
    }
    $lines += "  --data-dir '$($node.DataDir)'"

    Set-Content -Path "$tmpDir\run-$($node.Name).ps1" -Value ($lines -join "`n") -Encoding UTF8
}

# --- Launch each node --------------------------------------------------------

Write-Host ""
Write-Host "Starting the local 4-node ML-DSA devnet" -ForegroundColor Cyan
Write-Host "  Genesis : $gen"
Write-Host "  Binary  : $bin"
Write-Host "  LogLevel: $LogLevel"
Write-Host "  Resume  : $Resume"
Write-Host ""

foreach ($node in $nodes) {
    Start-Process powershell.exe `
        -ArgumentList "-NoExit", "-File", "$tmpDir\run-$($node.Name).ps1" `
        -WindowStyle Normal
    Write-Host "  Launched $($node.Name) (api=:$($node.ApiPort) p2p=:$($node.P2pPort))" -ForegroundColor Green

    # Alice is everyone's bootstrap peer: give her a head start.
    if ($node.Name -eq "alice") { Start-Sleep -Milliseconds 500 }
}

Write-Host ""
Write-Host "All nodes launched" -ForegroundColor Cyan
Write-Host "API endpoints:"
foreach ($node in $nodes) {
    Write-Host "  $($node.Name.PadRight(6)) http://localhost:$($node.ApiPort)/api/status"
}
Write-Host ""
Write-Host "To stop: close the node windows. To wipe this devnet's data:" -ForegroundColor Yellow
Write-Host "  Remove-Item -Recurse -Force $(($nodes | ForEach-Object { $_.DataDir }) -join ', ')"
