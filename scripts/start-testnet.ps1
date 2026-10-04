# start-testnet.ps1
#
# Launches a 3-node QCB testnet (alice / bob / carol) in separate Windows
# Terminal tabs or PowerShell windows.
#
# Usage:
#   .\scripts\start-testnet.ps1              # fresh start (clears data dirs)
#   .\scripts\start-testnet.ps1 -Resume      # restart from persisted state
#   .\scripts\start-testnet.ps1 -LogLevel debug
#
# Requirements:
#   - Run from the repo root: cd C:\Dev\chain-forge-engine\chain-forge-engine
#   - Binary must be built:   cargo build --release -p chain-forge-node
#   - Windows Terminal is recommended (wt.exe); falls back to Start-Process

param(
    [switch]$Resume,
    [string]$LogLevel  = "info",
    [string]$Genesis   = "genesis-3node.json",
    [string]$DataRoot  = "C:\tmp",
    [string]$Binary    = ".\target\release\chain-forge-node.exe"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Sanity checks ────────────────────────────────────────────────────────────

if (-not (Test-Path $Binary)) {
    Write-Error "Binary not found: $Binary`nRun: cargo build --release -p chain-forge-node"
}

if (-not (Test-Path $Genesis)) {
    Write-Error "Genesis file not found: $Genesis`nRun from the repo root."
}

# ── Node definitions ─────────────────────────────────────────────────────────

$nodes = @(
    @{ Name = "alice"; Validator = "qcb1alice"; ApiPort = 8080; DataDir = "$DataRoot\qcb-alice" },
    @{ Name = "bob";   Validator = "qcb1bob";   ApiPort = 8081; DataDir = "$DataRoot\qcb-bob"   },
    @{ Name = "carol"; Validator = "qcb1carol"; ApiPort = 8082; DataDir = "$DataRoot\qcb-carol" }
)

# ── Clear data dirs unless resuming ──────────────────────────────────────────

if (-not $Resume) {
    Write-Host "Clearing data directories..." -ForegroundColor Yellow
    foreach ($n in $nodes) {
        if (Test-Path $n.DataDir) {
            Remove-Item -Recurse -Force $n.DataDir
            Write-Host "  Removed $($n.DataDir)"
        }
    }
}

# ── Build the command string for each node ───────────────────────────────────

function Get-NodeCmd($node) {
    $bin  = (Resolve-Path $Binary).Path
    $gen  = (Resolve-Path $Genesis).Path
    # PowerShell command that sets RUST_LOG then runs the node
    return (
        "`$env:RUST_LOG='$LogLevel'; " +
        "& '$bin' " +
        "--genesis '$gen' " +
        "--validator $($node.Validator) " +
        "--api-port $($node.ApiPort) " +
        "--data-dir '$($node.DataDir)'"
    )
}

# ── Launch each node ─────────────────────────────────────────────────────────

$wtAvailable = $null -ne (Get-Command wt.exe -ErrorAction SilentlyContinue)

Write-Host ""
Write-Host "Starting 3-node QCB testnet" -ForegroundColor Cyan
Write-Host "  Genesis : $Genesis"
Write-Host "  Binary  : $Binary"
Write-Host "  LogLevel: $LogLevel"
Write-Host "  Resume  : $Resume"
Write-Host ""

foreach ($node in $nodes) {
    $cmd = Get-NodeCmd $node
    $title = "QCB-$($node.Name.ToUpper()) | api=:$($node.ApiPort)"

    if ($wtAvailable) {
        # Open a new Windows Terminal tab for each node
        $wtArgs = "new-tab --title `"$title`" -- powershell.exe -NoExit -Command `"$cmd`""
        Start-Process wt.exe -ArgumentList $wtArgs
        Write-Host "  Launched $($node.Name) in new WT tab (api=:$($node.ApiPort))" -ForegroundColor Green
    } else {
        # Fall back to a plain PowerShell window
        Start-Process powershell.exe -ArgumentList "-NoExit", "-Command", $cmd `
            -WindowStyle Normal
        Write-Host "  Launched $($node.Name) in new window (api=:$($node.ApiPort))" -ForegroundColor Green
    }

    # Small delay so alice is up before bob/carol try to peer
    if ($node.Name -eq "alice") { Start-Sleep -Milliseconds 500 }
}

Write-Host ""
Write-Host "All nodes launched. API endpoints:" -ForegroundColor Cyan
foreach ($node in $nodes) {
    Write-Host "  $($node.Name.PadRight(6)) http://localhost:$($node.ApiPort)/status"
}
Write-Host ""
Write-Host "To stop: close the node windows, then run:" -ForegroundColor Yellow
Write-Host "  Remove-Item -Recurse -Force C:\tmp\qcb-alice, C:\tmp\qcb-bob, C:\tmp\qcb-carol"
