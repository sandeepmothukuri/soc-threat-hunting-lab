<#
.SYNOPSIS
    build-all.ps1 — Master Build Orchestration for Windows Hosts
.DESCRIPTION
    Automates building the entire 8-VM SOC lab together using Vagrant or profile groups.
.PARAMETER Profile
    Optional profile to run: "all", "network", "endpoint", "intel", or "check".
.EXAMPLE
    .\scripts\build-all.ps1 -Profile all
    .\scripts\build-all.ps1 -Profile network
    .\scripts\build-all.ps1 -Profile check
#>

[CmdletBinding()]
param(
    [ValidateSet("all", "network", "endpoint", "intel", "check")]
    [string]$Profile = "all"
)

$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host "`n╔══════════════════════════════════════════════════════╗" -ForegroundColor Blue
    Write-Host "║ $Message" -ForegroundColor Blue
    Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Blue
}

# Ensure in repository root
$repoRoot = (Get-Item $PSScriptRoot).Parent.FullName
Set-Location $repoRoot

switch ($Profile) {
    "all" {
        Write-Step "Building Entire 8-VM SOC Lab Together (vagrant up)"
        if (-not (Get-Command "vagrant" -ErrorAction SilentlyContinue)) {
            Write-Host "Vagrant is not installed in PATH. Please install Vagrant or use manual build." -ForegroundColor Red
            exit 1
        }
        & vagrant up
        Write-Step "Running Lab Health Verification"
        & "$PSScriptRoot\health-check.ps1"
    }

    "network" {
        Write-Step "Building Network Sensors Profile (zeek-rita, arkime, target, kali)"
        & vagrant up zeek-rita arkime ubuntu-target kali
    }

    "endpoint" {
        Write-Step "Building Endpoint DFIR Profile (velociraptor, target, kali)"
        & vagrant up velociraptor ubuntu-target kali
    }

    "intel" {
        Write-Step "Building Threat Intel & SOAR Profile (misp, thehive, shuffle)"
        & vagrant up misp thehive shuffle
    }

    "check" {
        Write-Step "Running Lab Health Verification"
        & "$PSScriptRoot\health-check.ps1"
    }
}
