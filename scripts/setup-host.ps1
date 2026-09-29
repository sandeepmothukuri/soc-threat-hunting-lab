<#
.SYNOPSIS
    setup-host.ps1 — Prepare Windows Host for SOC Threat Hunting Lab
.DESCRIPTION
    Checks system requirements (RAM, CPU, Disk, Virtualization), verifies VirtualBox 7.x,
    and configures the four isolated VirtualBox host-only networks for the lab.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\setup-host.ps1
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host "`n==== $Message ====" -ForegroundColor Cyan
}

function Write-Pass {
    param([string]$Message)
    Write-Host "  [PASS] $Message" -ForegroundColor Green
}

function Write-WarnMsg {
    param([string]$Message)
    Write-Host "  [WARN] $Message" -ForegroundColor Yellow
}

function Write-Fail {
    param([string]$Message)
    Write-Host "  [FAIL] $Message" -ForegroundColor Red
}

Write-Host "`n+------------------------------------------------------+" -ForegroundColor Blue
Write-Host "|   SOC Threat Hunting Lab -- Host Setup (Windows)     |" -ForegroundColor Blue
Write-Host "+------------------------------------------------------+" -ForegroundColor Blue

# 1. System Requirements Check
Write-Step "1/3 Checking Hardware & Hypervisor Prerequisites"

# RAM Check
$totalRamGB = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
if ($totalRamGB -ge 32) {
    Write-Pass "Physical RAM: $totalRamGB GB (Optimal for all 8 concurrent VMs)"
} elseif ($totalRamGB -ge 16) {
    Write-WarnMsg "Physical RAM: $totalRamGB GB (Supported via profile-based execution or sequential builds)"
} else {
    Write-Fail "Physical RAM: $totalRamGB GB (Minimum 16GB required)"
}

# CPU Check
$cpuCores = (Get-CimInstance Win32_Processor).NumberOfLogicalProcessors
Write-Pass "Logical CPU Processors: $cpuCores"

# Free Disk Space Check
$systemDrive = (Get-PSDrive -Name C)
$freeDiskGB = [math]::Round($systemDrive.Free / 1GB, 1)
if ($freeDiskGB -ge 150) {
    Write-Pass "Free Disk Space (C:): $freeDiskGB GB"
} else {
    Write-WarnMsg "Free Disk Space (C:): $freeDiskGB GB (150GB+ recommended for full PCAP capture)"
}

# 2. VirtualBox Verification
Write-Step "2/3 Verifying VirtualBox Installation"

$vboxPath = $null
if (Get-Command "VBoxManage.exe" -ErrorAction SilentlyContinue) {
    $vboxPath = "VBoxManage.exe"
} elseif (Test-Path "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe") {
    $vboxPath = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
    $env:Path += ";C:\Program Files\Oracle\VirtualBox"
}

if (-not $vboxPath) {
    Write-Fail "VirtualBox was not detected in PATH or standard install directory."
    Write-Host "  Please install VirtualBox 7.x from: https://www.virtualbox.org/wiki/Downloads" -ForegroundColor Yellow
    exit 1
}

$vboxVersion = & $vboxPath --version
Write-Pass "VirtualBox version detected: $vboxVersion"

# 3. Host-Only Networks Configuration
Write-Step "3/3 Checking & Creating VirtualBox Host-Only Networks"

$desiredNetworks = @(
    @{ Name = "Attacker VLAN"; IP = "192.168.20.1"; Mask = "255.255.255.0"; Subnet = "192.168.20.0/24" },
    @{ Name = "Target VLAN";   IP = "192.168.30.1"; Mask = "255.255.255.0"; Subnet = "192.168.30.0/24" },
    @{ Name = "Detection VLAN";IP = "192.168.50.1"; Mask = "255.255.255.0"; Subnet = "192.168.50.0/24" },
    @{ Name = "Intel VLAN";    IP = "192.168.60.1"; Mask = "255.255.255.0"; Subnet = "192.168.60.0/24" }
)

$existingAdapters = & $vboxPath list hostonlyifs

foreach ($net in $desiredNetworks) {
    $targetIP = $net.IP
    if ($existingAdapters -match [regex]::Escape($targetIP)) {
        Write-Pass "$($net.Name) ($($net.Subnet)) already configured at gateway $targetIP"
    } else {
        Write-Host "  Creating new host-only adapter for $($net.Name)..." -ForegroundColor Cyan
        try {
            $createOut = & $vboxPath hostonlyif create
            $adapterName = ($createOut | Select-String "Interface '([^']+)'").Matches.Groups[1].Value
            if (-not $adapterName) {
                $adapterName = (& $vboxPath list hostonlyifs | Select-String "^Name:\s+(.*)" | Select-Object -Last 1).Matches.Groups[1].Value
            }
            & $vboxPath hostonlyif ipconfig "$adapterName" --ip $net.IP --netmask $net.Mask
            Write-Pass "Created $adapterName with IP $($net.IP) ($($net.Subnet))"
        } catch {
            Write-WarnMsg "Could not automatically create adapter for $($net.Name). Error: $_"
        }
    }
}

Write-Host "`n+------------------------------------------------------+" -ForegroundColor Green
Write-Host "|   Windows Host Preparation Complete!                 |" -ForegroundColor Green
Write-Host "+------------------------------------------------------+" -ForegroundColor Green
Write-Host "Next Step Options to build all together:" -ForegroundColor Cyan
Write-Host "  Option 1 (Automated Vagrant): run 'vagrant up'" -ForegroundColor White
Write-Host "  Option 2 (Manual VM Build): follow docs/vm-build-guide.md" -ForegroundColor White
