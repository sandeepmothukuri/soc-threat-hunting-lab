<#
.SYNOPSIS
    health-check.ps1 — Verify All Lab Services on Windows
.DESCRIPTION
    Tests TCP connectivity and HTTP status codes across Detection, Intel, and Target VLANs.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\health-check.ps1
#>

[CmdletBinding()]
param(
    [int]$TimeoutSeconds = 3
)

$PassCount = 0
$FailCount = 0
$WarnCount = 0

function Write-Pass {
    param([string]$Message)
    Write-Host "  [PASS] $Message" -ForegroundColor Green
    $script:PassCount++
}

function Write-Fail {
    param([string]$Message)
    Write-Host "  [FAIL] $Message" -ForegroundColor Red
    $script:FailCount++
}

function Write-WarnMsg {
    param([string]$Message)
    Write-Host "  [WARN] $Message" -ForegroundColor Yellow
    $script:WarnCount++
}

function Write-Header {
    param([string]$Title)
    Write-Host "`n-- $Title --" -ForegroundColor Cyan
}

function Test-PortReachability {
    param([string]$HostName, [int]$Port, [string]$ServiceName)
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $connect = $tcp.BeginConnect($HostName, $Port, $null, $null)
        $wait = $connect.AsyncWaitHandle.WaitOne($TimeoutSeconds * 1000, $false)
        if ($wait -and $tcp.Connected) {
            $tcp.EndConnect($connect)
            $tcp.Close()
            Write-Pass "$ServiceName ($HostName`:$Port) -- reachable"
            return $true
        } else {
            $tcp.Close()
            Write-Fail "$ServiceName ($HostName`:$Port) -- UNREACHABLE"
            return $false
        }
    } catch {
        Write-Fail "$ServiceName ($HostName`:$Port) -- UNREACHABLE ($_)"
        return $false
    }
}

function Test-HttpEndpoint {
    param([string]$Url, [string]$ServiceName, [int]$ExpectedCode = 200)
    try {
        $req = [System.Net.WebRequest]::Create($Url)
        $req.Timeout = $TimeoutSeconds * 1000
        $req.ServerCertificateValidationCallback = { $true }
        $resp = $req.GetResponse()
        $code = [int]$resp.StatusCode
        $resp.Close()
        if ($code -eq $ExpectedCode -or $code -eq 200 -or $code -eq 302 -or $code -eq 301) {
            Write-Pass "$ServiceName -> HTTP $code"
        } else {
            Write-Fail "$ServiceName -> HTTP $code (expected $ExpectedCode)"
        }
    } catch [System.Net.WebException] {
        if ($_.Response) {
            $code = [int]$_.Response.StatusCode
            if ($code -eq 200 -or $code -eq 302 -or $code -eq 401 -or $code -eq 403) {
                Write-Pass "$ServiceName -> HTTP $code (Service Active)"
                return
            }
        }
        Write-Fail "$ServiceName -> Unreachable ($Url)"
    } catch {
        Write-Fail "$ServiceName -> Exception: $_"
    }
}

Write-Host "`n+------------------------------------------------------+" -ForegroundColor Blue
Write-Host "|   Threat Detection Lab -- Health Check (Windows)     |" -ForegroundColor Blue
Write-Host "+------------------------------------------------------+" -ForegroundColor Blue
Write-Host "  Timestamp: $(Get-Date)" -ForegroundColor Gray

# Detection VLAN (192.168.50.0/24)
Write-Header "Detection VLAN -- 192.168.50.0/24"
Test-PortReachability "192.168.50.10" 22   "Zeek VM -- SSH"
Test-PortReachability "192.168.50.10" 4380 "RITA API"
Test-HttpEndpoint     "https://192.168.50.10:4380" "RITA Web"
Test-PortReachability "192.168.50.20" 22   "Arkime VM -- SSH"
Test-PortReachability "192.168.50.20" 8005 "Arkime Web UI"
Test-PortReachability "192.168.50.20" 9200 "Elasticsearch"
Test-HttpEndpoint     "http://192.168.50.20:8005" "Arkime UI"
Test-PortReachability "192.168.50.30" 22   "Velociraptor VM -- SSH"
Test-PortReachability "192.168.50.30" 8000 "Velociraptor Agent Port"
Test-PortReachability "192.168.50.30" 8889 "Velociraptor Web UI"
Test-HttpEndpoint     "https://192.168.50.30:8889" "Velociraptor UI"

# Intel VLAN (192.168.60.0/24)
Write-Header "Intel VLAN -- 192.168.60.0/24"
Test-PortReachability "192.168.60.10" 22  "MISP VM -- SSH"
Test-PortReachability "192.168.60.10" 443 "MISP HTTPS"
Test-HttpEndpoint     "https://192.168.60.10" "MISP Web UI"
Test-PortReachability "192.168.60.20" 22   "TheHive VM -- SSH"
Test-PortReachability "192.168.60.20" 9000 "TheHive API"
Test-PortReachability "192.168.60.20" 9001 "Cortex"
Test-HttpEndpoint     "http://192.168.60.20:9000" "TheHive Web UI"
Test-PortReachability "192.168.60.30" 22   "Shuffle VM -- SSH"
Test-PortReachability "192.168.60.30" 3001 "Shuffle Web UI"
Test-HttpEndpoint     "http://192.168.60.30:3001" "Shuffle UI"

# Target VLAN (192.168.30.0/24)
Write-Header "Target VLAN -- 192.168.30.0/24"
Test-PortReachability "192.168.30.10" 22  "Ubuntu Target -- SSH"

# Summary
Write-Host "`n======================================================" -ForegroundColor Blue
Write-Host "  Results: $PassCount passed  $FailCount failed  $WarnCount warnings" -ForegroundColor White
Write-Host "======================================================" -ForegroundColor Blue

if ($FailCount -eq 0) {
    Write-Host "  All tested endpoints are reachable!" -ForegroundColor Green
} else {
    Write-Host "  Some services failed checks. Start failing VMs or check VirtualBox network adapters." -ForegroundColor Yellow
}
