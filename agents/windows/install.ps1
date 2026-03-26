<#
.SYNOPSIS
    Install NetMon Windows agents as Windows services using NSSM or SC.

.DESCRIPTION
    Installs:
      - netmon-collector : session collector (firewall log tail / netstat)
      - netmon-deployer  : firewall rule deployer (LGPO)

.PARAMETER MqttHost     MQTT broker hostname/IP
.PARAMETER MqttPort     MQTT broker port (default 1883)
.PARAMETER MqttUser     MQTT username (optional)
.PARAMETER MqttPass     MQTT password (optional)
.PARAMETER InstallDir   Installation directory (default C:\netmon)
.PARAMETER NssmPath     Path to nssm.exe if available (optional)

.EXAMPLE
    .\install.ps1 -MqttHost 192.168.1.10
#>

param(
    [Parameter(Mandatory=$true)]  [string]$MqttHost,
    [int]    $MqttPort  = 1883,
    [string] $MqttUser  = "",
    [string] $MqttPass  = "",
    [string] $InstallDir = "C:\netmon",
    [string] $NssmPath  = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Require admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Please run this script as Administrator."
    exit 1
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot  = Split-Path -Parent (Split-Path -Parent $ScriptDir)

# Copy repo to install dir
Write-Host "==> Copying files to $InstallDir"
if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir | Out-Null }
Copy-Item -Recurse -Force "$RepoRoot\*" "$InstallDir\"

# Install paho-mqtt
Write-Host "==> Installing Python dependencies"
pip install paho-mqtt --quiet

$Python = (Get-Command python).Source
$Env_Vars = @{
    MQTT_HOST = $MqttHost
    MQTT_PORT = "$MqttPort"
    MQTT_USER = $MqttUser
    MQTT_PASS = $MqttPass
}

function Install-Service {
    param([string]$SvcName, [string]$Script, [string]$Display)

    $cmd = "`"$Python`" `"$InstallDir\$Script`""

    if ($NssmPath -and (Test-Path $NssmPath)) {
        Write-Host "==> Installing $SvcName with NSSM"
        & $NssmPath install $SvcName $Python "$InstallDir\$Script" | Out-Null
        foreach ($kv in $Env_Vars.GetEnumerator()) {
            & $NssmPath set $SvcName AppEnvironmentExtra "$($kv.Key)=$($kv.Value)" | Out-Null
        }
        & $NssmPath set $SvcName Start SERVICE_AUTO_START | Out-Null
        & $NssmPath start $SvcName | Out-Null
    } else {
        Write-Host "==> Installing $SvcName with SC (NSSM not found)"
        # Build environment string
        $envStr = ($Env_Vars.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join " "
        sc.exe create $SvcName binPath= "$cmd" start= auto DisplayName= $Display | Out-Null
        # Set environment via registry
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$SvcName"
        New-ItemProperty -Path $regPath -Name Environment -PropertyType MultiString `
            -Value ($Env_Vars.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) `
            -Force | Out-Null
        sc.exe start $SvcName | Out-Null
    }
    Write-Host "    $SvcName started."
}

Install-Service "netmon-collector" "agents\windows\session_collector.py" "NetMon Session Collector"
Install-Service "netmon-deployer"  "agents\windows\firewall_deployer.py"  "NetMon Firewall Deployer"

# Enable Windows Firewall logging
Write-Host "==> Enabling Windows Firewall logging"
netsh advfirewall set allprofiles logging allowedconnections enable | Out-Null
netsh advfirewall set allprofiles logging droppedconnections enable  | Out-Null
netsh advfirewall set allprofiles logging maxfilesize 4096           | Out-Null

Write-Host "==> Installation complete."
