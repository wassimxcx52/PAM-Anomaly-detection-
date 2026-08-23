# setup-env.ps1 -- one-time env setup for the PAM stack (Windows).
#   Run from the deploy/ folder:  ./setup-env.ps1
# Detects this machine's LAN IP (paste into WALLIX SIEM config), asks for the
# WALLIX VM IP, and writes .env from .env.example.

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

# --- detect the host LAN IP (the address WALLIX must forward logs to) ---
$hostIp = (Get-NetIPAddress -AddressFamily IPv4 |
  Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" -and
                 $_.PrefixOrigin -ne "WellKnown" -and $_.IPAddress -like "192.168.*" } |
  Select-Object -First 1 -ExpandProperty IPAddress)
if (-not $hostIp) { $hostIp = "<your-LAN-IP>" }

Write-Host ""
Write-Host "This machine's LAN IP : $hostIp" -ForegroundColor Cyan
Write-Host "  -> In the WALLIX GUI, set SIEM Integration destination + syslog to THIS IP."
Write-Host ""

# --- ask for the WALLIX VM IP (the only per-machine value in .env) ---
$wallixIp = Read-Host "Enter the WALLIX Bastion VM IP (from the VM console)"
if (-not $wallixIp) { Write-Host "No IP entered, aborting."; exit 1 }

# --- write .env ---
Copy-Item .env.example .env -Force
(Get-Content .env) -replace '^WALLIX_HOST=.*', "WALLIX_HOST=$wallixIp" | Set-Content .env -Encoding utf8

Write-Host ""
Write-Host ".env written: WALLIX_HOST=$wallixIp" -ForegroundColor Green
Write-Host "Edit .env to change the Grafana password / port if needed, then run:"
Write-Host "  docker compose -f docker-compose.yml up -d --build"
