# Close the PostgreSQL port to the LAN.
#
# A default PostgreSQL install answers on every interface (listen_addresses =
# '*'), so the database — and every credential in it — is reachable from any
# device on the same Wi-Fi. NetPulse only ever connects from the machine it runs
# on, so the listener belongs on loopback.
#
# Idempotent: re-running changes nothing once listen_addresses is localhost.
# Run from an elevated PowerShell prompt:
#
#   powershell -ExecutionPolicy Bypass -File scripts\harden_postgres.ps1
#
# On Linux the same change is one line in /etc/postgresql/<version>/main/
# postgresql.conf followed by `sudo systemctl restart postgresql`.

$ErrorActionPreference = "Stop"

$service = Get-Service -Name "postgresql-x64-*" -ErrorAction SilentlyContinue |
    Select-Object -First 1
if (-not $service) {
    Write-Error "No PostgreSQL service found (postgresql-x64-*)."
    exit 1
}

$dataDir = $null
$imagePath = (Get-CimInstance Win32_Service -Filter "Name='$($service.Name)'").PathName
if ($imagePath -match '-D\s+"?([^"]+)"?') {
    $dataDir = $matches[1].Trim()
}
if (-not $dataDir -or -not (Test-Path (Join-Path $dataDir "postgresql.conf"))) {
    Write-Error "Could not locate postgresql.conf for $($service.Name)."
    exit 1
}

$confPath = Join-Path $dataDir "postgresql.conf"
$original = Get-Content -LiteralPath $confPath -Raw

$updated = [regex]::Replace(
    $original,
    "(?m)^\s*listen_addresses\s*=\s*'[^']*'",
    "listen_addresses = 'localhost'"
)

if ($updated -eq $original) {
    Write-Host "listen_addresses already restricted; nothing to change."
} else {
    $backup = "$confPath.bak-netpulse"
    if (-not (Test-Path $backup)) {
        Copy-Item -LiteralPath $confPath -Destination $backup
        Write-Host "Backed up to $backup"
    }
    Set-Content -LiteralPath $confPath -Value $updated -NoNewline
    Write-Host "listen_addresses is now 'localhost'."
}

# hba still allows loopback only, which is what we want; reload covers a
# listen_addresses change, but a restart is what actually rebinds the socket.
Restart-Service -Name $service.Name -Force
Start-Sleep -Seconds 3

$listening = Get-NetTCPConnection -LocalPort 5432 -State Listen -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty LocalAddress -Unique
if ($listening -and ($listening -contains "0.0.0.0" -or $listening -contains "::")) {
    Write-Warning "Port 5432 still answers on all interfaces: $($listening -join ', ')"
    exit 1
}

Write-Host "Port 5432 now listens on: $($listening -join ', ')"
