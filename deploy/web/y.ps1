$ErrorActionPreference = "Stop"

$BaseUrl = $env:BH_BASE_URL
if ([string]::IsNullOrWhiteSpace($BaseUrl)) { $BaseUrl = "https://bhsocket.io" }
$HostName = $env:BH_SOCKET_HOST
if ([string]::IsNullOrWhiteSpace($HostName)) { $HostName = "bhsocket.io" }
$Port = $env:BH_SOCKET_PORT
if ([string]::IsNullOrWhiteSpace($Port)) { $Port = "443" }

$InstallDir = Join-Path $env:LOCALAPPDATA "BHSocket"
$BinDir = Join-Path $InstallDir "bin"
$Archive = Join-Path $env:TEMP "bh-netcat_x86_64-cygwin.tar.gz"
$Url = "$BaseUrl/bin/bh-netcat_x86_64-cygwin.tar.gz"

Write-Host "--> Trying x86_64-cygwin"
Write-Host -NoNewline "--> Downloading binaries                                              "
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
Invoke-WebRequest -Uri $Url -OutFile $Archive -UseBasicParsing
Write-Host "[OK]"

Write-Host -NoNewline "--> Unpacking binaries                                                "
tar -xzf $Archive -C $BinDir
$Real = Join-Path $BinDir "bh-netcat.real.exe"
$Source = Join-Path $BinDir "gs-netcat"
if (Test-Path $Source) {
  Move-Item -Force $Source $Real
} elseif (Test-Path "$Source.exe") {
  Move-Item -Force "$Source.exe" $Real
}
Write-Host "[OK]"

Write-Host -NoNewline "--> Copying binaries                                                  "
$Cmd = Join-Path $BinDir "bh-netcat.cmd"
@"
@echo off
set GSOCKET_HOST=$HostName
set GSOCKET_PORT=$Port
set GS_HOST=$HostName
set GS_PORT=$Port
"$Real" %*
"@ | Set-Content -Encoding ASCII $Cmd
Write-Host "[OK]"

Write-Host "--> Installed $Cmd"
Write-Host "--> Add $BinDir to PATH if bh-netcat is not found in a new terminal."
Write-Host ""
Write-Host "--> To connect:"
Write-Host "--> bh-netcat -s `"SECRET`" -i"
