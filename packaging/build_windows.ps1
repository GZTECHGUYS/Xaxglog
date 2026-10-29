# Build the Windows one-folder portable .exe (and optional signed installer).
# Run from the repository root in PowerShell:
#   powershell -ExecutionPolicy Bypass -File packaging/build_windows.ps1
param(
  [string]$Python = "python",
  [string]$CertThumbprint = "",
  [string]$TimestampUrl = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

& $Python -m pip install --upgrade pyinstaller
& $Python -m PyInstaller packaging/xaxglog.spec --distpath dist --workpath build/pyinstaller --noconfirm

$Exe = Join-Path $Root "dist/Xaxglog/Xaxglog.exe"
if (-not (Test-Path $Exe)) { throw "PyInstaller did not produce $Exe" }

if ($CertThumbprint) {
  $Signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue
  if (-not $Signtool) { throw "signtool.exe not found; install the Windows SDK" }
  & $Signtool.Source sign /sha1 $CertThumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 $Exe
  Write-Host "signed $Exe"
} else {
  Write-Host "No certificate thumbprint supplied; artifact is UNSIGNED (development only)."
}

Write-Host "Portable build: dist/Xaxglog/"
Write-Host "Zip it for distribution: Compress-Archive -Path dist/Xaxglog -DestinationPath dist/Xaxglog-windows.zip"
