# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Build, sign and publish an Umbra release.
#
#   powershell -File tools\release.ps1 -Version 1.1.0 -KeyFile C:\path\umbra-release-key.txt
#
# What it does, in order:
#   1. writes the version into app/rust/Cargo.toml and app/pubspec.yaml
#   2. runs the core test suite (a failing test stops the release)
#   3. flutter build windows --release
#   4. copies tor.exe / lyrebird.exe / bridges.txt next to the build
#   5. zips it and signs the zip with your Ed25519 key
#   6. creates the GitHub release and uploads zip + zip.sig
#
# The signature is what the in-app updater checks. Without the matching key the
# app refuses the update, so keep the key file off the repository and backed up.

param(
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$KeyFile,
    [switch]$SkipPublish
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$app = Join-Path $root 'app'
$release = Join-Path $app 'build\windows\x64\runner\Release'
$dist = Join-Path $root 'dist'
$zip = Join-Path $dist "Umbra-$Version.zip"

if (-not (Test-Path $KeyFile)) { throw "podepisovací klíč nenalezen: $KeyFile" }
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "verze musí být X.Y.Z, dostal jsem '$Version'" }

Write-Host "== verze -> $Version =="
$cargo = Join-Path $app 'rust\Cargo.toml'
(Get-Content $cargo -Raw) -replace '(?m)^version = "\d+\.\d+\.\d+"', "version = `"$Version`"" |
    Set-Content $cargo -Encoding utf8 -NoNewline
$pubspec = Join-Path $app 'pubspec.yaml'
(Get-Content $pubspec -Raw) -replace '(?m)^version: .*$', "version: $Version+1" |
    Set-Content $pubspec -Encoding utf8 -NoNewline

Write-Host "== testy jádra =="
Push-Location $root
cargo test -p umbra-core
if ($LASTEXITCODE -ne 0) { Pop-Location; throw 'testy jádra neprošly — nevydávám' }

Write-Host "== build =="
Push-Location $app
flutter build windows --release
if ($LASTEXITCODE -ne 0) { Pop-Location; Pop-Location; throw 'build selhal' }
Pop-Location

Write-Host "== Tor a mosty k buildu =="
$torSource = Join-Path $root 'dist\tor'
foreach ($f in @('tor.exe', 'lyrebird.exe', 'bridges.txt')) {
    $src = Join-Path $torSource $f
    if (-not (Test-Path $src)) { throw "chybí $src — dej tam Tor Expert Bundle (viz README)" }
    Copy-Item $src $release -Force
}

Write-Host "== zip + podpis =="
New-Item -ItemType Directory -Force -Path $dist | Out-Null
if (Test-Path $zip) { Remove-Item $zip -Force }
# One top-level folder inside the zip; the updater strips it when unpacking.
$staging = Join-Path $dist "Umbra-$Version"
if (Test-Path $staging) { Remove-Item $staging -Recurse -Force }
New-Item -ItemType Directory -Force -Path $staging | Out-Null
Copy-Item (Join-Path $release '*') $staging -Recurse -Force
Compress-Archive -Path $staging -DestinationPath $zip
Remove-Item $staging -Recurse -Force

cargo build -p umbra-cli --bin umbra-sign --release
& (Join-Path $root 'target\release\umbra-sign.exe') sign $KeyFile $zip
if ($LASTEXITCODE -ne 0) { Pop-Location; throw 'podpis selhal' }
Pop-Location

if ($SkipPublish) {
    Write-Host "hotovo (bez publikování): $zip"
    return
}

Write-Host "== GitHub release =="
gh release create "v$Version" $zip "$zip.sig" --title "Umbra $Version" --generate-notes
Write-Host "vydáno: v$Version"
