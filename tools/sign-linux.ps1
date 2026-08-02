# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Sign the Linux release tarball and publish its manifest.
#
#   powershell -File tools\sign-linux.ps1 -Version 2.1.0 -KeyFile C:\path\nullchat-release-key.txt
#
# Why this is a separate step and not part of the CI workflow: the signing key
# must never exist on a GitHub runner. The Linux tarball is built by
# .github/workflows/release-linux.yml, which attaches it to the release; this
# script signs THAT published file and uploads the signature next to it.
#
# It downloads the asset instead of signing a local copy on purpose. A locally
# rebuilt tarball has the same contents but different archive metadata (mtimes,
# gzip header), so its hash differs and the signature would not match what
# people actually download. Signing the published bytes is the only correct
# thing to do here.
#
# The manifest is Linux-specific: MANIFEST-<ver>.txt describes the Windows zip
# for the in-app updater, and packaging/arch/PKGBUILD needs the hash and size of
# the tarball, so it reads MANIFEST-<ver>-linux-x86_64.txt written below.
#
# This file stays plain ASCII on purpose: Windows PowerShell reads .ps1 as ANSI.

param(
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$KeyFile,
    [switch]$SkipPublish
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$signer = Join-Path $root 'target\release\nullchat-sign.exe'
# The public half baked into every build; verifying here catches a wrong key
# file before anything is uploaded.
$pubkey = '89fec22189550db91adda520386ee2810725d95d8e21e71e31d9f5f7ff512e00'

if (-not (Test-Path $KeyFile)) { throw "signing key not found: $KeyFile" }
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "version must be X.Y.Z, got '$Version'" }

if (-not (Test-Path $signer)) {
    Push-Location $root
    cargo build -p nullchat-cli --bin nullchat-sign --release
    if ($LASTEXITCODE -ne 0) { Pop-Location; throw 'building the signer failed' }
    Pop-Location
}

$name = "NullChat-$Version-linux-x86_64.tar.gz"
$dir = Join-Path $root 'dist\linux'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$tarball = Join-Path $dir $name

Write-Host "== fetching the published tarball =="
Remove-Item $tarball, "$tarball.sig" -Force -ErrorAction SilentlyContinue
gh release download "v$Version" -R LukasVitek67/umbra -p $name -D $dir --clobber
if ($LASTEXITCODE -ne 0) { throw "no $name on release v$Version - has the Linux workflow run for this tag?" }

# What the release says the file is, against what actually landed on disk.
#
# This is not paranoia. On a bad line `gh release download` has returned 0
# having written a partial file, and the next two steps sign whatever is in
# front of them: 2.5.11 shipped a signature and a manifest computed over 8.3 MB
# of a 14.2 MB tarball. Both were valid signatures - of the wrong bytes - so
# nothing downstream could tell, and the Arch package would have refused the
# real file. A signature is a statement about content; signing content you did
# not fully receive is the one mistake that turns the whole scheme into
# decoration.
$expected = gh release view "v$Version" -R LukasVitek67/umbra --json assets `
    --jq ".assets[] | select(.name==`"$name`") | .size"
if ($LASTEXITCODE -ne 0 -or -not $expected) { throw "could not read the published size of $name" }
$actual = (Get-Item $tarball).Length
if ([int64]$expected -ne [int64]$actual) {
    throw "$name came down incomplete: $actual of $expected bytes. Re-run; the download resumes."
}
Write-Host "  $actual bytes, matching the published asset"

Write-Host "== signing =="
& $signer sign $KeyFile $tarball
if ($LASTEXITCODE -ne 0) { throw 'signing the tarball failed' }

$sha = (Get-FileHash -Path $tarball -Algorithm SHA256).Hash.ToLower()
$size = (Get-Item $tarball).Length
$manifest = Join-Path $dir "MANIFEST-$Version-linux-x86_64.txt"
$noBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($manifest, "version=$Version`nsha256=$sha`nsize=$size`n", $noBom)
Remove-Item "$manifest.sig" -Force -ErrorAction SilentlyContinue
& $signer sign $KeyFile $manifest
if ($LASTEXITCODE -ne 0) { throw 'signing the manifest failed' }

& $signer verify $pubkey $tarball
if ($LASTEXITCODE -ne 0) { throw 'the tarball signature does not verify - wrong key?' }
& $signer verify $pubkey $manifest
if ($LASTEXITCODE -ne 0) { throw 'the manifest signature does not verify - wrong key?' }

if (-not $SkipPublish) {
    Write-Host "== uploading =="
    gh release upload "v$Version" -R LukasVitek67/umbra --clobber `
        "$tarball.sig" $manifest "$manifest.sig"
    if ($LASTEXITCODE -ne 0) { throw 'uploading failed' }
}

# packaging/arch/PKGBUILD pins these, in source order, rather than using SKIP.
Write-Host ''
Write-Host 'sha256sums for packaging/arch/PKGBUILD:'
foreach ($f in @($tarball, "$tarball.sig", $manifest, "$manifest.sig")) {
    '  {0}  # {1}' -f (Get-FileHash -Path $f -Algorithm SHA256).Hash.ToLower(), (Split-Path $f -Leaf)
}
