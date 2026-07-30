# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Build, sign and publish an NullChat release.
#
#   powershell -File tools\release.ps1 -Version 1.1.0 -KeyFile C:\path\nullchat-release-key.txt
#
# What it does, in order:
#   1. writes the version into app/rust/Cargo.toml and app/pubspec.yaml
#   2. runs the core test suite (a failing test stops the release)
#   3. flutter build windows --release
#   4. copies tor.exe / lyrebird.exe / bridges.txt from dist/tor next to the build
#   5. zips it and signs the zip with your Ed25519 key
#   6. creates the GitHub release and uploads zip + zip.sig
#
# The signature is what the in-app updater checks. Without the matching key the
# app refuses the update, so keep the key file out of the repository and backed
# up. This file stays plain ASCII on purpose: Windows PowerShell reads .ps1 as
# ANSI, and accented characters would break parsing.

param(
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$KeyFile,
    [switch]$SkipPublish
)

$ErrorActionPreference = 'Stop'

# libsignal generates code from protobufs at build time, and the JDK's internal
# pipes fail under an 8.3-shortened TEMP path, which breaks the Android build.
if (-not $env:PROTOC -and (Test-Path 'C:\protoc\bin\protoc.exe')) { $env:PROTOC = 'C:\protoc\bin\protoc.exe' }
if ($env:TEMP -match '~') { New-Item -ItemType Directory -Force -Path 'C:\Temp' | Out-Null; $env:TMP = 'C:\Temp'; $env:TEMP = 'C:\Temp' }
$root = Split-Path -Parent $PSScriptRoot
$app = Join-Path $root 'app'
$release = Join-Path $app 'build\windows\x64\runner\Release'
$dist = Join-Path $root 'dist'
$zip = Join-Path $dist "NullChat-$Version.zip"

if (-not (Test-Path $KeyFile)) { throw "signing key not found: $KeyFile" }
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "version must be X.Y.Z, got '$Version'" }

# Refuse to release from a dirty tree. What gets built here comes from the
# working copy, but the tag is created from a commit - so anything uncommitted
# ships in the binaries and is missing from the tag, and nobody can rebuild what
# people are running. This is not hypothetical: 2.1.0 was tagged on a commit
# that still said 2.0.2, and the Linux build (which CI makes from the commit)
# reported that older number back to its own updater.
$dirty = git -C $root status --porcelain 2>$null
if ($LASTEXITCODE -ne 0) { throw 'not a git checkout - releasing needs one, so the tag can point at real source' }
if ($dirty) {
    Write-Host $dirty
    throw 'the working tree has uncommitted changes - commit or stash them, then release'
}

Write-Host "== version -> $Version =="
# Write UTF-8 *without* a BOM: PowerShell's -Encoding utf8 adds one, and a BOM
# in pubspec.yaml makes the flutter_rust_bridge codegen refuse to read it.
$noBom = New-Object System.Text.UTF8Encoding($false)
$cargo = Join-Path $app 'rust\Cargo.toml'
$text = (Get-Content $cargo -Raw) -replace '(?m)^version = "\d+\.\d+\.\d+"', "version = `"$Version`""
[System.IO.File]::WriteAllText($cargo, $text, $noBom)
$pubspec = Join-Path $app 'pubspec.yaml'
$text = (Get-Content $pubspec -Raw) -replace '(?m)^version: .*$', "version: $Version+1"
[System.IO.File]::WriteAllText($pubspec, $text, $noBom)

Write-Host "== core tests =="
Push-Location $root
cargo test -p nullchat-core
if ($LASTEXITCODE -ne 0) { Pop-Location; throw 'core tests failed - not releasing' }

Write-Host "== build =="
Push-Location $app
flutter build windows --release
if ($LASTEXITCODE -ne 0) { Pop-Location; Pop-Location; throw 'build failed' }
Pop-Location

Write-Host "== tor + bridges into the build =="
$torSource = Join-Path $root 'dist\tor'
foreach ($f in @('tor.exe', 'lyrebird.exe', 'bridges.txt')) {
    $src = Join-Path $torSource $f
    if (-not (Test-Path $src)) { Pop-Location; throw "missing $src (Tor Expert Bundle - see README)" }
    Copy-Item $src $release -Force
}

Write-Host "== zip + signature =="
New-Item -ItemType Directory -Force -Path $dist | Out-Null
if (Test-Path $zip) { Remove-Item $zip -Force }
if (Test-Path "$zip.sig") { Remove-Item "$zip.sig" -Force }
# One top-level folder inside the zip; the updater strips it when unpacking.
$staging = Join-Path $dist "NullChat-$Version"
if (Test-Path $staging) { Remove-Item $staging -Recurse -Force }
New-Item -ItemType Directory -Force -Path $staging | Out-Null
Copy-Item (Join-Path $release '*') $staging -Recurse -Force
Compress-Archive -Path $staging -DestinationPath $zip
Remove-Item $staging -Recurse -Force

cargo build -p nullchat-cli --bin nullchat-sign --release
if ($LASTEXITCODE -ne 0) { Pop-Location; throw 'building the signer failed' }
$signer = Join-Path $root 'target\release\nullchat-sign.exe'
& $signer sign $KeyFile $zip
if ($LASTEXITCODE -ne 0) { Pop-Location; throw 'signing failed' }

# A signature alone says only "the author built this", and every past release
# keeps a valid one, so it cannot stop an old, fixed-since version from being
# replayed at users. The manifest binds version and archive together, and is
# signed as well.
#
# The size is in there for a second reason: GitHub's asset CDN does not always
# send Content-Length, and without a total the updater's progress bar had
# nothing to divide by and looked like it was downloading forever.
$manifestPath = Join-Path $dist "MANIFEST-$Version.txt"
$sha = (Get-FileHash -Path $zip -Algorithm SHA256).Hash.ToLower()
$size = (Get-Item $zip).Length
$manifest = "version=$Version`nsha256=$sha`nsize=$size`n"
[System.IO.File]::WriteAllText($manifestPath, $manifest, (New-Object System.Text.UTF8Encoding($false)))
& $signer sign $KeyFile $manifestPath
if ($LASTEXITCODE -ne 0) { Pop-Location; throw 'signing the manifest failed' }
Pop-Location

# What changed, published as a plain file so the in-app updater can show it
# before the user agrees to anything.
#
# The text comes from CHANGELOG.md, which is written in English for the person
# installing the update. STATUS.md is the developer's Czech notebook and reads
# like one, which is not what belongs in a release.
$notesPath = Join-Path $dist "NOTES-$Version.md"
$changelog = Join-Path $root 'CHANGELOG.md'
$notes = "NullChat $Version"
if (Test-Path $changelog) {
    $text = Get-Content $changelog -Raw
    $pattern = "(?ms)^##\s+$([regex]::Escape($Version))\s*\r?\n(.*?)(?=^##\s|\z)"
    $section = [regex]::Match($text, $pattern)
    if ($section.Success) {
        $notes = "NullChat $Version`r`n`r`n" + ($section.Groups[1].Value).Trim()
    } else {
        Write-Warning "CHANGELOG.md has no section for $Version - releasing with a bare title"
    }
}
Set-Content -Path $notesPath -Value $notes -Encoding utf8

if ($SkipPublish) {
    Write-Host "done (not published): $zip"
    return
}

Write-Host "== commit the version bump =="
# The bump has to be a commit before the tag exists, and the tag has to name
# that exact commit: `gh release create` otherwise tags whatever the default
# branch points at, which is how a release ends up describing source that says
# a different version.
git -C $root add app/rust/Cargo.toml app/pubspec.yaml Cargo.lock
if ($LASTEXITCODE -ne 0) { throw 'git add failed' }
# --allow-empty-message would be wrong here; if nothing changed, the bump was
# already committed and we just carry on with the existing HEAD.
$staged = git -C $root diff --cached --name-only
if ($staged) {
    git -C $root commit -m "chore(release): $Version"
    if ($LASTEXITCODE -ne 0) { throw 'committing the version bump failed' }
}
git -C $root push
if ($LASTEXITCODE -ne 0) { throw 'pushing the version bump failed - the tag would point at the wrong commit' }
$target = (git -C $root rev-parse HEAD).Trim()
Write-Host "tagging $target"

Write-Host "== GitHub release =="
# Uploading tens of megabytes over a slow link fails often enough to be normal,
# and a half-uploaded release is worse than none: it sits there as a draft with
# assets the updater cannot use. Retry, and only then give up loudly.
$assets = @($zip, "$zip.sig", $notesPath, $manifestPath, "$manifestPath.sig")
$published = $false
foreach ($attempt in 1..3) {
    if ($attempt -gt 1) {
        Write-Host "upload attempt $attempt (cleaning up the previous one)"
        gh release delete "v$Version" --yes --cleanup-tag 2>&1 | Out-Null
        Start-Sleep -Seconds 5
    }
    gh release create "v$Version" @assets --target $target --title "NullChat $Version" --notes-file $notesPath
    if ($LASTEXITCODE -eq 0) { $published = $true; break }
}
if (-not $published) { throw "gh release create failed after 3 attempts - assets are in $dist" }
Write-Host "released: v$Version"

# Windows is done; Linux and Android are not, and neither can be finished here
# without saying so. The tag push starts the Linux build on CI, but CI has no
# signing key - the tarball it attaches stays unsigned until this is run.
Write-Host ''
Write-Host 'Still to do for this release:'
Write-Host "  1. wait for the Linux build: gh run list -R LukasVitek67/umbra -w release-linux.yml"
Write-Host "  2. sign it:  powershell -File tools\sign-linux.ps1 -Version $Version -KeyFile <key>"
Write-Host '  3. paste the printed hashes into packaging/arch/PKGBUILD and commit'
Write-Host "  4. APKs: flutter build apk --release --split-per-abi --no-tree-shake-icons"
Write-Host "     then sign each and upload: gh release upload v$Version <apk> <apk>.sig"
