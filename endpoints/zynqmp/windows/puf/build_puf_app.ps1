# SPDX-License-Identifier: Apache-2.0
# Step B1: build AMD's xilskey PUF registration example for the A53, in boot-header mode, with the red key.
#   powershell -ExecutionPolicy Bypass -File build_puf_app.ps1 [-Xsa C:\tz\aegis\aegis_zu4eg_pqc.xsa] [-ExampleDir <dir>]
# Everything goes to C:\tz\aegis-keys\build (owner-only ACL inherited from C:\tz\aegis-keys). Nothing touches the board.
# Stops at the first failed check. Output: build\BUILD_OK.txt with the ELF path and its SHA-256.
param(
  [string]$Xsa = '',
  [string]$ExampleDir = ''   # folder holding the two example files; default: search the Vitis 2025.2 install
)
. "$PSScriptRoot\puf_common.ps1"

Assert-OwnerOnlyAcl $KeyDir -RequireProtected
Assert-NotInGit $KeyDir
$red = Read-HexFile $RedKeyFile 32
$null = Read-HexFile $IvFile 12
if (Test-Path $BuildDir) { Fail "$BuildDir exists: run cleanup_puf_build.ps1 first (one build at a time)" }

if (-not $Xsa) {
  $Xsa = @('C:\tz\aegis\aegis_zu4eg_pqc.xsa', 'C:\tz\aegis\aegis_zu4eg.xsa') | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $Xsa -or -not (Test-Path $Xsa)) { Fail 'no XSA found; pass -Xsa' }

if (-not $ExampleDir) {
  $hits = @(Get-ChildItem -Path "$AmdRoot\Vitis\data\embeddedsw" -Recurse -Filter 'xilskey_puf_registration_example.c' -ErrorAction SilentlyContinue)
  if ($hits.Count -ne 1) { Fail "found $($hits.Count) copies of xilskey_puf_registration_example.c under $AmdRoot\Vitis\data\embeddedsw; pass -ExampleDir" }
  $ExampleDir = $hits[0].DirectoryName
}
"EXAMPLE_DIR $ExampleDir"
"XSA         $Xsa"
"KEY_ID      $(Get-KeyId $red)"

New-Item -ItemType Directory -Force $BuildDir | Out-Null
Assert-OwnerOnlyAcl $BuildDir
$src = Join-Path $BuildDir 'src'
$ws  = Join-Path $BuildDir 'ws'

# 1. patched copies of the example (sha256-pinned originals, switches set, guard block, key inserted)
Invoke-Python @("$PSScriptRoot\prepare_puf_src.py", '--src-dir', $ExampleDir, '--red-key', $RedKeyFile,
                '--iv', $IvFile, '--out-dir', $src) 'prepare_puf_src.py'

# 2. Vitis: platform, libraries, application, build
Stop-VitisServers
$env:AEGIS_PUF_WS  = $ws -replace '\\', '/'
$env:AEGIS_PUF_XSA = $Xsa -replace '\\', '/'
$env:AEGIS_PUF_SRC = $src -replace '\\', '/'
& $VitisBat -s "$PSScriptRoot\vitis_puf_app.py" *> (Join-Path $BuildDir 'vitis.log')
$vitisRc = $LASTEXITCODE
Stop-VitisServers
$vlog = Get-Content -Raw (Join-Path $BuildDir 'vitis.log')
if ($vlog -notmatch 'APP_BUILT') { Fail "Vitis build did not finish (exit $vitisRc); see $BuildDir\vitis.log" }
if ($vlog -match 'Aegis guard') { Fail 'the Aegis guard stopped the compile; see vitis.log' }

# 3. the ELF: one file, then the static eFUSE check
$elf = @(Get-ChildItem -Path (Join-Path $ws 'puf_reg') -Recurse -Filter 'puf_reg.elf' -ErrorAction SilentlyContinue)
if ($elf.Count -ne 1) { Fail "expected one puf_reg.elf under $ws\puf_reg, found $($elf.Count)" }
$elfPath = $elf[0].FullName
Invoke-Python @("$PSScriptRoot\check_puf_elf.py", $elfPath, '--red-key', $RedKeyFile, '--iv', $IvFile) 'check_puf_elf.py'

# 4. the compiled copies Vitis imported must still be the verified ones
$imported = Join-Path $ws 'puf_reg\src'
foreach ($f in 'xilskey_puf_registration_example.c', 'xilskey_puf_registration.h') {
  $a = (Get-FileHash (Join-Path $src $f) -Algorithm SHA256).Hash
  $b = (Get-FileHash (Join-Path $imported $f) -Algorithm SHA256).Hash
  if ($a -ne $b) { Fail "$f in the Vitis component differs from the verified copy" }
}
Invoke-Python @("$PSScriptRoot\prepare_puf_src.py", '--verify', $imported, '--red-key', $RedKeyFile, '--iv', $IvFile) 'header re-check'

$hash = (Get-FileHash $elfPath -Algorithm SHA256).Hash
Set-Content -Path (Join-Path $BuildDir 'BUILD_OK.txt') -Encoding ascii -Value @("elf $elfPath", "sha256 $hash", "keyid $(Get-KeyId $red)")
"BUILD_OK $elfPath sha256 $hash"
