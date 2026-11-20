# SPDX-License-Identifier: Apache-2.0
# Step C: build the encrypted BOOT.BIN on the Windows PC (the only place the red key is).
#   powershell -ExecutionPolicy Bypass -File make_boot_encrypted.ps1 -RegDir C:\tz\aegis-keys\reg-<time> [-Auth none|bh]
# Partition inputs default to C:\tz\stage\linux-side, which must hold the six inputs of the current plain BOOT.BIN
# and their SHA256SUMS (from the Linux PC's bootimg/v3; none of them is secret). The sums are checked. Output: C:\tz\stage\boot-enc-<time>\
# BOOT.BIN, boot-encrypted.bif, report.txt, bootgen.log, SHA256SUMS. The output holds no key (checked).
param(
  [Parameter(Mandatory = $true)][string]$RegDir,
  [ValidateSet('none', 'bh')][string]$Auth = 'none',
  [string]$Stage = 'C:\tz\stage\linux-side',
  [string]$Fsbl  = '',
  [string]$Pmufw = '',
  [string]$Bit   = '',
  [string]$ExpectSums = ''
)
. "$PSScriptRoot\puf_common.ps1"
Assert-OwnerOnlyAcl $KeyDir -RequireProtected
$null = Read-HexFile $RedKeyFile 32
if (-not $Fsbl)  { $Fsbl  = Join-Path $Stage 'fsbl.elf' }
if (-not $Pmufw) { $Pmufw = Join-Path $Stage 'pmufw.elf' }
if (-not $Bit)   { $Bit   = Join-Path $Stage 'system.bit' }
if (-not $ExpectSums -and (Test-Path (Join-Path $Stage 'SHA256SUMS'))) { $ExpectSums = Join-Path $Stage 'SHA256SUMS' }
$out = "C:\tz\stage\boot-enc-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$a = @("$PSScriptRoot\make_boot_encrypted.py", '--red-key', $RedKeyFile, '--reg-dir', $RegDir,
       '--fsbl', $Fsbl, '--pmufw', $Pmufw, '--bit', $Bit,
       '--bl31', (Join-Path $Stage 'bl31.elf'), '--tee', (Join-Path $Stage 'tee-raw.bin'), '--uboot', (Join-Path $Stage 'u-boot.elf'),
       '--out-dir', $out, '--bootgen', $Bootgen, '--auth', $Auth, '--auth-dir', (Join-Path $KeyDir 'auth'))
if ($ExpectSums) { $a += @('--expect-sums', $ExpectSums) }
Invoke-Python $a 'make_boot_encrypted.py'
Get-ChildItem -Path $KeyDir -Directory -Filter 'bootgen-*' -ErrorAction SilentlyContinue | ForEach-Object { Write-Warning "left-over $($_.FullName): run cleanup_puf_build.ps1" }
"OUTPUT $out"
