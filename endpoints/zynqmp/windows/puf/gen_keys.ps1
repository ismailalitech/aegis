# SPDX-License-Identifier: Apache-2.0
# Step A: generate the red key (AES-256) and the black-key IV on the Windows PC.
#   powershell -ExecutionPolicy Bypass -File gen_keys.ps1
# Writes C:\tz\aegis-keys\red_key.hex (32 bytes) and black_key_iv.hex (12 bytes) from .NET's CSPRNG
# (System.Security.Cryptography.RandomNumberGenerator), with an ACL that gives only the current user access.
# It never overwrites existing keys: a new red key needs a new PUF registration and a new BOOT.BIN.
# The red key stays on this PC: not in git, not on the Linux PC. (It reaches the board's RAM once, over JTAG, when
# the registration app runs; that is how the PUF encrypts it. Nothing on the board stores it.)
. "$PSScriptRoot\puf_common.ps1"

if (Test-Path $RedKeyFile) { Fail "$RedKeyFile exists; keys are never overwritten (delete by hand only if you mean to start over)" }
if (Test-Path $IvFile) { Fail "$IvFile exists; keys are never overwritten" }

New-Item -ItemType Directory -Force $KeyDir | Out-Null
Set-OwnerOnlyAcl $KeyDir
Assert-OwnerOnlyAcl $KeyDir -RequireProtected
Assert-NotInGit $KeyDir

function New-RandomHex([int]$n) {
  $buf = New-Object byte[] $n
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  try { $rng.GetBytes($buf) } finally { $rng.Dispose() }
  if (-not ($buf | Where-Object { $_ -ne 0 })) { Fail 'RNG returned all zero bytes' }
  ($buf | ForEach-Object { $_.ToString('X2') }) -join ''
}

$red = New-RandomHex 32
$iv  = New-RandomHex 12
# ASCII, no BOM, one line: the format prepare_puf_src.py and make_boot_encrypted.py read.
[IO.File]::WriteAllText($RedKeyFile, $red + "`r`n", [Text.Encoding]::ASCII)
[IO.File]::WriteAllText($IvFile, $iv + "`r`n", [Text.Encoding]::ASCII)
foreach ($f in $RedKeyFile, $IvFile) { Assert-OwnerOnlyAcl $f }

"KEY_DIR   $KeyDir"
"RED_KEY   red_key.hex      key id $(Get-KeyId $red)   (the key itself is not printed)"
"BLACK_IV  black_key_iv.hex"
& icacls.exe $KeyDir
"GEN_KEYS_OK"
