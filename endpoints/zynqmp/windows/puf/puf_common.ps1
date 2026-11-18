# Shared paths and helpers for the PUF scripts (dot-sourced: . "$PSScriptRoot\puf_common.ps1").
# Windows PowerShell 5.1. Nothing here touches the board.
$ErrorActionPreference = 'Stop'

$AmdRoot   = 'C:\AMDDesignTools\2025.2'
$VitisBat  = "$AmdRoot\Vitis\bin\vitis.bat"
$XsdbBat   = "$AmdRoot\Vitis\bin\xsdb.bat"
$Bootgen   = "$AmdRoot\Vitis\bin\bootgen.bat"     # verify: 2025.2 also ships it under Vivado\bin
$KeyDir    = 'C:\tz\aegis-keys'                    # red key, IV, logs, registration outputs; never in git
$BuildDir  = 'C:\tz\aegis-keys\build'              # temporary: sources with the key, Vitis workspace, ELF
$ComPort   = 'COM11'                               # TE0790 UART (MPSoC UART0), 115200 8N1

$RedKeyFile = Join-Path $KeyDir 'red_key.hex'
$IvFile     = Join-Path $KeyDir 'black_key_iv.hex'

function Fail([string]$msg) { throw "PUF STEP FAILED: $msg" }

function Find-Python {
  # 1) the py launcher, 2) python.exe on PATH (not the WindowsApps stub), 3) a python.exe inside the AMD install.
  $py = Get-Command py.exe -ErrorAction SilentlyContinue
  if ($py) { return @{ Exe = $py.Source; Pre = @('-3') } }
  $p = Get-Command python.exe -ErrorAction SilentlyContinue | Where-Object { $_.Source -notmatch 'WindowsApps' } | Select-Object -First 1
  if ($p) { return @{ Exe = $p.Source; Pre = @() } }
  $p = Get-ChildItem -Path "$AmdRoot\Vitis" -Recurse -Filter python.exe -ErrorAction SilentlyContinue |
       Where-Object { $_.FullName -notmatch '\\Lib\\' } | Select-Object -First 1
  if ($p) { return @{ Exe = $p.FullName; Pre = @() } }
  Fail 'no Python 3 found (install one, or put one on PATH)'
}

function Invoke-Python([string[]]$ArgsList, [string]$What) {
  # Runs a script from this folder with -I (isolated mode); stops on a non-zero exit.
  $py = Find-Python
  $pre = $py.Pre
  & $py.Exe @pre '-I' @ArgsList | Out-Host
  if ($LASTEXITCODE -ne 0) { Fail "$What (exit code $LASTEXITCODE)" }
}

function Get-CurrentUserSid { [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value }

function Set-OwnerOnlyAcl([string]$path) {
  # Remove inherited entries; full control for the current user only (by SID, so names do not matter).
  $sid = Get-CurrentUserSid
  & icacls.exe $path /inheritance:r /grant:r "*${sid}:(OI)(CI)F" | Out-Null
  if ($LASTEXITCODE -ne 0) { Fail "icacls failed on $path" }
}

function Assert-OwnerOnlyAcl([string]$path, [switch]$RequireProtected) {
  # Every access rule (explicit or inherited) must be for the current user. The key directory itself must not
  # inherit from C:\tz (-RequireProtected); files and folders below it inherit from the key directory.
  $sid = Get-CurrentUserSid
  $acl = Get-Acl $path
  if ($RequireProtected -and -not $acl.AreAccessRulesProtected) { Fail "$path inherits permissions; run gen_keys.ps1 (it sets the ACL)" }
  foreach ($r in $acl.Access) {
    $rs = $r.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
    if ($rs -ne $sid) { Fail "$path grants access to $($r.IdentityReference); only the current user may have access" }
  }
}

function Assert-NotInGit([string]$path) {
  $git = Get-Command git.exe -ErrorAction SilentlyContinue
  if ($git) {
    & git.exe -C $path rev-parse --is-inside-work-tree 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { Fail "$path is inside a git work tree: keys must stay out of any repository" }
  }
}

function Read-HexFile([string]$path, [int]$nbytes) {
  if (-not (Test-Path $path)) { Fail "missing $path" }
  $t = ((Get-Content -Raw $path) -replace '\s', '').ToUpper()
  if ($t -notmatch "^[0-9A-F]{$(2 * $nbytes)}$") { Fail "$path must hold $nbytes bytes as hex" }
  return $t
}

function Get-KeyId([string]$hex) {
  # Short fingerprint for logs (SHA-256 over a label and the key); the key itself is never printed.
  $sha = [System.Security.Cryptography.SHA256]::Create()
  $b = [System.Text.Encoding]::ASCII.GetBytes("aegis-zynqmp-keyid:" + $hex)
  ($sha.ComputeHash($b) | Select-Object -First 6 | ForEach-Object { $_.ToString('x2') }) -join ''
}

function Stop-VitisServers {
  # As in ../README.txt: a "vitis -s" run can leave its server running; stop only those two processes.
  Get-CimInstance Win32_Process | Where-Object {
    ($_.Name -eq 'java.exe' -and $_.CommandLine -match 'RigelApp') -or
    ($_.Name -eq 'python.exe' -and $_.CommandLine -match 'slxcmd\.py.*server') } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}
