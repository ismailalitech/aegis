# Step B2: run the PUF registration app over JTAG and turn its COM11 output into the bootgen files.
#   powershell -ExecutionPolicy Bypass -File run_puf_registration.ps1
#   powershell -ExecutionPolicy Bypass -File run_puf_registration.ps1 -PostCheck C:\tz\aegis-keys\reg-<time>
# The first form checks everything again, asks for the typed confirmation, captures COM11, runs
# run_puf_registration.tcl (JTAG RAM boot: PMU fw, FSBL, app), parses the log into reg-<time>\ and deletes the
# build directory (sources, workspace and ELF hold the red key).
# The second form runs after the power cycle (S1 twice, board back on its normal SD boot): it reads the eFUSE cache
# again, read-only, and compares it with the snapshot taken before the run.
param(
  [string]$Fsbl  = 'C:\tz\stage\linux-side\fsbl.elf',    # the FSBL/PMU fw of the current BOOT.BIN (TE0807 hooks)
  [string]$Pmufw = 'C:\tz\stage\linux-side\pmufw.elf',
  [int]$Secs = 60,
  [string]$PostCheck = '',
  [switch]$KeepBuild
)
. "$PSScriptRoot\puf_common.ps1"

function Get-EfuseLines([string]$text) {
  # IPDISABLE is left out: its VCU bit is only valid once the PL is configured (UG1087), so it reads 0 at power-on
  # and 0x100 later on this chip, without any eFUSE change.
  ($text -split "`r?`n") | Where-Object { $_ -match '^EFUSE ' -and $_ -notmatch 'IPDISABLE' } | ForEach-Object { $_.Trim() }
}

if ($PostCheck) {
  $before = Join-Path $PostCheck 'efuse_before.txt'
  if (-not (Test-Path $before)) { Fail "no $before" }
  $after = Join-Path $PostCheck 'efuse_after_powercycle.txt'
  & $XsdbBat "$PSScriptRoot\efuse_status.tcl" *> $after
  Get-Process hw_server -ErrorAction SilentlyContinue | Stop-Process -Force
  $a = @(Get-EfuseLines (Get-Content -Raw $after)); $b = @(Get-EfuseLines (Get-Content -Raw $before))
  if ($a.Count -lt 39 -or ($a | Where-Object { $_ -match 'ERROR' })) { Fail "eFUSE read incomplete, see $after (is the board on its plain SD boot?)" }
  $d = Compare-Object $b $a
  if ($d) { $d | Format-Table -AutoSize | Out-Host; Fail 'eFUSE cache DIFFERS from the snapshot before the run: stop and report' }
  "EFUSE_UNCHANGED: $($a.Count) registers identical before the run and after the power cycle"
  exit 0
}

# ---------- pre-flight (all of it again, even if the build just passed) ----------
Assert-OwnerOnlyAcl $KeyDir -RequireProtected
Assert-NotInGit $KeyDir
$red = Read-HexFile $RedKeyFile 32
$null = Read-HexFile $IvFile 12
$ok = Join-Path $BuildDir 'BUILD_OK.txt'
if (-not (Test-Path $ok)) { Fail 'no build\BUILD_OK.txt: run build_puf_app.ps1 first' }
$okText = Get-Content $ok
$elf = ($okText | Where-Object { $_ -like 'elf *' }) -replace '^elf ', ''
$sha = ($okText | Where-Object { $_ -like 'sha256 *' }) -replace '^sha256 ', ''
if (-not (Test-Path $elf)) { Fail "ELF $elf missing" }
if ((Get-FileHash $elf -Algorithm SHA256).Hash -ne $sha) { Fail 'ELF changed since build_puf_app.ps1' }
Invoke-Python @("$PSScriptRoot\check_puf_elf.py", $elf, '--red-key', $RedKeyFile, '--iv', $IvFile) 'check_puf_elf.py'
Invoke-Python @("$PSScriptRoot\prepare_puf_src.py", '--verify', (Join-Path $BuildDir 'ws\puf_reg\src'), '--red-key', $RedKeyFile, '--iv', $IvFile) 'header re-check'
foreach ($f in $Fsbl, $Pmufw) { if (-not (Test-Path $f)) { Fail "missing $f" } }
if ([System.IO.Ports.SerialPort]::GetPortNames() -notcontains $ComPort) { Fail "$ComPort not present (TE0790 plugged in?)" }
if (Get-Process hw_server, vivado -ErrorAction SilentlyContinue) { Fail 'hw_server or Vivado is running: close them (nothing else may use the JTAG)' }

"FSBL  $Fsbl  $((Get-FileHash $Fsbl -Algorithm SHA256).Hash)"
"PMUFW $Pmufw  $((Get-FileHash $Pmufw -Algorithm SHA256).Hash)"
"APP   $elf  $sha  (key id $(Get-KeyId $red))"
@'

CHECKLIST (README.md, "Checklist before the registration run"). Confirm each point:
  [ ] the board runs its normal plain SD boot (Linux on COM11 seen), 12 V on ONE input only
  [ ] green-dot TE0790 on J12; no terminal holds COM11; no Vivado / hw_server / other xsdb open
  [ ] no FTDI EEPROM tool is open, and none will be
  [ ] build_puf_app.ps1 ended with BUILD_OK; the lines above say SOURCE_OK/VERIFY_OK/ELF_CHECK_PASS
  [ ] switches: XSK_PUF_INFO_ON_UART TRUE, every other switch FALSE (printed above by --verify)
  [ ] you will power-cycle the board (S1 twice) after the run, then run this script with -PostCheck
'@ | Out-Host
$answer = Read-Host 'Type BOOT-HEADER-ONLY to start the JTAG run (anything else aborts)'
if ($answer -cne 'BOOT-HEADER-ONLY') { Fail 'aborted by the operator' }

# ---------- run ----------
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$reg = Join-Path $KeyDir "reg-$stamp"
New-Item -ItemType Directory $reg | Out-Null
$comLog = Join-Path $reg 'com11.log'
$xsdbLog = Join-Path $reg 'xsdb.log'
$cap = Start-Job -ArgumentList $ComPort, $comLog, $Secs -ScriptBlock {
  param($port, $f, $secs)
  $p = New-Object System.IO.Ports.SerialPort $port, 115200, 'None', 8, 'One'; $p.Open()
  $sb = New-Object System.Text.StringBuilder; $sw = [Diagnostics.Stopwatch]::StartNew()
  while ($sw.Elapsed.TotalSeconds -lt $secs) { [void]$sb.Append($p.ReadExisting()); Start-Sleep -Milliseconds 50 }
  $p.Close(); [IO.File]::WriteAllText($f, $sb.ToString(), [Text.Encoding]::ASCII)
}
Start-Sleep 2
try {
  & $XsdbBat "$PSScriptRoot\run_puf_registration.tcl" ($Fsbl -replace '\\', '/') ($Pmufw -replace '\\', '/') ($elf -replace '\\', '/') *> $xsdbLog
} finally {
  Wait-Job $cap | Out-Null; Receive-Job $cap; Remove-Job $cap
  Get-Process hw_server -ErrorAction SilentlyContinue | Stop-Process -Force
  if (-not $KeepBuild) {
    Remove-Item -Recurse -Force $BuildDir -ErrorAction SilentlyContinue
    if (Test-Path $BuildDir) { Write-Warning "could not delete $BuildDir (it holds the red key): delete it by hand" } else { 'BUILD_DIR_DELETED' }
  }
}
$x = Get-Content -Raw $xsdbLog
$i = $x.IndexOf('SNAPSHOT_BEFORE_BEGIN')
if ($i -lt 0) { Fail "no eFUSE snapshot in $xsdbLog (xsdb did not connect?)" }
$b = $x.Substring($i)
Set-Content -Path (Join-Path $reg 'efuse_before.txt') -Encoding ascii -Value (Get-EfuseLines $b)
if ($x -match 'PUF_EFUSE_NOT_BLANK') { Fail "PUF eFUSEs are not blank; nothing was run. See $xsdbLog" }
if ($x -notmatch 'XSDB_PUF_DONE' -or $x -match 'STEP_ERR') { Fail "xsdb sequence incomplete, see $xsdbLog" }

Invoke-Python @("$PSScriptRoot\parse_puf_log.py", '--log', $comLog, '--out-dir', $reg, '--red-key', $RedKeyFile, '--iv', $IvFile) 'parse_puf_log.py'
"REGISTRATION_OK $reg"
'Next: power-cycle the board (S1 twice), let it boot from the card, then:'
"  powershell -ExecutionPolicy Bypass -File $PSScriptRoot\run_puf_registration.ps1 -PostCheck $reg"
