# SPDX-License-Identifier: Apache-2.0
param([string]$name, [string]$fsbl, [string]$pmufw, [int]$secs = 140)
$ErrorActionPreference = 'Stop'
$out = "C:\tz\jtag\$name"
New-Item -ItemType Directory -Force $out | Out-Null
$ub = 'C:/tz/stage/linux-side/u-boot.elf'; $bl = 'C:/tz/stage/linux-side/bl31.elf'
# passive serial capture (sends nothing)
$cap = Start-Job -ArgumentList "$out\com11.txt", $secs -ScriptBlock {
  param($f, $secs)
  $p = New-Object System.IO.Ports.SerialPort 'COM11',115200,'None',8,'One'; $p.Open()
  $sb = New-Object System.Text.StringBuilder; $sw = [Diagnostics.Stopwatch]::StartNew()
  while ($sw.Elapsed.TotalSeconds -lt $secs) { [void]$sb.Append($p.ReadExisting()); Start-Sleep -Milliseconds 50 }
  $p.Close(); $sb.ToString() | Set-Content $f -Encoding utf8
}
Start-Sleep 2
& 'C:\AMDDesignTools\2025.2\Vitis\bin\xsdb.bat' C:\tz\jtag\jtag_boot.tcl $fsbl $pmufw $ub $bl *> "$out\xsdb.txt"
Wait-Job $cap | Out-Null; Receive-Job $cap; Remove-Job $cap
Get-Process hw_server -ErrorAction SilentlyContinue | Stop-Process -Force
"DONE $name"
