# Add the Aegis hand-off hook (docs/zynqmp-key-design.md, phase B) to the Vitis 2025.2 zynqmp_fsbl sources.
# Run AFTER patch_fsbl_te.ps1, on the same source directory. A second run changes nothing.
#   -d  the FSBL source directory of the Vitis platform
#   -s  where aegis_fsbl_handoff.c/.h are (default: next to this script); aegis_zynqmp_handoff.h is taken from
#       there or from ..\handoff
param([string]$d = 'C:\tz\aegis\ws_pqc\aegis_zu4eg\zynqmp_fsbl', [string]$s = $PSScriptRoot)
$ErrorActionPreference = 'Stop'
function Must($cond, $msg) { if (-not $cond) { throw "PATCH FAILED: $msg" } }
function Occurrences($text, $what) { [int](($text.Length - $text.Replace($what, '').Length) / $what.Length) }
# Replace an anchor that must occur exactly once; skipped when $marker is already in the file.
function Edit($file, $marker, $old, $new) {
  $p = Join-Path $d $file; $t = [IO.File]::ReadAllText($p)
  if ($t.Contains($marker)) { return }
  $n = Occurrences $t $old
  Must ($n -eq 1) "$file : anchor found $n times, expected 1: $old"
  [IO.File]::WriteAllText($p, $t.Replace($old, $new))
}
function Has($file, $what) {
  $p = Join-Path $d $file
  Must (Test-Path $p) "$file not found in $d"
  Must ([IO.File]::ReadAllText($p).Contains($what)) "$file : expected '$what' (not the 2025.2 FSBL?)"
}

Must (Test-Path $d) "FSBL source directory not found: $d"

# 1. What the hook relies on in the 2025.2 FSBL, and the Trenz port underneath it
Has 'xfsbl_hooks.c' 'TE_XFsbl_HookPsuInit'              # patch_fsbl_te.ps1 has run
Has 'xfsbl_main.c' 'XFsblPs FsblInstance'
Has 'xfsbl_main.h' 'SecondaryBootDevice'
Has 'xfsbl_csu_dma.c' 'XCsuDma CsuDma'
Has 'xfsbl_image_header.h' 'XIH_BH_ENC_STS_OFFSET'
Has 'xfsbl_image_header.h' 'XIH_BH_TOTAL_PFW_LENGTH_OFFSET'
Has 'xfsbl_image_header.h' 'XIH_BH_IMAGE_ATTRB_AUTH_ONLY_MASK'
Has 'xfsbl_handoff.c' 'XFsbl_HookBeforeHandoff(EarlyHandoff)'

# 2. Our files (the CMake build compiles every .c in the directory)
$ho = @((Join-Path $s 'aegis_zynqmp_handoff.h'), (Join-Path $s '..\handoff\aegis_zynqmp_handoff.h')) |
      Where-Object { Test-Path $_ } | Select-Object -First 1
Must ($ho) "aegis_zynqmp_handoff.h not found in $s or $s\..\handoff"
foreach ($f in 'aegis_fsbl_handoff.c', 'aegis_fsbl_handoff.h') {
  Must (Test-Path (Join-Path $s $f)) "$f not found in $s"
  Copy-Item (Join-Path $s $f) $d -Force
}
Copy-Item $ho $d -Force

# 3. xfsbl_hooks.c: the hand-off page is filled in XFsbl_HookBeforeHandoff
Edit 'xfsbl_hooks.c' 'aegis_fsbl_handoff.h' '#include "psu_init.h"' "#include `"psu_init.h`"`r`n#include `"aegis_fsbl_handoff.h`" /* Aegis */"
$hk = Join-Path $d 'xfsbl_hooks.c'; $t = [IO.File]::ReadAllText($hk)
if (-not $t.Contains('AegisFsbl_BeforeHandoff')) {
  $a = $t.IndexOf('u32 XFsbl_HookBeforeHandoff(u32 EarlyHandoff)')
  Must ($a -gt 0) 'xfsbl_hooks.c : XFsbl_HookBeforeHandoff not found'
  $b = $t.IndexOf('return Status;', $a)
  $c = $t.IndexOf('u32 XFsbl_HookBeforeFallback(void)', $a)
  Must ($b -gt $a -and $c -gt $b) 'xfsbl_hooks.c : return of XFsbl_HookBeforeHandoff not found'
  $t = $t.Substring(0, $b) + "/* Aegis: seed and measurements for OP-TEE; cannot fail the boot */`r`n`tAegisFsbl_BeforeHandoff(EarlyHandoff);`r`n`r`n`t" + $t.Substring($b)
  [IO.File]::WriteAllText($hk, $t)
}

# 4. xfsbl_main.c: the boot image is measured when the last partition is loaded, while the FSBL still has the boot
#    device as it used it (XFsbl_Handoff switches the data cache off and restores the SD card-detect before the hook)
Edit 'xfsbl_main.c' 'aegis_fsbl_handoff.h' '#include "xfsbl_main.h"' "#include `"xfsbl_main.h`"`r`n#include `"aegis_fsbl_handoff.h`" /* Aegis */"
Edit 'xfsbl_main.c' 'AegisFsbl_Measure' 'XFsbl_Printf(DEBUG_INFO,"All Partitions Loaded \n\r");' "XFsbl_Printf(DEBUG_INFO,`"All Partitions Loaded \n\r`");`r`n`t`t`t`t`t`t/* Aegis: measure the boot image as stored */`r`n`t`t`t`t`t`tAegisFsbl_Measure();"

"AEGIS_PATCH_OK"
