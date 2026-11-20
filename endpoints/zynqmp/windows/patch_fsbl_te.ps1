# SPDX-License-Identifier: Apache-2.0
# Port Trenz TE0807/TEBF0808 FSBL hooks (StarterKit 2022.2 build 6) onto the Vitis 2025.2 zynqmp_fsbl sources.
param([string]$d = 'C:\tz\aegis\ws\aegis_zu4eg\zynqmp_fsbl')
$ErrorActionPreference = 'Stop'
$s = 'C:\tz\sk\StarterKit\sw_lib\sw_apps\zynqmp_fsbl\src'
function Must($cond, $msg) { if (-not $cond) { throw "PATCH FAILED: $msg" } }
function Edit($file, $old, $new) {
  $p = Join-Path $d $file; $t = [IO.File]::ReadAllText($p)
  Must ($t.Contains($old)) "$file : anchor not found: $old"
  [IO.File]::WriteAllText($p, $t.Replace($old, $new))
}

# 1. Trenz files
$files = 'te_xfsbl_hooks.c','te_xfsbl_hooks.h','te_xfsbl_hooks_te0807.c','te_xfsbl_hooks_te0807.h',
         'te_iic_platform.c','te_iic_platform.h','te_iic_define_te0807.h','te_si534x.c','te_si534x.h',
         'te_Si5345-Registers.h','te_uart.c','te_uart.h'
foreach ($f in $files) { Copy-Item (Join-Path $s $f) $d -Force }

# 2. SDT drivers: LookupConfig takes the base address, not a device ID
Edit 'te_iic_define_te0807.h' '#define XIICPS_DEVICE_ID	XPAR_XIICPS_0_DEVICE_ID' '#define XIICPS_DEVICE_ID	XPAR_XIICPS_0_BASEADDR /* 2025.2 SDT: base address */'
Edit 'te_iic_define_te0807.h' '#define UART_DEVICE_ID			XPAR_XUARTPS_0_DEVICE_ID' '#define UART_DEVICE_ID			XPAR_XUARTPS_0_BASEADDR /* 2025.2 SDT: base address */'

# 3. psu_init.c: export the tail of psu_init() (init_serdes/init_peripheral are static)
$tail = @'

/* Aegis/TE port: tail of psu_init() exported so the TE hook can run it after the Si5345 is configured. */
int te_psu_init_tail(void)
{
	int status = 1;
	status &=  init_serdes();
	init_peripheral();
	status &=  psu_peripherals_powerdwn_data();
	status &=    psu_afi_config();
	psu_ddr_qos_init_data();
	return status;
}
'@
$pi = Join-Path $d 'psu_init.c'; $t = [IO.File]::ReadAllText($pi)
if (-not $t.Contains('te_psu_init_tail')) { [IO.File]::WriteAllText($pi, $t + $tail) }

# 4. TE hook: replace Trenz's inlined 2022.2 init_serdes/init_peripheral/... with the exported 2025.2 tail
$h = Join-Path $d 'te_xfsbl_hooks_te0807.c'; $t = [IO.File]::ReadAllText($h)
$a = $t.IndexOf('//note: SDK with default FSBL will not generate init_serdes()')
$b = $t.IndexOf('// code from psu_init():', $a)
Must ($a -gt 0 -and $b -gt $a) 'te_xfsbl_hooks_te0807.c serdes block'
$t = $t.Substring(0, $a) + "psu_status &= te_psu_init_tail(); /* 2025.2: init_serdes, init_peripheral, powerdwn, afi, qos as generated */`r`n  " + $t.Substring($b)
# fix Trenz's status bug (failure returned as 0 == XFSBL_SUCCESS) and the uninitialised Status
$t = $t.Replace("u32 TE_XFsbl_TPSU_MODIFIED(void)`r`n{", "int te_psu_init_tail(void);`r`n u32 TE_XFsbl_TPSU_MODIFIED(void)`r`n{")
$t = $t.Replace("u32 TE_XFsbl_TPSU_MODIFIED(void)`n{", "int te_psu_init_tail(void);`n u32 TE_XFsbl_TPSU_MODIFIED(void)`n{")
Must ($t.Contains('int te_psu_init_tail(void);')) 'prototype insert'
$protos = "/* 2025.2 psu_init.h no longer declares these */`r`nunsigned long psu_mio_init_data(void);`r`nunsigned long psu_peripherals_pre_init_data(void);`r`nunsigned long psu_pll_init_data(void);`r`nunsigned long psu_clock_init_data(void);`r`nunsigned long psu_ddr_init_data(void);`r`nunsigned long psu_ddr_phybringup_data(void);`r`nunsigned long psu_peripherals_init_data(void);`r`n"
$t = $t.Replace("int te_psu_init_tail(void);", $protos + "int te_psu_init_tail(void);")
$n = ([regex]::Matches($t, 'Status= psu_status;')).Count
Must ($n -eq 2) "expected 2 'Status= psu_status;' got $n"
$t = $t.Replace('Status= psu_status;', 'Status = XFSBL_PSU_INIT_FAILED; /* port fix: was psu_status (0 == success) */')
$t = [regex]::Replace($t, '(u32 TE_XFsbl_TPSU_MODIFIED\(void\)\s*\{[^{]*?)u32 Status;', '${1}u32 Status = XFSBL_SUCCESS;')
[IO.File]::WriteAllText($h, $t)

# 5. Xilinx files: the same edits Trenz marks "TE Mod"
Edit 'xfsbl_hooks.h' '#include "xil_types.h"' "#include `"xil_types.h`"`r`n/* TE Mod: */`r`n#include `"te_xfsbl_hooks.h`"`r`n/* TE Mod: finished */"
Edit 'xfsbl_board.h' '#include "xfsbl_hw.h"' "#include `"xfsbl_hw.h`"`r`n/* TE Mod: */`r`n#include `"te_xfsbl_hooks.h`"`r`n/* TE Mod: finished */"
$hk = Join-Path $d 'xfsbl_hooks.c'; $t = [IO.File]::ReadAllText($hk)
$a = $t.IndexOf('/* Add the code here */', $t.IndexOf('u32 XFsbl_HookPsuInit(void)'))
$b = $t.IndexOf('if (XFSBL_SUCCESS != Status)', $a)
Must ($a -gt 0 -and $b -gt $a) 'xfsbl_hooks.c psu block'
$t = $t.Substring(0, $a) + "/* TE Mod: Si5345 PLL on the TE0807 is set up between peripherals init and SERDES init */`r`n#ifndef XFSBL_ENABLE_DDR_SR`r`n`t/* Remove DDR IOs from retention (2025.2 stock step) */`r`n`tXFsbl_IoRetentionClear();`r`n#endif`r`n`tStatus = TE_XFsbl_HookPsuInit();`r`n/* TE Mod: finished */`r`n`r`n`t" + $t.Substring($b)
[IO.File]::WriteAllText($hk, $t)
$bc = Join-Path $d 'xfsbl_board.c'; $t = [IO.File]::ReadAllText($bc)
$a = $t.IndexOf('u32 XFsbl_BoardInit(void)'); $b = $t.IndexOf('u32 Status;', $a)
Must ($a -gt 0 -and $b -gt $a) 'xfsbl_board.c BoardInit'
$t = $t.Substring(0, $b) + "u32 Status;`r`n/* TE Mod: */`r`n`tStatus = TE_XFsbl_BoardInit();`r`n`tif (Status != XFSBL_SUCCESS) {`r`n`t`treturn Status;`r`n`t}`r`n/* TE Mod: finished */" + $t.Substring($b + 'u32 Status;'.Length)
[IO.File]::WriteAllText($bc, $t)
Edit 'xfsbl_main.c' '"Zynq MP First Stage Boot Loader' '"Zynq MP First Stage Boot Loader (TE0807 hooks, Aegis 2025.2)'
"PATCH_OK"
