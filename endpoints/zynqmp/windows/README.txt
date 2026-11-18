Aegis Zynq endpoint: Windows build of the hardware design, FSBL and PMU firmware (Vivado/Vitis 2025.2)
=====================================================================================================

Board: Trenz TE0807-02/03-4BE21-A(K) (XCZU4EG-1E, 4 GB DDR4) on a TEBF0808 carrier.
Tools: AMD Vivado 2025.2 and Vitis 2025.2 (Unified IDE, SDT flow), installed in C:\AMDDesignTools\2025.2.
Paths are fixed to C:\tz (short path: Trenz warns about the 260-character limit on Windows).

Trenz download expected (public, trenz-electronic.de/trenzdownloads):
  Modules_and_Module_Carriers/5.2x7.6/TE0807/Reference_Design/2022.2/StarterKit/
    TE0807-StarterKit-vivado_2022.2-build_6_20230817092640.zip
    sha256 d7738d50a1823b48517ee010a0ad53287ff3ef83bb5895d84ab299732661ba76
  extracted to C:\tz\sk  (so C:\tz\sk\StarterKit\board_files and ...\sw_lib\sw_apps\zynqmp_fsbl\src exist).
  Used: board files TE0807_4EG_1E\4.0 (board part trenz.biz:te0807_4eg_1e_tebf0808:part0:4.0) and the
  FSBL hook sources. Trenz's own PL design is NOT used (it needs their custom IP); the PL is empty.

Order
-----
1. Vivado (about 15 min):
     cd C:\tz\aegis
     C:\AMDDesignTools\2025.2\Vivado\bin\vivado.bat -mode batch -source build_hw.tcl
   -> C:\tz\aegis\aegis_zu4eg.xsa (bitstream included), vivado\aegis_zu4.runs\impl_1\zusys_wrapper.bit
   What it does: Zynq MPSoC with Trenz's preset.xml applied as ONE parameter dict (the board-preset
   automation rejects it in 2025.2), SD0 eMMC pins "MIO 13 .. 22" + 4Bit (the 2022.2 option
   "MIO 13 .. 16 21 22" no longer exists), maxihpm0_lpd_aclk <- pl_clk0, dp_s_axis_audio_clk <-
   dp_audio_ref_clk (40 ns min period). Expected: 0 critical warnings, timing met.

2. Vitis platform + stock FSBL:   C:\AMDDesignTools\2025.2\Vitis\bin\vitis.bat -s vitis_plat.py
3. PMU domain + PMU firmware app: vitis.bat -s vitis_apps.py   then   vitis.bat -s vitis_pmu.py
   -> ws\pmufw\build\pmufw.elf
4. Keep the stock FSBL (optional): copy ws\aegis_zu4eg\export\aegis_zu4eg\sw\boot\fsbl.elf, and the
   source files of ws\aegis_zu4eg\zynqmp_fsbl (not build\) to a backup folder.
5. Port Trenz's FSBL hooks:  powershell -File patch_fsbl_te.ps1
   (run it on the pristine 2025.2 sources; it stops with "PATCH FAILED" if an anchor is missing)
6. Rebuild the FSBL:          vitis.bat -s vitis_rebuild.py
   -> ws\aegis_zu4eg\export\aegis_zu4eg\sw\boot\fsbl.elf, banner "(TE0807 hooks, Aegis 2025.2)"

Note: after each "vitis -s" run, Vitis 2025.2 may leave its server running (java ... RigelApp and
python ... slxcmd.py server); the next run then fails with "workspace is already in use". Stop those two
processes (only those) before the next run.

What patch_fsbl_te.ps1 changes
--------------------------------------------------------------------
- adds Trenz's te_xfsbl_hooks*, te_xfsbl_hooks_te0807*, te_iic_platform*, te_iic_define_te0807.h,
  te_si534x*, te_Si5345-Registers.h (SI5345_B), te_uart*;
- Trenz's "TE Mod" edits: xfsbl_hooks.h and xfsbl_board.h include te_xfsbl_hooks.h; XFsbl_HookPsuInit
  calls TE_XFsbl_HookPsuInit (after 2025.2's DDR IO-retention clear); XFsbl_BoardInit calls
  TE_XFsbl_BoardInit first; banner text in xfsbl_main.c;
- 2025.2 changes: LookupConfig by base address (XPAR_XIICPS_0_BASEADDR, XPAR_XUARTPS_0_BASEADDR);
  psu_init.c gets an exported te_psu_init_tail() = the generated tail of psu_init() (init_serdes,
  init_peripheral, powerdwn, afi, qos), called by the TE hook after the Si5345 setup, instead of
  Trenz's inlined 2022.2 copy; prototypes for the psu_*_data() functions;
- bug fix: a failing psu_init step returned 0 (= XFSBL_SUCCESS); now XFSBL_PSU_INIT_FAILED.
psu_init.c itself is generated from the XSA and is not included; the patch appends the tail function.

JTAG RAM boot test (nothing written to the card, flash or fuses)
-----------------------------------------------------------------
  powershell -File run_test.ps1 -name t1 -fsbl <fsbl.elf> -pmufw <pmufw.elf>
  (expects u-boot.elf and bl31.elf in C:\tz\stage\linux-side; captures COM11 at 115200 for 140 s,
  sends nothing; COM port name is in the script)
  jtag_boot.tcl first writes BOOT_MODE_USER (0xFF5E0200) = 0x100: a volatile register (alternate boot
  mode = JTAG) cleared by power-on reset, so the BootROM does not run the card's FSBL. After the test
  a warm reboot does NOT boot from the card; power-cycle (S1 twice).
  pl_status.tcl: read-only check of CSU PCAP_STATUS / PMU power state.

Results (18 November 2026): JTAG RAM boot and SD boot both reach Debian; PCAP_STATUS 0xA0002FDE
(PL_INIT, PL_DONE set) after SD boot.

Rules: no FT_Prog or other FTDI EEPROM tool on the TE0790; no eFUSE/BBRAM; no QSPI programming.

In the repository
-----------------
Trenz's FSBL hook sources (te_*) are not copied here: they come from Trenz's public download above, and
patch_fsbl_te.ps1 copies them into the Vitis workspace and applies every change. The Linux side (TF-A, U-Boot,
bootgen, the SD card) is in endpoints/zynqmp/README.md.
