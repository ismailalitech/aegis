# SPDX-License-Identifier: Apache-2.0
# Read-only snapshot over JTAG: eFUSE cache registers and boot status. Reads only (mrd); writes nothing.
#   xsdb efuse_status.tcl            (board on, booted from the card in a NON-secure boot, so JTAG is enabled)
# Used before the registration run and again after a power cycle: the two outputs must be identical in the
# EFUSE lines. The cache is reloaded from the fuses at power-on, so the post-power-cycle read shows the fuses.
# Register map: xilskey 2025.2 xilskey_eps_zynqmp_hw.h (eFUSE at 0xFFCC0000), xfsbl_hw.h, pmu_global.h.
proc efuse_dump {} {
  # name address
  set regs {
    WR_LOCK        0xFFCC0000
    STS            0xFFCC0008
    DNA_0          0xFFCC100C  DNA_1 0xFFCC1010  DNA_2 0xFFCC1014
    IPDISABLE      0xFFCC1018
    USER_0 0xFFCC1020 USER_1 0xFFCC1024 USER_2 0xFFCC1028 USER_3 0xFFCC102C
    USER_4 0xFFCC1030 USER_5 0xFFCC1034 USER_6 0xFFCC1038 USER_7 0xFFCC103C
    MISC_USER_CTRL 0xFFCC1040
    PBR_BOOT_ERR   0xFFCC1044
    RESERVED       0xFFCC104C
    PUF_CHASH      0xFFCC1050
    PUF_MISC       0xFFCC1054
    SEC_CTRL       0xFFCC1058
    SPK_ID         0xFFCC105C
  }
  for {set a 0xFFCC10A0} {$a <= 0xFFCC10FC} {incr a 4} { lappend regs [format "PPK_%03X" [expr {$a & 0xFFF}]] [format 0x%08X $a] }
  foreach {n a} $regs {
    if {[catch {set v [mrd -force -value $a]} e]} { puts "EFUSE $n $a ERROR: $e" } else { puts [format "EFUSE %-14s %s = 0x%08X" $n $a $v] }
  }
}
proc boot_status {} {
  foreach {n a} {
    CSU_MULTI_BOOT        0xFFCA0010
    CSU_BR_ERROR          0xFFD80528
    FSBL_ERROR_STATUS     0xFFD80060
    GLOB_GEN_STORAGE5     0xFFD80044
    CRL_BOOT_MODE_USER    0xFF5E0200
  } {
    if {[catch {set v [mrd -force -value $a]} e]} { puts "BOOT $n $a ERROR: $e" } else { puts [format "BOOT  %-20s %s = 0x%08X" $n $a $v] }
  }
}
# Run as a script: snapshot. Sourced with ::EFUSE_STATUS_LIBRARY_ONLY set: only define the two procs.
if {![info exists ::EFUSE_STATUS_LIBRARY_ONLY]} {
  connect
  puts [targets]
  targets -set -nocase -filter {name =~ "*PSU*"}
  efuse_dump
  boot_status
  disconnect
  puts "EFUSE_STATUS_DONE"
}
