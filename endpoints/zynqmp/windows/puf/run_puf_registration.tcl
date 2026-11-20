# SPDX-License-Identifier: Apache-2.0
# xsdb: JTAG run of the PUF registration app (boot-header mode). argv: fsbl pmufw app_elf
# Called by run_puf_registration.ps1, which has already checked the app ELF. Nothing is written to the card, the
# flash, the eFUSEs or the BBRAM: the only writes are the same volatile registers as ../jtag_boot.tcl
# (BOOT_MODE_USER, CSU_JTAG_SEC, the APU reset/vector registers) plus the downloads into RAM.
# Sequence = ../jtag_boot.tcl up to the FSBL (PMU firmware, FSBL initialises clocks/DDR and waits in JTAG mode),
# then the app instead of U-Boot/TF-A.
lassign $argv FSBL PMUFW APP
if {$APP eq "" || ![file exists $APP] || ![file exists $FSBL] || ![file exists $PMUFW]} { puts "ARGS_ERROR"; exit 1 }
proc step {msg body} { puts "STEP: $msg"; if {[catch {uplevel 1 $body} e]} { puts "STEP_ERR: $msg :: $e"; error $e } }
set ::EFUSE_STATUS_LIBRARY_ONLY 1
source [file join [file dirname [info script]] efuse_status.tcl]

# Started before power-on: the run must begin before the card's Linux 6.12 powers PM islands down (a JTAG
# "rst -system" does not bring them back; seen in phase A).
set t0 [clock seconds]
while {[catch {connect} e]} { if {[clock seconds] - $t0 > 300} { puts "NO_JTAG: $e"; exit 1 }; after 500 }
while {[llength [targets -filter {name =~ "*PSU*"}]] == 0} { if {[clock seconds] - $t0 > 300} { puts "NO_PSU"; exit 1 }; after 200 }
puts "PSU_SEEN after [expr {[clock seconds] - $t0}] s"
puts [targets]
targets -set -nocase -filter {name =~ "*PSU*"}
# Read the snapshot 3 s after the PSU appears (still before Linux: the card's FSBL and U-Boot take longer), twice,
# and require the two reads to match. IPDISABLE's VCU bit is only valid once the PL is configured (UG1087), so it
# is left out of the comparison and of the decision.
after 3000
proc puf_rows {} {
    set r {}
    foreach a {0xFFCC0008 0xFFCC1050 0xFFCC1054 0xFFCC1058 0xFFCC105C} { lappend r [mrd -force -value $a] }
    return $r
}
set rows1 [puf_rows]
puts "SNAPSHOT_BEFORE_BEGIN"
efuse_dump
boot_status
puts "SNAPSHOT_BEFORE_END"
after 500
set rows2 [puf_rows]
if {$rows1 ne $rows2} { puts "EFUSE_SNAPSHOT_UNSTABLE $rows1 / $rows2: stop"; disconnect; exit 1 }
lassign $rows1 sts chash pufmisc secctrl spkid
if {($sts & 0x20) == 0} { puts [format "EFUSE_CACHE_NOT_DONE sts=0x%08X: stop" $sts]; disconnect; exit 1 }
# Refuse unless the PUF eFUSEs hold nothing: CHASH = 0, AUX (PUF_MISC 23:0) = 0, REG_DIS (31), SYN_WRLK (30) and
# SYN_INVLD (29) clear. Bit 28 is PUF_MISC_RESERVED (xilskey_eps_zynqmp_hw.h): set on this chip from the factory,
# it does not affect registration (xilskey's XilSkey_Puf_Validate_Access_Rules ignores it), so it is logged only.
if {$chash != 0 || ($pufmisc & 0xE0FFFFFF) != 0} { puts [format "PUF_EFUSE_NOT_BLANK chash=0x%08X misc=0x%08X: stop" $chash $pufmisc]; disconnect; exit 1 }
if {($pufmisc & 0x10000000) != 0} { puts "NOTE: PUF_MISC_RESERVED (bit 28) set; not used by the registration" }

step "boot mode JTAG (volatile)" { mwr 0xff5e0200 0x0100 }
step "rst -system" { rst -system }
after 500
targets -set -nocase -filter {name =~ "*PSU*"}
step "PMU visible" { mwr 0xffca0038 0x1ff }
after 500
puts [targets]
step "pmufw" { targets -set -nocase -filter {name =~ "*MicroBlaze PMU*"}; catch {stop}; dow $PMUFW; con }
after 500
step "release A53#0" { targets -set -nocase -filter {name =~ "*APU*"}; mwr 0xffff0000 0x14000000; mask_write 0xFD1A0104 0x501 0x0 }
after 300
step "fsbl" { targets -set -nocase -filter {name =~ "*A53*#0"}; catch {stop}; rst -processor; dow $FSBL; con }
after 6000
step "stop fsbl" { targets -set -nocase -filter {name =~ "*A53*#0"}; stop }
step "puf registration app" { dow $APP }
puts "APP_START"
step "con" { con }
# The app prints its results within seconds and then loops forever (for (;;) at the end of main).
after 20000
step "stop app" { targets -set -nocase -filter {name =~ "*A53*#0"}; stop }
puts [targets]
disconnect
puts "XSDB_PUF_DONE"
