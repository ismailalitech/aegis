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

connect
puts [targets]
targets -set -nocase -filter {name =~ "*PSU*"}
puts "SNAPSHOT_BEFORE_BEGIN"
efuse_dump
boot_status
puts "SNAPSHOT_BEFORE_END"
# refuse if the PUF eFUSEs are not blank (registration would be refused by xilskey anyway) or RSA_EN is set
set chash [mrd -force -value 0xFFCC1050]
set pufmisc [mrd -force -value 0xFFCC1054]
if {$chash != 0 || ($pufmisc & 0xF0FFFFFF) != 0} { puts [format "PUF_EFUSE_NOT_BLANK chash=0x%08X misc=0x%08X: stop" $chash $pufmisc]; disconnect; exit 1 }

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
