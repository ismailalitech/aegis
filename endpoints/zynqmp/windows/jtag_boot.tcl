# JTAG RAM boot (no flash, no eFUSE, no card writes). argv: fsbl pmufw uboot bl31
lassign $argv FSBL PMUFW UBOOT BL31
proc step {msg body} { puts "STEP: $msg"; if {[catch {uplevel 1 $body} e]} { puts "STEP_ERR: $msg :: $e" } }
connect
puts [targets]
targets -set -nocase -filter {name =~ "*PSU*"}
# volatile CRL_APB BOOT_MODE_USER: alternate boot mode = JTAG, so the BootROM does not run the card's FSBL (cleared by power-on reset)
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
puts [targets]
step "u-boot" { dow $UBOOT }
step "bl31" { dow $BL31 }
step "con" { con }
after 1000
puts [targets]
disconnect
puts "JTAG_DONE"
