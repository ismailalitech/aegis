# Synthesis only of one RTL top on the board's device (MPFS095T-1FCSG325E), for resource and timing estimates.
# Usage: libero SCRIPT:synth_core.tcl "SCRIPT_ARGS:<project dir> <top> <rtl dir> <clock MHz>"
set proj [lindex $argv 0]
set top  [lindex $argv 1]
set rtl  [lindex $argv 2]
set mhz  [lindex $argv 3]
new_project -location $proj -name SYNTH -project_description {} -block_mode 0 -standalone_peripheral_initialization 0 \
    -instantiate_in_smartdesign 1 -ondemand_build_dh 1 -use_relative_path 0 -linked_files_root_dir_env {} \
    -hdl {VERILOG} -family {PolarFireSoC} -die {MPFS095T} -package {FCSG325} -speed {-1} -die_voltage {1.0} \
    -part_range {EXT} -adv_options {IO_DEFT_STD:LVCMOS 1.8V} -adv_options {RESTRICTPROBEPINS:1} \
    -adv_options {RESTRICTSPIPINS:0} -adv_options {SYSTEM_CONTROLLER_SUSPEND_MODE:0} -adv_options {TEMPR:EXT} \
    -adv_options {VCCI_1.2_VOLTR:EXT} -adv_options {VCCI_1.5_VOLTR:EXT} -adv_options {VCCI_1.8_VOLTR:EXT} \
    -adv_options {VCCI_2.5_VOLTR:EXT} -adv_options {VCCI_3.3_VOLTR:EXT} -adv_options {VOLTR:EXT}
foreach f [glob -directory $rtl *.v] { import_files -hdl_source $f }
build_design_hierarchy
set_root -module "${top}::work"
set sdc [file join $proj synth_clock.sdc]
set fh [open $sdc w]
puts $fh "create_clock -name PCLK -period [expr {1000.0 / $mhz}] \[get_ports PCLK\]"
close $fh
import_files -sdc $sdc
organize_tool_files -tool {SYNTHESIZE} -file "$proj/constraint/synth_clock.sdc" -module "${top}::work" -input_type {constraint}
run_tool -name {SYNTHESIZE}
save_project
