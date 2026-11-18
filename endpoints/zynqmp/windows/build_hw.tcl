set_param board.repoPaths {C:/tz/sk/StarterKit/board_files}
set outdir C:/tz/aegis/vivado
file delete -force $outdir
create_project aegis_zu4 $outdir -part xczu4eg-fbvb900-1-e
set_property board_part trenz.biz:te0807_4eg_1e_tebf0808:part0:4.0 [current_project]
puts "BOARD_PART=[get_property board_part [current_project]]"
create_bd_design zusys
set ps [create_bd_cell -type ip -vlnv xilinx.com:ip:zynq_ultra_ps_e zynq_ultra_ps_e_0]
# Trenz's board preset, applied as ONE dict like their own scripts do (parameters depend on each other).
# Only change vs. the 2022.2 preset: SD0 eMMC pin option "MIO 13 .. 16 21 22" no longer exists, so use "MIO 13 .. 22" with 4-bit data.
set fh [open C:/tz/sk/StarterKit/board_files/TE0807_4EG_1E/4.0/preset.xml r]; set xml [read $fh]; close $fh
set d [dict create]
foreach line [split $xml "\n"] {
  if {![regexp {<user_parameter\s+name="([^"]+)"\s+value="([^"]*)"} $line -> name value]} continue
  if {$name eq "CONFIG.PSU__SD0__PERIPHERAL__IO"} { set value "MIO 13 .. 22"; dict set d CONFIG.PSU__SD0__DATA_TRANSFER_MODE 4Bit }
  dict set d $name $value
}
puts "PRESET_PARAMS=[dict size $d]"
set_property -dict $d $ps
puts "SD0_IO=[get_property CONFIG.PSU__SD0__PERIPHERAL__IO $ps] SD0_MODE=[get_property CONFIG.PSU__SD0__DATA_TRANSFER_MODE $ps] POW=[get_property CONFIG.PSU__SD0__GRP_POW__IO $ps] DDR_BIN=[get_property CONFIG.PSU__DDRC__SPEED_BIN $ps] CL=[get_property CONFIG.PSU__DDRC__CL $ps]"
catch {set_property CONFIG.PSU__SD0__DATA_TRANSFER_MODE 4Bit $ps} e4; puts "SD0_4BIT_TRY=[get_property CONFIG.PSU__SD0__DATA_TRANSFER_MODE $ps] ($e4)"
connect_bd_net [get_bd_pins zynq_ultra_ps_e_0/pl_clk0] [get_bd_pins zynq_ultra_ps_e_0/maxihpm0_lpd_aclk]
if {[llength [get_bd_pins -quiet zynq_ultra_ps_e_0/dp_audio_ref_clk]]} { connect_bd_net [get_bd_pins zynq_ultra_ps_e_0/dp_audio_ref_clk] [get_bd_pins zynq_ultra_ps_e_0/dp_s_axis_audio_clk]; puts "AUDIO_CLK=dp_audio_ref_clk" } else { connect_bd_net [get_bd_pins zynq_ultra_ps_e_0/pl_clk1] [get_bd_pins zynq_ultra_ps_e_0/dp_s_axis_audio_clk]; puts "AUDIO_CLK=pl_clk1" }
validate_bd_design
save_bd_design
set wrapper [make_wrapper -files [get_files zusys.bd] -top]
add_files -norecurse $wrapper
update_compile_order -fileset sources_1
set_property top zusys_wrapper [current_fileset]
launch_runs impl_1 -to_step write_bitstream -jobs 4
wait_on_run impl_1
puts "IMPL_STATUS=[get_property STATUS [get_runs impl_1]]"
open_run impl_1
write_hw_platform -fixed -include_bit -force C:/tz/aegis/aegis_zu4eg.xsa
report_timing_summary -file C:/tz/aegis/timing_final.rpt
puts "XSA_DONE"


