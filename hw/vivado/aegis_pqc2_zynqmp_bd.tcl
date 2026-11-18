# SPDX-License-Identifier: Apache-2.0
#
# Add the Aegis accelerator (aegis_pqc2: Keccak sponge with DMA squeeze, and the NTT) to a Zynq UltraScale+ block
# design that already holds the PS as zynq_ultra_ps_e_0 (the TE0807 preset, PS only). Vivado 2025.2:
#   source hw/vivado/aegis_pqc2_zynqmp_bd.tcl     (with the block design open; then validate, wrapper, bitstream)
#
#   PS M_AXI_HPM0_LPD -> SmartConnect -> AXI APB Bridge -> aegis_pqc2 S_APB      registers at 0x8000_0000 (4 KiB)
#   aegis_pqc2 M_AXI (64-bit, write only) -> PS S_AXI_HP0_FPD (64-bit)        DDR low and high
#   one clock: pl_clk0 at 100 MHz (the PolarFire ran the same RTL at 50 MHz; lower it here if timing fails)
#
# The HP0 port is not cache-coherent: the driver gives the DMA buffer non-cached memory or invalidates the cache
# lines after a squeeze.

set ps [get_bd_cells zynq_ultra_ps_e_0]
set rtl_dir [file normalize [file join [file dirname [info script]] .. rtl]]
add_files -norecurse [glob $rtl_dir/aegis_pqc2_zynqmp.v $rtl_dir/aegis_pqc2.v $rtl_dir/aegis_sponge.v \
    $rtl_dir/aegis_keccak.v $rtl_dir/aegis_keccak_round.v $rtl_dir/aegis_ntt.v $rtl_dir/aegis_modmul.v \
    $rtl_dir/aegis_ram_sdp.v $rtl_dir/aegis_ntt_rom.v]
update_compile_order -fileset sources_1

set_property -dict [list \
    CONFIG.PSU__USE__M_AXI_GP2 {1} \
    CONFIG.PSU__USE__S_AXI_GP2 {1} \
    CONFIG.PSU__SAXIGP2__DATA_WIDTH {64} \
    CONFIG.PSU__FPGA_PL0_ENABLE {1} \
    CONFIG.PSU__CRL_APB__PL0_REF_CTRL__FREQMHZ {100} \
] $ps

set core   [create_bd_cell -type module -reference aegis_pqc2_zynqmp aegis_pqc2_0]
set bridge [create_bd_cell -type ip -vlnv xilinx.com:ip:axi_apb_bridge:3.0 axi_apb_bridge_0]
set_property CONFIG.C_APB_NUM_SLAVES {1} $bridge
set sc     [create_bd_cell -type ip -vlnv xilinx.com:ip:smartconnect:1.0 aegis_sc_0]
set_property -dict [list CONFIG.NUM_SI {1} CONFIG.NUM_MI {1}] $sc
set rst    [create_bd_cell -type ip -vlnv xilinx.com:ip:proc_sys_reset:5.0 aegis_rst_0]

set clk [get_bd_pins zynq_ultra_ps_e_0/pl_clk0]
connect_bd_net $clk [get_bd_pins aegis_pqc2_0/clk] [get_bd_pins axi_apb_bridge_0/s_axi_aclk] \
    [get_bd_pins aegis_sc_0/aclk] [get_bd_pins aegis_rst_0/slowest_sync_clk] \
    [get_bd_pins zynq_ultra_ps_e_0/saxihp0_fpd_aclk]
# maxihpm0_lpd_aclk is already on pl_clk0 in the PS-only design; connect it if it is not
if {[llength [get_bd_nets -of_objects [get_bd_pins zynq_ultra_ps_e_0/maxihpm0_lpd_aclk]]] == 0} {
    connect_bd_net $clk [get_bd_pins zynq_ultra_ps_e_0/maxihpm0_lpd_aclk]
}
connect_bd_net [get_bd_pins zynq_ultra_ps_e_0/pl_resetn0] [get_bd_pins aegis_rst_0/ext_reset_in]
connect_bd_net [get_bd_pins aegis_rst_0/peripheral_aresetn] [get_bd_pins aegis_pqc2_0/resetn] \
    [get_bd_pins axi_apb_bridge_0/s_axi_aresetn] [get_bd_pins aegis_sc_0/aresetn]

# the LPD master may already drive something in the PS-only design: then add a SmartConnect master port instead
connect_bd_intf_net [get_bd_intf_pins zynq_ultra_ps_e_0/M_AXI_HPM0_LPD] [get_bd_intf_pins aegis_sc_0/S00_AXI]
connect_bd_intf_net [get_bd_intf_pins aegis_sc_0/M00_AXI] [get_bd_intf_pins axi_apb_bridge_0/AXI4_LITE]
connect_bd_intf_net [get_bd_intf_pins axi_apb_bridge_0/APB_M] [get_bd_intf_pins aegis_pqc2_0/S_APB]
connect_bd_intf_net [get_bd_intf_pins aegis_pqc2_0/M_AXI] [get_bd_intf_pins zynq_ultra_ps_e_0/S_AXI_HP0_FPD]

# addresses: the registers for the PS, and only DDR for the DMA master
assign_bd_address -target_address_space /zynq_ultra_ps_e_0/Data -offset 0x80000000 -range 4K \
    [get_bd_addr_segs axi_apb_bridge_0/AXI4_LITE/Reg]
foreach seg {HP0_DDR_LO HP0_DDR_HIGH} {
    set s [get_bd_addr_segs -quiet zynq_ultra_ps_e_0/SAXIGP2/$seg]
    if {$s ne ""} { assign_bd_address -target_address_space /aegis_pqc2_0/M_AXI $s }
}
foreach s [get_bd_addr_segs -of_objects [get_bd_addr_spaces aegis_pqc2_0/M_AXI] -quiet] {
    if {![string match "*DDR*" [get_property NAME $s]]} { exclude_bd_addr_seg $s }
}
validate_bd_design
puts "aegis_pqc2 added: registers at 0x80000000, DMA to DDR through S_AXI_HP0_FPD"
