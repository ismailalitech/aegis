# Aegis accelerator v2: aegis_pqc2 (through the aegis_pqc2_fic0 port wrapper) in FIC3 APB slot 14 (0x40000E00), as
# aegis_pqc was, plus its AXI4 write master on a second master port of the FIC0 interconnect DMA_INITIATOR, whose
# slave port goes to the MSS (FIC_0_AXI4_TARGET), i.e. into DDR. The core runs on the FIC3 clock (50 MHz); the
# interconnect crosses to the FIC0 clock (125 MHz) on that port (MASTER1_CLOCK_DOMAIN_CROSSING).
# Sourced right after PFDAQ.tcl. Build: AEGIS_OVERLAY=AEGIS_PQC2.tcl hw/libero/build.sh <version>.
foreach f [glob -nocomplain ./script_support/hdl/aegis/*.v] {
    import_files -convert_EDN_to_HDL 0 -library {work} -hdl_source $f
}
build_design_hierarchy

# ---- APB slot 14, exactly as for aegis_pqc
configure_core -component_name {FIC_3_0x4000_0xxx} -params {"APBSLOT14ENABLE:true"}
sd_update_instance -sd_name {FIC_3_ADDRESS_GENERATION} -instance_name {FIC_3_0x4000_0xxx_0}
sd_connect_pin_to_port -sd_name {FIC_3_ADDRESS_GENERATION} -pin_name {FIC_3_0x4000_0xxx_0:APBmslave14} -port_name {}
sd_rename_port -sd_name {FIC_3_ADDRESS_GENERATION} -current_port_name {APBmslave14} -new_port_name {FIC_3_0x4000_0Exx}
generate_component -component_name {FIC_3_ADDRESS_GENERATION} -recursive 0
sd_update_instance -sd_name {FIC_3_PERIPHERALS} -instance_name {FIC_3_ADDRESS_GENERATION_1}
sd_connect_pin_to_port -sd_name {FIC_3_PERIPHERALS} -pin_name {FIC_3_ADDRESS_GENERATION_1:FIC_3_0x4000_0Exx} -port_name {}
generate_component -component_name {FIC_3_PERIPHERALS} -recursive 0
sd_update_instance -sd_name {MPFS_DISCOVERY_KIT} -instance_name {FIC_3_PERIPHERALS_0}

# ---- FIC0 interconnect: a second master port, write and read access to its one slave (the MSS), clock crossing
configure_core -component_name {DMA_INITIATOR} -params {"NUM_MASTERS:2" "NUM_MASTERS_WIDTH:1" "MASTER1_TYPE:0" \
    "MASTER1_DATA_WIDTH:64" "MASTER1_CLOCK_DOMAIN_CROSSING:true" "MASTER1_WRITE_SLAVE0:true" \
    "MASTER1_READ_SLAVE0:true" "MASTER1_CHAN_RS:true"}
sd_update_instance -sd_name {FIC_0_PERIPHERALS} -instance_name {DMA_INITIATOR}
sd_connect_pin_to_port -sd_name {FIC_0_PERIPHERALS} -pin_name {DMA_INITIATOR:AXI4mmaster1} -port_name {}
sd_rename_port -sd_name {FIC_0_PERIPHERALS} -current_port_name {AXI4mmaster1} -new_port_name {AEGIS_DMA}
sd_connect_pin_to_port -sd_name {FIC_0_PERIPHERALS} -pin_name {DMA_INITIATOR:M_CLK1} -port_name {}
sd_rename_port -sd_name {FIC_0_PERIPHERALS} -current_port_name {M_CLK1} -new_port_name {AEGIS_DMA_CLK}
generate_component -component_name {FIC_0_PERIPHERALS} -recursive 0
sd_update_instance -sd_name {MPFS_DISCOVERY_KIT} -instance_name {FIC_0_PERIPHERALS_0}
build_design_hierarchy

# ---- the core
create_hdl_core -file "${project_dir}/hdl/aegis_pqc2_fic0.v" -module {aegis_pqc2_fic0} -library {work} -package {}
hdl_core_add_bif -hdl_core_name {aegis_pqc2_fic0} -bif_definition {APB:AMBA:AMBA2:slave} -bif_name {APB_TARGET} -signal_map {}
foreach {bs cs} {PADDR PADDR PENABLE PENABLE PWRITE PWRITE PRDATA PRDATA PWDATA PWDATA PREADY PREADY PSLVERR PSLVERR PSELx PSEL} {
    hdl_core_assign_bif_signal -hdl_core_name {aegis_pqc2_fic0} -bif_name {APB_TARGET} -bif_signal_name $bs -core_signal_name $cs
}
hdl_core_add_bif -hdl_core_name {aegis_pqc2_fic0} -bif_definition {AXI4:AMBA:AMBA4:master} -bif_name {AXI4_INITIATOR} -signal_map {}
foreach s {AWID AWADDR AWLEN AWSIZE AWBURST AWLOCK AWCACHE AWPROT AWQOS AWREGION AWUSER AWVALID AWREADY
           WDATA WSTRB WLAST WUSER WVALID WREADY BID BRESP BUSER BVALID BREADY
           ARID ARADDR ARLEN ARSIZE ARBURST ARLOCK ARCACHE ARPROT ARQOS ARREGION ARUSER ARVALID ARREADY
           RID RDATA RRESP RLAST RUSER RVALID RREADY} {
    hdl_core_assign_bif_signal -hdl_core_name {aegis_pqc2_fic0} -bif_name {AXI4_INITIATOR} -bif_signal_name $s -core_signal_name $s
}
sd_instantiate_hdl_core -sd_name {MPFS_DISCOVERY_KIT} -hdl_core_name {aegis_pqc2_fic0} -instance_name {aegis_pqc2_0}
sd_connect_pins -sd_name {MPFS_DISCOVERY_KIT} -pin_names {"aegis_pqc2_0:APB_TARGET" "FIC_3_PERIPHERALS_0:FIC_3_0x4000_0Exx"}
sd_connect_pins -sd_name {MPFS_DISCOVERY_KIT} -pin_names {"aegis_pqc2_0:AXI4_INITIATOR" "FIC_0_PERIPHERALS_0:AEGIS_DMA"}
sd_connect_pins -sd_name {MPFS_DISCOVERY_KIT} -pin_names {"CLOCKS_AND_RESETS_0:FIC_3_CLK" "aegis_pqc2_0:PCLK" "FIC_0_PERIPHERALS_0:AEGIS_DMA_CLK"}
sd_connect_pins -sd_name {MPFS_DISCOVERY_KIT} -pin_names {"CLOCKS_AND_RESETS_0:RESETN_FIC_3_CLK" "aegis_pqc2_0:PRESETN"}
generate_component -component_name {MPFS_DISCOVERY_KIT} -recursive 0
save_smartdesign -sd_name {MPFS_DISCOVERY_KIT}
generate_component -component_name {MPFS_DISCOVERY_KIT} -recursive 0
build_design_hierarchy
