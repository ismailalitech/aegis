# SPDX-License-Identifier: Apache-2.0
# Aegis: add the aegis_pqc APB slave in FIC3 APB slot 14 (0x40000E00), next to pfdaq (slot 15).
# Sourced right after PFDAQ.tcl. HDL files are copied to script_support/hdl/aegis/ by build.sh.
foreach f [glob -nocomplain ./script_support/hdl/aegis/*.v] {
    import_files -convert_EDN_to_HDL 0 -library {work} -hdl_source $f
}
build_design_hierarchy

configure_core -component_name {FIC_3_0x4000_0xxx} -params {"APBSLOT14ENABLE:true"}
sd_update_instance -sd_name {FIC_3_ADDRESS_GENERATION} -instance_name {FIC_3_0x4000_0xxx_0}
sd_connect_pin_to_port -sd_name {FIC_3_ADDRESS_GENERATION} -pin_name {FIC_3_0x4000_0xxx_0:APBmslave14} -port_name {}
sd_rename_port -sd_name {FIC_3_ADDRESS_GENERATION} -current_port_name {APBmslave14} -new_port_name {FIC_3_0x4000_0Exx}
generate_component -component_name {FIC_3_ADDRESS_GENERATION} -recursive 0
sd_update_instance -sd_name {FIC_3_PERIPHERALS} -instance_name {FIC_3_ADDRESS_GENERATION_1}
sd_connect_pin_to_port -sd_name {FIC_3_PERIPHERALS} -pin_name {FIC_3_ADDRESS_GENERATION_1:FIC_3_0x4000_0Exx} -port_name {}
generate_component -component_name {FIC_3_PERIPHERALS} -recursive 0
sd_update_instance -sd_name {MPFS_DISCOVERY_KIT} -instance_name {FIC_3_PERIPHERALS_0}
build_design_hierarchy

create_hdl_core -file "${project_dir}/hdl/aegis_pqc.v" -module {aegis_pqc} -library {work} -package {}
hdl_core_add_bif -hdl_core_name {aegis_pqc} -bif_definition {APB:AMBA:AMBA2:slave} -bif_name {APB_TARGET} -signal_map {}
foreach {bs cs} {PADDR PADDR PENABLE PENABLE PWRITE PWRITE PRDATA PRDATA PWDATA PWDATA PREADY PREADY PSLVERR PSLVERR PSELx PSEL} {
    hdl_core_assign_bif_signal -hdl_core_name {aegis_pqc} -bif_name {APB_TARGET} -bif_signal_name $bs -core_signal_name $cs
}
sd_instantiate_hdl_core -sd_name {MPFS_DISCOVERY_KIT} -hdl_core_name {aegis_pqc} -instance_name {aegis_pqc_0}
sd_connect_pins -sd_name {MPFS_DISCOVERY_KIT} -pin_names {"aegis_pqc_0:APB_TARGET" "FIC_3_PERIPHERALS_0:FIC_3_0x4000_0Exx"}
sd_connect_pins -sd_name {MPFS_DISCOVERY_KIT} -pin_names {"CLOCKS_AND_RESETS_0:FIC_3_CLK" "aegis_pqc_0:PCLK"}
sd_connect_pins -sd_name {MPFS_DISCOVERY_KIT} -pin_names {"CLOCKS_AND_RESETS_0:RESETN_FIC_3_CLK" "aegis_pqc_0:PRESETN"}
generate_component -component_name {MPFS_DISCOVERY_KIT} -recursive 0
save_smartdesign -sd_name {MPFS_DISCOVERY_KIT}
generate_component -component_name {MPFS_DISCOVERY_KIT} -recursive 0
build_design_hierarchy
