# SPDX-License-Identifier: Apache-2.0
import vitis

# Vitis 2025.2 builds only the FSBL boot domain for ZynqMP: add the PMU domain and the PMU firmware app.
ws = "C:/tz/aegis/ws"
client = vitis.create_client()
client.set_workspace(path=ws)
plat = client.get_component(name="aegis_zu4eg")
plat.add_domain(cpu="psu_pmu_0", os="standalone", name="pmufw_domain", display_name="pmufw_domain")
print("PMU_DOMAIN_ADDED")
plat.build()
print("PLATFORM_REBUILT")
pxpfm = ws + "/aegis_zu4eg/export/aegis_zu4eg/aegis_zu4eg.xpfm"
client.create_app_component(name="pmufw", platform=pxpfm, domain="pmufw_domain", template="zynqmp_pmufw")
print("PMUFW_APP_CREATED")
vitis.dispose()
