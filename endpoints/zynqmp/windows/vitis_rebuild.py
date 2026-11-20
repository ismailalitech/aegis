# SPDX-License-Identifier: Apache-2.0
import vitis
client = vitis.create_client()
client.set_workspace(path="C:/tz/aegis/ws")
plat = client.get_component(name="aegis_zu4eg")
plat.build()
print("PLATFORM_REBUILT")
vitis.dispose()
