import vitis
client = vitis.create_client()
client.set_workspace(path="C:/tz/aegis/ws")
pmu = client.get_component(name="pmufw")
pmu.build()
print("PMUFW_BUILT")
vitis.dispose()
