import vitis, os, shutil

ws = "C:/tz/aegis/ws"
if os.path.isdir(ws):
    shutil.rmtree(ws)
os.makedirs(ws)
client = vitis.create_client()
client.set_workspace(path=ws)
plat = client.create_platform_component(
    name="aegis_zu4eg",
    hw_design="C:/tz/aegis/aegis_zu4eg.xsa",
    os="standalone",
    cpu="psu_cortexa53_0",
    domain_name="standalone_a53_0",
)
print("PLATFORM_CREATED")
plat.build()
print("PLATFORM_BUILT")
vitis.dispose()
