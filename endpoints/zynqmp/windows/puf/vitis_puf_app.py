import os
import vitis

# Vitis 2025.2 (vitis -s): a throw-away workspace with a platform from the XSA, xilskey + xilsecure in the A53
# domain, and the patched xilskey PUF registration example as an application. Called by build_puf_app.ps1, which
# sets the three environment variables. The workspace is inside C:\tz\aegis-keys\build and is deleted after the
# board run (the copied sources and the ELF hold the red key).
# Untested on the bench: the domain library call is set_lib() (verify in the Vitis 2025.2 Python API; if this
# Vitis has no set_lib, the script prints the domain's methods and stops before anything is built).
ws = os.environ["AEGIS_PUF_WS"]
xsa = os.environ["AEGIS_PUF_XSA"]
src = os.environ["AEGIS_PUF_SRC"]
files = ["xilskey_puf_registration_example.c", "xilskey_puf_registration.h"]

client = vitis.create_client()
client.set_workspace(path=ws)
plat = client.create_platform_component(
    name="puf_plat",
    hw_design=xsa,
    os="standalone",
    cpu="psu_cortexa53_0",
    domain_name="standalone_a53_0",
)
print("PLATFORM_CREATED")
dom = plat.get_domain(name="standalone_a53_0")
if not hasattr(dom, "set_lib"):
    print("NO_SET_LIB: domain methods are " + ", ".join(m for m in dir(dom) if not m.startswith("_")))
    vitis.dispose()
    raise SystemExit(3)
dom.set_lib(lib_name="xilsecure")
dom.set_lib(lib_name="xilskey")
print("LIBS_ADDED " + str(dom.get_libs()))
# xilskey's own eFUSE-access options stay at their defaults (all OFF); print them for the record.
for p in ("XILSKEY_access_secure_crit_efuse", "XILSKEY_access_user_efuse", "XILSKEY_access_key_manage_efuse",
          "XILSKEY_use_puf_hd_as_user_efuse"):
    try:
        print("XILSKEY_OPTION %s = %s" % (p, dom.get_config(option="lib", param=p, lib_name="xilskey")))
    except Exception as e:  # the option names are from xilskey.cmake 2025.2; reading them is informational
        print("XILSKEY_OPTION %s unreadable (%s)" % (p, e))
plat.build()
print("PLATFORM_BUILT")
xpfm = ws + "/puf_plat/export/puf_plat/puf_plat.xpfm"
app = client.create_app_component(name="puf_reg", platform=xpfm, domain="standalone_a53_0",
                                  template="empty_application")
app.import_files(from_loc=src, files=files, dest_dir_in_cmp="src")
print("APP_CREATED")
app.build()
print("APP_BUILT")
vitis.dispose()
