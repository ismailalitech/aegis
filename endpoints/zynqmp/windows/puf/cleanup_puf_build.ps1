# SPDX-License-Identifier: Apache-2.0
# Delete everything that holds the red key except red_key.hex itself: the build directory (patched sources,
# Vitis workspace, ELF) and any left-over bootgen-* temporary directory. Run it whenever a build or a run stopped
# half-way.   powershell -ExecutionPolicy Bypass -File cleanup_puf_build.ps1
. "$PSScriptRoot\puf_common.ps1"
Stop-VitisServers
$targets = @($BuildDir) + @(Get-ChildItem -Path $KeyDir -Directory -Filter 'bootgen-*' -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
foreach ($t in $targets) {
  if (Test-Path $t) {
    Remove-Item -Recurse -Force $t
    if (Test-Path $t) { Fail "could not delete $t" }
    "DELETED $t"
  }
}
# Windows keeps no copy we create on purpose; check the usual suspects by hand: the Recycle Bin (Remove-Item does
# not use it) and any editor that opened the header copy.
"CLEANUP_OK"
