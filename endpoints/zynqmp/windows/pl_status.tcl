# SPDX-License-Identifier: Apache-2.0
connect
puts [targets]
targets -set -nocase -filter {name =~ "*PSU*"}
foreach {n a} {CSU_PCAP_STATUS 0xFFCA3010 CSU_PCAP_CTRL 0xFFCA3008 CSU_STATUS 0xFFCA0000 PMU_GLOBAL_PWR_STATE 0xFFD80100 CSU_IDCODE 0xFFCA0040} {
  if {[catch {set r [mrd -force -value $a]} e]} { puts "$n $a ERROR: $e" } else { puts [format "%s %s = 0x%08X" $n $a $r] }
}
disconnect
