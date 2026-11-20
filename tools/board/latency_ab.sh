#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# runtime-only experiment: IRQ affinity and CPU pinning for the Linux UIO latency path. Restores affinity on exit.
trap "echo 7 > /proc/irq/80/smp_affinity" EXIT INT TERM
run() { name=$1; shift; printf "%s " "$name"; "$@" 2>&1 | tail -1 | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); l=d[\"latency_us\"]; print(json.dumps({\"overrun\":d[\"overrun\"],\"mean\":l[\"mean\"],\"p999\":l[\"p999_le\"],\"max\":l[\"max\"]}))"; }
echo 7 > /proc/irq/80/smp_affinity
run A_default_1 pfdaq_lat -c 0 -p 500 -n 100000
run A_default_2 pfdaq_lat -c 0 -p 500 -n 100000
echo 4 > /proc/irq/80/smp_affinity
run B_cpu2_pinned_1 taskset -c 2 pfdaq_lat -c 0 -p 500 -n 100000
run B_cpu2_pinned_2 taskset -c 2 pfdaq_lat -c 0 -p 500 -n 100000
run C_cpu2_fifo80_1 taskset -c 2 pfdaq_lat -c 0 -p 500 -n 100000 -R 80
run C_cpu2_fifo80_2 taskset -c 2 pfdaq_lat -c 0 -p 500 -n 100000 -R 80
echo 2 > /proc/irq/80/smp_affinity
run D_cpu1_fifo80_1 taskset -c 1 pfdaq_lat -c 0 -p 500 -n 100000 -R 80
run D_cpu1_fifo80_2 taskset -c 1 pfdaq_lat -c 0 -p 500 -n 100000 -R 80
echo DONE
