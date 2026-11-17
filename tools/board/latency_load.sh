#!/bin/sh
trap "kill \$P1 \$P2 \$P3 2>/dev/null; echo 7 > /proc/irq/80/smp_affinity" EXIT INT TERM
for c in 0 1 2; do taskset -c $c sh -c "while :; do :; done" & eval P$((c+1))=$!; done
echo 4 > /proc/irq/80/smp_affinity
for i in 1 2; do printf "LOAD_C_cpu2_fifo80_$i "; taskset -c 2 pfdaq_lat -c 0 -p 500 -n 100000 -R 80 2>&1 | tail -1 | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); l=d[\"latency_us\"]; print(json.dumps({\"overrun\":d[\"overrun\"],\"mean\":l[\"mean\"],\"p999\":l[\"p999_le\"],\"max\":l[\"max\"]}))"; done
echo DONE
