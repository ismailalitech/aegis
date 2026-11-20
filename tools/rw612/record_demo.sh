#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Record the FRDM-RW612 tamper demo as a screen recording: an xterm (X11, so ffmpeg can grab it on a Wayland desktop
# too) with three tmux panes (the gateway's aegis-fleet journal, the board console, the operator's steps), then a
# 4x-speed WebM and MP4 and a poster frame for the site.
#   GATEWAY=<address> tools/rw612/record_demo.sh <out dir>
#   GATEWAY=<address> STEPS=tfm TFM_BUILD=<dir with aegis_s/ and prover_ns/> tools/rw612/record_demo.sh <out dir>
# Needs xterm, tmux, xdotool, ffmpeg; the board on its MCU-Link; builds in ~/aegis-tools/nxp-build/prover and
# prover-tampered (endpoints/rw612/README.md). The board ends on the good image.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:?out dir}
T=${AEGIS_TOOLS:-$HOME/aegis-tools}
TTY=${RW612_TTY:-$(ls /dev/serial/by-id/usb-SEGGER_J-Link_*-if00 | head -1)}
G=root@${GATEWAY:?set GATEWAY}
PY=${PY:-python3}
mkdir -p "$OUT"
S=aegis-rw612-demo
tmux kill-session -t $S 2>/dev/null || true
tmux new-session -d -s $S -x 178 -y 46 \
	"ssh -o BatchMode=yes $G 'journalctl -u aegis-fleet -f -n 1 -o cat' | grep --line-buffered frdm-rw612 | sed -u -e 's/ADMITTED/\x1b[32mADMITTED\x1b[0m/' -e 's/QUARANTINED/\x1b[31mQUARANTINED\x1b[0m/'"
tmux set -t $S status off
tmux set -t $S pane-border-status top
tmux set -t $S pane-border-format ' #{pane_title} '
tmux set -t $S pane-border-style fg=colour240
tmux set -t $S pane-active-border-style fg=colour240
tmux select-pane -t $S:0.0 -T 'gateway (PolarFire SoC): aegis-fleet journal, one verdict per cycle'
tmux split-window -v -l 30 -t $S:0.0 "$PY $HERE/demo_console.py $TTY"
tmux select-pane -t $S:0.1 -T 'FRDM-RW612 console (USB serial)'
tmux split-window -h -l 52 -t $S:0.1 "sleep 999999"
tmux select-pane -t $S:0.2 -T 'operator'
xterm -geometry 178x46 -fa 'DejaVu Sans Mono' -fs 11 -bg '#0d1117' -fg '#d0d7de' -T $S -e tmux attach -t $S &
sleep 3
W=$(xdotool search --name "^$S\$" | head -1)
ffmpeg -loglevel error -y -f x11grab -draw_mouse 0 -window_id "$W" -framerate 10 -i "$DISPLAY" -c:v libx264 -preset veryfast -crf 18 \
	"$OUT/raw.mkv" &
FF=$!
sleep 2
if [ "${STEPS:-zephyr}" = tfm ]; then
	tmux respawn-pane -k -t $S:0.2 "sh $HERE/demo_steps_tfm.sh ${TFM_BUILD:?set TFM_BUILD}; sleep 3600"
else
	tmux respawn-pane -k -t $S:0.2 "sh $HERE/demo_steps.sh $T/nxp-build/prover $T/nxp-build/prover-tampered; sleep 3600"
fi
while ! tmux capture-pane -p -t $S:0.2 | grep -q "Same key all along"; do sleep 2; done
sleep 4
kill -INT $FF; wait $FF || true
tmux capture-pane -p -t $S:0.0 > "$OUT/journal-pane.txt"
tmux capture-pane -p -t $S:0.1 > "$OUT/console-pane.txt"
tmux kill-session -t $S
echo "recorded $OUT/raw.mkv"
