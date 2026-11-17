# Video shot list for the Aegis labs

One video per lab, each under four minutes, showing the real boards. The site's lab pages take a `youtube = "<id>"` front-matter
field; put the video ID there when it is uploaded.

## Before you record anything

- Charge or plug in the PC (it lost power once and the services did not restart by themselves; they do now, but check).
- Run `tools/regression.sh --board` first. If it does not end in `passed 12, failed 0`, fix that before filming.
- Terminal font size 18 or larger, dark theme, one window at a time, 1080p.
- **Do not show:** `bench.env`, the contents of `~/.ssh`, any password, your home folder path, or the router's address list. Use
  `clear` before each take and `cd` into the repository first so the prompt is short.
- Record the screen with OBS (or the Ubuntu screen recorder). Film the boards with a phone held still, or fixed on a stand.
- Say what you do in plain words and say the numbers aloud. No music is needed.

## Videos

| Lab | Title | Length | What to show |
|---|---|---|---|
| 47 | The bench | 2 min | The three boards, the cables and the PC. Name each board and say what it does. On screen: `tools/regression.sh --board` running and ending in `passed 12, failed 0` (speed it up in the middle). |
| 48 | The gateway proves itself | 3 min | `ssh` to the gateway, `systemctl status aegisd`. On the PC: `host/aegis_verify.py quote <gateway>` printing an accepted quote; run it twice and point at the different signature. Then show the refusal text from the recorded run (`measurement changed: design_digests_sha256`) and explain why that is correct. |
| 49 | The accelerator that is not faster | 3 min | `hw/tb/run_all.sh --fast` finishing; the board self-test (`pqc_selftest 500`) with zero mismatches; the ACVP run with the fabric hashing; then the timing table on screen, and the sentence "correct, but 8 to 12 percent slower". |
| 50 and 51 | Admit, tamper, quarantine | 4 min | **The main video.** Three windows: the gateway journal (`ssh <gateway> journalctl -fu aegis-fleet -o cat`), the demo script, and the STM32 board in view. Run `tools/demo.sh`. Show the STM32 admitted, the tampered image flashed, the **QUARANTINED** line, the good image back and **ADMITTED** with a new session. Keep the Arduino in the shot with its quarantine line scrolling next to the STM32's. |
| 51 | Attack it | 2 min | `tests/redteam/fuzz_host.py 2000`, then `fuzz_devices.py` against the STM32 and gateway. Show the final table. Mention the two defects it found. |
| 53 | Quarantine that really cuts | 3 min | In a terminal: `sudo tests/host/test_enforcement.sh`. Narrate the five stages as they print. Then edit `gateway/enforce/aegis.nft` to put back the line `ct state established,related accept`, run the test again and show the single failure (the open connection survives quarantine). Restore the fix and run it a third time. |
| 52 | The 5 ms mystery | 3 min | Run `pfdaq_lat -c 0 -p 500 -n 100000` on the board and read the maximum. Then pin the interrupt and the process and add `-R 80`; show the maximum drop. State the limits: two runs, one loaded run with 1.47 ms. |

## Photos worth taking at the same time

- The bench from above, with each board labelled.
- The PolarFire and the STM32 with their Ethernet cables and the ST-LINK USB cable.
- The Arduino with its USB cable.
- A screenshot of the Libero project canvas with the Aegis block.

## After

Upload the videos as unlisted, copy each ID into the matching lab's front matter (`youtube = "..."`), rebuild the site and open the
page with scripts off to check the "Play the video" link still opens YouTube.
