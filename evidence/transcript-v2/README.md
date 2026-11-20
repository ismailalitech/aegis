# One transcript on the STM32 boards (20 November 2026)

The transcript of `docs/architecture.md` ("One transcript", threat T24) on both STM32H573 boards, with
`tests/board/transcript_swap_check.py` run on the gateway (aegis-fleet stopped) and the upgrade script's logs. Images:
SPE 67a452b1 (`...-freshkem`, before the transcript) and SPE 3183f74a (`...-freshkem-transcript`, built from this
branch; same MCUboot version 2.3.0 and signer). The non-secure image (prover 0.6.0, NSPE 1f4110fd) is not changed.
Home directories are written as `~` and LAN addresses as 192.168.x.x.

| File | What it shows |
|---|---|
| `ts-before-b2.txt` | Board 2 still on SPE 67a452b1, `live`: the gateway asks for the transcript and the image answers the first version's exchange. Refused before a credential is sent; the check stops with exit 3. This is what `"transcript": "v2"` does to an image from before it. |
| `flash-ts-b2-final.txt`, `flash-ts-b1.txt` | The upgrade from 67a452b1 to 3183f74a of board 2 (the last one, after the real swap below had put 67a452b1 back on it) and of board 1 (backup, policy allows the new SPE, write, reset, the gateway admits the board again). The gateway's entries had no `"transcript"` yet, so its sessions are the first version's (`[unbound]`). Both boards report `sstack=18880/26624` (deepest secure stack seen, of the stack's size). |
| `ts-live-b2.txt`, `ts-live-b1.txt` | SPE 3183f74a, `live`, exit 0 on both boards: L1 the bound exchange accepted, its heartbeat verifies and the endpoint reports the same session; L2 the same quote a second time refused, the session kept; L3 an older quote refused, the newer one accepted; L4 credentials that do not name this transcript refused by the partition (`ERR pq -149`), the session kept; L5 an entry without `"transcript"` still gets the first version's exchange; L6 a last bound cycle. |
| `ts-swapreset-b2.txt` | `quote` on 3183f74a, a reset, `swap`: S0 the reset ended the session; S1 the recorded quote cannot be continued (the quote was in RAM), refused before a credential; S2 the same challenge asked again gives another token (TF-M's ES256 signature is randomized), so continuing the recorded quote is refused; S3 a new cycle gets a session. |
| `ts-realswap-quote.txt`, `ts-realswap-b2.txt` | The acceptance test of the plan: `quote` on 3183f74a (admitted, token 71de85bb...), then the previous image 67a452b1, which derives the same device key, flashed into the secure slot and the board reset, then `swap`: S1, S2 and S3 refused. The gateway appraised one image and the other is refused the session, whether it continues the recorded quote, signs its own quote for the same challenge first (SPE 67a452b1 in S2's measurements) or starts a new cycle (it does not know the transcript). |

What this does not show: an image that holds the device key and signs T2 for a quote it saw, built to lie. On this
bench the STM32s are in the Open state with TF-M's public development signing keys, so anyone who can flash them can
build one; the transcript adds nothing against that (`docs/threat-model.md`, T24 and limitation 10).

Order on board 2: `ts-before-b2.txt` on 67a452b1; a first upgrade to 3183f74a (its log
is not kept here); `ts-live-b2.txt`, `ts-swapreset-b2.txt`, `ts-realswap-quote.txt`; 67a452b1 flashed and reset;
`ts-realswap-b2.txt`; `flash-ts-b2-final.txt`. Both boards run 3183f74a since.
