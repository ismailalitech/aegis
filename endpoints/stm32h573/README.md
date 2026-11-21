# STM32H573I-DK endpoint

TF-M v2.3.0 with the Aegis partition (`tfm-aegis-partition/`: the Prover SDK's port to this chip) in the secure
slot, the Aegis prover (`prover-ns/`) in the non-secure slot. `upgrade_secure.sh` replaces the secure image with
backup, policy change and checks; `restore_from_backup.sh` puts both slots back from such a backup; `probe.sh` is
the TrustZone negative test. What was changed on the boards, and how to undo it: `docs/board-changes.md`.

## STM32 EAT image

The same two images built with the option for standard evidence (`docs/evidence-format.md`, "STM32 EAT image"): the
partition answers PSA message `QUOTE_EAT` (type 7) and the prover forwards `PQEAT <challenge>`, so the gateway can
ask with `"evidence_format": "eat-cose-v1"`. The option is off by default; built without it, both images are the
ones board 1 runs (SPE `9de76167...`, NSPE `1f4110fd...`). Board 2 has run the images below since 21 November 2026
(SPE `315dcc2f...`, NSPE `acf8fc53...`), with `"evidence_format": "eat-cose-v1"` in its policy entry.

Build (no board needed; under a minute):

    OUT=$HOME/aegis-tools/tfm-aegis-build-eat/eat endpoints/stm32h573/tfm-aegis-partition/build_tfm.sh -DAEGIS_EAT_COSE=ON
    (cd endpoints/stm32h573/prover-ns && SPE=$HOME/aegis-tools/tfm-aegis-build-eat/eat/api_ns ./build.sh -DAEGIS_EAT_COSE=ON)

The images built on 21 November 2026, in `~/aegis-tools/tfm-aegis-build-eat/images/` (with `SHA256SUMS`):

| Image | sha256 of the .hex | Measurement (`tools/image_measurement.py`) |
|---|---|---|
| secure: `tfm-s-v2.3.0-aegis-pq-sdk2-eat.hex` | `550dc43877a21e709454bd308c200e197b2cf5cc35bec42205ac011227de764f` | SPE `315dcc2fae21ac5ec7a6a69338f9c490b98f38953403c37a7cb624092b361bbe` (version 2.3.0, signer `e30466f6...`, as now) |
| non-secure: `prover-ns-0.6.0-eat.hex` | `224ee58081bd5c8d6adeff64e658f84652786980bf38157f9cb2a65f8c9dea5f` | NSPE `acf8fc53323d1a80535fc8e7726692d2830fd1935b86917991ad3a6c413ed1f3` (signer `82a5b443...`, as now) |

Both slots change: the prover without the option answers `PQEAT` with `ERR bad-request`. The secure gateway veneers
did not move, so either secure image runs with either non-secure image, and the steps below can stop after any one.
Expected on the board: the same `sstack=18872/26624` in the heartbeat as SPE 9de76167 (`tools/stack_estimate.py`
gives 18704 for both builds).

**Before you start: endorsement.** If the board's entry has `"endorsement": "required"`, its record names SPE
`9de76167...` and NSPE `1f4110fd...`, and a quote must report exactly the endorsed components
(`docs/enrolment.md`, rule 8): issue a record with the new values first, or step 1 ends "NOT admitted".

### Put it on board 2

    SN=<board 2's ST-LINK serial>
    IMG=$HOME/aegis-tools/tfm-aegis-build-eat/images
    (cd $IMG && sha256sum -c SHA256SUMS)

1. **Secure slot.** Backup of both slots, the new SPE allowed next to the old one, written, admitted (still with
   `PQCHAL`), the old SPE removed; it prints the rollback if the board is not admitted:

       endpoints/stm32h573/upgrade_secure.sh stm32h573-dk-2 "$SN" $IMG/tfm-s-v2.3.0-aegis-pq-sdk2-eat.hex

2. **Non-secure slot.** Allow the new NSPE next to the old one, write the prover, reset, wait for `ADMITTED`
   (`ssh root@$GATEWAY journalctl -u aegis-fleet -f`). Step 1's backup already holds this slot.

       ssh root@$GATEWAY "cp /root/aegis/gateway/policy/fleet.json /root/aegis/gateway/policy/fleet.json.bak-eat` (any name you will remember; `upgrade_secure.sh` makes its own `fleet.json.bak-<stamp>`"
       ssh root@$GATEWAY "python3 -c \"
       import json; P = '/root/aegis/gateway/policy/fleet.json'; p = json.load(open(P))
       e = [x for x in p['endpoints'] if x['name'] == 'stm32h573-dk-2'][0]
       e['allowed'].append({'type': 'NSPE', 'measurement_value': 'acf8fc53323d1a80535fc8e7726692d2830fd1935b86917991ad3a6c413ed1f3'})
       json.dump(p, open(P, 'w'), indent=1)\""
       CLI=$HOME/STMicroelectronics/STM32Cube/STM32CubeProgrammer/bin/STM32_Programmer_CLI
       $CLI -c port=SWD sn=$SN mode=UR -d $IMG/prover-ns-0.6.0-eat.hex -v      # "Download verified successfully"
       $CLI -c port=SWD sn=$SN mode=HOTPLUG -hardRst

3. **Policy: standard evidence.** On the entry: `"evidence_format": "eat-cose-v1"`, and the old NSPE removed. The
   next cycle asks `PQEAT`; the verdict carries `evidence_format` and an attestation result is written for it.

       ssh root@$GATEWAY "python3 -c \"
       import json; P = '/root/aegis/gateway/policy/fleet.json'; p = json.load(open(P))
       e = [x for x in p['endpoints'] if x['name'] == 'stm32h573-dk-2'][0]
       e['evidence_format'] = 'eat-cose-v1'
       e['allowed'] = [a for a in e['allowed'] if a.get('measurement_value') != '1f4110fd8b2a5e93839bccdd37c8ff13d206527bc649fb3e57318117ce6ecb8b']
       json.dump(p, open(P, 'w'), indent=1)\""

   The gateway must run a `fleet.py` that knows `evidence_format` (this repository's `main` since WP10).

### When the gateway runs a signed policy

`upgrade_secure.sh` and the `fleet.json` edits above act on the unsigned policy file. If the loop runs from a signed
policy (`docs/audit-and-policy.md`), they do not reach it. Do it as on the bench of 21 November 2026:

1. Put the new SPE and NSPE next to the old ones in the signed policy (`policy-sign`, a new version), deploy it
   (`fleet.py check` first), and let the loop reload it.
2. Write both slots with STM32CubeProgrammer as in step 2 (`-d <hex> -v`, then `-hardRst`). The board is refused
   with "component SPE is not the endorsed one" until step 3, as expected.
3. `aegis_provision.py endorse` the new image (the reference holds only the two new components), then
   `fleet.py enroll-endorsed <signed policy> <record> --policy-signers ...`. It does not pin the record; it prints
   the record's pin. Use that printed `endorsement_sha256` (the record's own hash, not the SHA-256 of the file).
4. Sign a policy with that pin, `"evidence_format": "eat-cose-v1"` and the old SPE and NSPE removed. The board is
   then admitted, and `fleet.py export-evidence` gives a pack that `tools/verify_evidence.py pack` accepts.

Rollback: sign a policy that allows the old SPE and NSPE again and drops `evidence_format`, write the rollback
images, and re-endorse them (the old record is kept as `fleet.json.bak-<stamp>`'s `endorsement_sha256`).

### Roll back

To SPE `9de7616732cfde9504dd448e8d8075de4a2a95163998228395ad37973ee60979` and NSPE `1f4110fd...`:

1. Take `"evidence_format"` off the entry first: the old images do not answer `PQEAT`, so the board would not be
   admitted in step 2.
2. Secure slot, with the image running before (`~/aegis-tools/tfm-aegis-build-sdk2/bin/tfm_s_signed.hex`, sha256
   `f4620c85dc3774221159df4c1c3863da9b564b44d29e385123371bc92f359637`; a copy is
   `$IMG/rollback-tfm-s-sdk2-9de76167.hex`):

       endpoints/stm32h573/upgrade_secure.sh stm32h573-dk-2 "$SN" $HOME/aegis-tools/tfm-aegis-build-sdk2/bin/tfm_s_signed.hex

3. Non-secure slot: allow NSPE `1f4110fd8b2a5e93839bccdd37c8ff13d206527bc649fb3e57318117ce6ecb8b` again as in step
   2 above, write `endpoints/stm32h573/artifacts/prover-ns-0.6.0-sstack.hex` (sha256 `3e1238b5...`; a copy is
   `$IMG/rollback-prover-ns-0.6.0-sstack-1f4110fd.hex`) the same way, reset, then remove NSPE `acf8fc53...`.

Or both slots at once from step 1's backup, and the policy as it was:

    STM32_SN=$SN endpoints/stm32h573/restore_from_backup.sh backups/stm32h573/<stamp>-stm32h573-dk-2-before-upgrade
    ssh root@$GATEWAY cp /root/aegis/gateway/policy/fleet.json.bak-<stamp> /root/aegis/gateway/policy/fleet.json
