# FRDM-RW612 with TrustZone: the Aegis prover as a TF-M secure partition

The Zephyr prover (`../prover`) is a single secure image: the firmware that derives the key also measures itself, so
the gateway labels it "device-key trust". Here the key and the measurements move into the TrustZone secure side,
under NXP's TF-M (v2.1.4, from the MCUXpresso SDK), and the non-secure image only carries the network.

## What runs where

- **Secure (TF-M + `aegis_pq`, a PSA-RoT partition, SID 0xAE10):**
  - At initialisation, before the non-secure image runs: SHA-256 of the whole secure partition (`SPE`,
    0x18001000-0x1809FFFF) and of the whole non-secure partition (`NSPE`, 0x180A0000-0x1839FFFF).
  - At the first request: the ML-DSA-65 key from ELS (CKDF from the die key, then HMAC, as in `../prover`). Not at
    initialisation, because TF-M's crypto partition sets ELS up during its own initialisation. Using ELS before that
    left the chip resetting moments later.
  - Every request: one line of the Aegis protocol in, the reply out. The code is `../prover/src/aegis_proto.c`, the
    same code the PC tests run against the gateway.
- **Non-secure:** a client that passes lines to the partition with `psa_call`. It never holds the key, the seed or the
  session, and it cannot reach ELS, which TF-M makes secure-privileged only.

The key is the same as the Zephyr prover's (`sha256(pk)` starts `dddd6ba1`): it is bound to the chip, not to the
firmware. What TrustZone adds is that a compromised **non-secure** image (a bug in the network stack, say) can neither
use the key nor change a measurement. Someone who reflashes the **secure** image with a debugger still can, as on the
STM32 with TF-M's development keys, until secure boot is fused on (not done on this bench).

## Build and flash

    cd ~/aegis-tools/mcuxsdk/mcuxsdk
    export ARMGCC_DIR=~/aegis-tools/arm-gnu-toolchain-14.2.rel1-x86_64-arm-none-eabi PATH=~/aegis-tools/zephyr-venv/bin:$PATH
    west build -p always --sysbuild ~/aegis/endpoints/rw612/tfm/aegis_ns_test --toolchain armgcc --config release \
        -b frdmrw612 -d ~/aegis-tools/rw-tfm/aegis-test
    ~/aegis/endpoints/rw612/tfm/flash.sh ~/aegis-tools/rw-tfm/aegis-test/aegis_s/aegis_s.bin \
        ~/aegis-tools/rw-tfm/aegis-test/aegis_ns_test/aegis_ns_test.bin

Needs the MCUXpresso SDK (`west init -m https://github.com/nxp-mcuxpresso/mcuxsdk-manifests.git`, then
`west update_board --set board frdmrw612`), CMake 3.30 or newer and Ninja 1.12 (pip, in the west venv), and the Arm GNU
toolchain 14.2. The projects change no SDK file: TF-M's linker scripts are preprocessed into the build directory, and
the one TF-M setting changed (the crypto IOVEC scratch, 33000 bytes on this board, lowered to 12288 so the partition
fits in the 192 KB of secure RAM) is set by a generated `config_tfm_target.h` that includes NXP's file first.

## Safety

Flashing writes only the external flash. The secure build keeps the board port's `-DOCOTP_NV_COUNTERS_RAM_EMULATION=1`:
without it, TF-M's NV counters would program real OTP fuses (`rw61x/nv_counters.c` stops the build with an `#error`
then). Never run the SDK's `tfm_secureboot/scripts`: they burn the secure-boot keys and can close the chip's lifecycle.
`flash.sh` erases the secure and non-secure partitions only, not TF-M's storage, the Wi-Fi firmware or anything else.

## Results so far (evidence/rw612-tfm/)

- NXP's TF-M regression on this board: 164 of 164 tests, 16 of 16 suites.
- 0.2.1 (the fix above, the stack report): flashed with the unchanged non-secure image (byte-identical), so only
  `SPE` changed in the gateway policy; the new value was allowed before flashing and the old one removed after the
  board was admitted.
- The Aegis partition with the test client: the key from ELS (`rc=0`), a `PQKEY` reply, a 378-byte claims token with
  profile `aegis-rw612-tfm-v1` and its ML-DSA-65 signature, and the expected errors for the other requests.

## Hardening TF-M's defaults (stage A, done)

NXP's `target_cfg.c` gives the non-secure world user access to peripherals that let it change what the secure side
measures, or harm the chip for good. `aegis_s/platform/target_cfg.c` is NXP's file with eight access rules changed to
secure-privileged: OCOTP and its adapter (fuse programming), FlexSPI and OTFAD (they could rewrite the secure image and
TF-M's storage), both flash caches, the TRNG (the non-secure side gets randomness through PSA), ROM control and the
debug mailbox. The CMake builds it instead of NXP's, and leaves out the load data of NXP's loader service, which lets a
non-secure caller make secure code process an SB3 file and write memory. No SDK file changes.

Tested on the board (`probe.sh`, evidence/rw612-tfm/hardening-probes.txt): a test build of the non-secure prover reads
one register of a peripheral at start-up. With NXP's rules, OCOTP and FlexSPI read fine; with the Aegis rules, OCOTP,
FlexSPI, the flash cache and the TRNG each fault (TF-M resets the chip, the read never returns), while the ENET register
the prover needs still reads. The hardened images are admitted by the gateway with trustzone trust.

Stage B (done): RSTCTL0, CLKCTL0 and SYSCTL0 are secure-privileged too; they hold the ELS reset and clock. The secure
partition switches the Ethernet controller's clocks on and releases its reset before the non-secure image runs, and the
non-secure image no longer touches those blocks: its drivers are built without clock control, its console starts at the
20 MHz the secure side set (measured on this board), its clock frequencies are constants. The same probe test: RSTCTL0,
CLKCTL0 and SYSCTL0 fault from the non-secure side, the ENET register still reads, and the gateway admits the image.

## Security review (docs/rw612-security-review.md)

Four reviewers and a skeptic per finding. Confirmed and fixed: the pin mux, SOC_TOP, PMU and SYSCTL2 made secure-only
(the pin mux one was critical: the non-secure side could remux the QSPI flash pins to GPIO and rewrite the flash without
FlexSPI), `enroll-pq` keeps existing pins, the credential names the pending ML-KEM key, `probe.sh` has three outcomes.
All re-tested on the board.

## Fuzzing (tests/fuzz, after the review)

`tests/fuzz/run.sh` builds `aegis_proto.c` into a libFuzzer harness with AddressSanitizer and UndefinedBehaviorSanitizer
and calls it exactly as `aegis_pq.c` does: raw request bytes up to `AEGIS_LINE_MAX`, a reply buffer of exactly
`AEGIS_REPLY_MAX`. The harness also plays the gateway (it holds the pinned gateway key, encapsulates, signs
credentials whose body the input changes), so the fuzzer reaches the paths behind the signature check, and it checks
every answer against a model of the protocol: a credential is accepted if and only if it is valid for the pending
exchange, a raw line is never accepted as one, and the confirmation tag, session id and every heartbeat tag are what
the gateway computes. CI runs it for 2 minutes on every push, seeds first.

It found one defect within seconds: a `PQKEMINIT` refused after the ML-KEM key was made (`ERR sign` when the RNG
fails, `ERR kem`) left the older exchange pending with the new key and nonce in it, unusable, with the new
decapsulation key kept in memory. Not exploitable from the non-secure side (it can always disrupt its own exchanges,
and no credential can name a key the gateway never saw), but the state was wrong. Fixed in 0.2.1: a valid
`PQKEMINIT` cancels the pending exchange and wipes its decapsulation key first. The STM32 partition had the same
pattern; it is fixed and deployed on board 2 (`evidence/stm32-kemfix/`), and `STM32=1 tests/fuzz/run.sh` fuzzes it.

## Stack of the secure partition (0.2.1)

At initialisation the partition fills its own stack (`tfm_sp_aegis_pq_stack`, 32 KB) below the current frame with a
pattern, and the heartbeat status reports the high-water mark: `stack=19368/32768` on the board after the key
derivation in ELS, quotes, ML-KEM exchanges and heartbeats (59 %, 13 KB to spare). TF-M sets the stack limit register
to the stack's base, so an overflow would fault rather than write into another partition.
