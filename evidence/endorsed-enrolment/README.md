# Endorsed enrolment (plan step 8)

`docs/enrolment.md` has the design, the rules and the runbook; threat T25 and limitation 11 of
`docs/threat-model.md` say what an endorsement does not show.

| File | What it shows |
|---|---|
| `pc-rehearsal.txt` | **PC only, simulated devices.** The runbook's steps in order, with the commands of `docs/enrolment.md` (the gateway replaced by a directory, `ssh` and `scp` by `cp`). Three endpoints enrolled by trust on first use hold sessions; the endorser endorses each (15 to 20 ms); `fleet.py enroll-endorsed` accepts the three records without `--force` because the keys are the pinned ones; `tests/board/endorsement_check.py`, read from standard input as it is over ssh, exits 0 for a pair of the same family (E9: the substitution is admitted under trust on first use and refused at E3 to E5 with the requirement) and for a mixed pair; after the switch `fleet.py check` says `endorsed by bench-pc` and the sessions are kept; a key file replaced by the other board's key, then a missing record, are quarantined with the credential revoked, and the endpoint is provisioned again when the files are back; a record signed by an endorser the policy does not list is refused by `enroll-endorsed` |

The simulated devices: two `aegis-pq` endpoints of `tests/host/test_fleet.py` (PSA-style token, ES256 inside, the
same measurements, different ML-DSA-65 keys: the two STM32 boards), and the Prover SDK's core behind its PC port
(`sdk/ports/host`, profile `aegis-rw612-els-v1`, sessions bound by the transcript). The same steps are in
`tests/host/test_endorsement.py` (`BoardCheck`, `SdkCore`, `Enrolment`), which CI runs.

**Not here yet: the boards.** The three real endpoints are endorsed, and the gateway's policy switched, by the
runbook's steps 1 to 7; their outputs (the tool's `elapsed_s` per device, the two check runs, `fleet.py check`, the
journal lines of the switch and of the substituted key) belong in this directory once that has been run.
