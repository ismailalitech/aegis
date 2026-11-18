# Enforcement with one gateway port and a VLAN switch

The gateway decides and records, but with one Ethernet port it cannot stand between the endpoints and the rest of the
network (threat model T16). A switch that does 802.1Q VLANs changes that without a second port. The endpoints go on
their own VLAN, the gateway's port carries that VLAN as well as the LAN, and the endpoints then reach anything only
through the gateway. The gateway routes between the two, masquerades, and enforces `gateway/enforce/aegis.nft` on the
VLAN interface.

```
 router --- [VLAN 1] ---+                 +--- [VLAN 20, untagged] --- STM32, RW612, ...
                        |   VLAN switch   |
 PC ------- [VLAN 1] ---+                 +--- [VLAN 1 untagged + VLAN 20 tagged] --- PolarFire gateway (end0, end0.20)
```

## Tested (`sudo tests/host/test_enforcement_vlan.sh`, network namespaces, also in CI)

A Linux bridge with VLAN filtering plays the switch, and `vlan-setup.sh` and the real ruleset run unchanged. Result:
16 of 16.

**Admission**
- An unattested endpoint reaches nothing on the LAN, only the gateway's quote port.
- The gateway can attest it.
- Once admitted, it reaches the LAN, masqueraded.
- A second, unattested endpoint still cannot reach the LAN.
- Once quarantined, it is cut off again, and the gateway can still attest it.

**Ways around the VLAN (all blocked)**
- An endpoint that gives itself a LAN address.
- An endpoint that tags its own frames for the LAN's VLAN.
- A LAN host reaching an endpoint directly.

**Known limits (the test checks that they behave as stated)**
- Endpoints on the same VLAN see each other past the gateway. Closing that needs the switch's port isolation (D-Link
  calls it traffic segmentation).
- A device that takes the address of an admitted endpoint that has gone away passes until the gateway's next cycle
  (30 s). That cycle attests the address, gets no valid quote and quarantines it. A switch with port security or
  802.1X would close this.

Writing the VLAN test also found a bug in the ruleset, which `tests/host/test_enforcement.sh` now checks. The input
chain dropped the replies to the gateway's own connections, so a non-admitted endpoint could never be attested, and
never admitted. Replies (`ct direction reply`) are now accepted; connections an endpoint opens still go through the
rules.

## The switch

It needs 802.1Q VLANs: D-Link's "smart" or "easy smart" models do (DGS-1100 series, for example); the unmanaged
DGS-105 and DGS-108 do not. In its web page:

1. Create VLAN 20.
2. Endpoint ports: untagged members of VLAN 20, removed from VLAN 1, PVID 20.
3. The gateway's port: untagged in VLAN 1 (PVID 1), tagged in VLAN 20.
4. The router's and the PC's ports: VLAN 1 only (the default).
5. If it has it, traffic segmentation, so endpoint ports can only talk to the gateway's port.

## The gateway (not applied yet)

```sh
# fixed addresses for the endpoints (their MACs are fixed: each is 02:ae plus the first bytes of the device's key)
printf 'static_lease <MAC> 10.20.0.10\n...' > /root/aegis/vlan-leases
AEGIS_VLAN_LEASES=/root/aegis/vlan-leases /root/aegis/gateway/enforce/vlan-setup.sh up end0 20 10.20.0.1/24 --dhcp 10.20.0.100 10.20.0.199
```

Then:
- set each endpoint's `host` in `fleet.json` to its VLAN address, and the policy's `enforce_cmd` to
  `aegis-enforce.sh`;
- on the PC, add a route to `10.20.0.0/24` via the gateway's LAN address, to reach the endpoints for tests.

To undo everything: `vlan-setup.sh down end0 20`.
