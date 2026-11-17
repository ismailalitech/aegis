# A second network port without a managed switch (branch `second-port`, not wired yet)

> **Shelved, 17 November 2026.** There is no W5500 module on the bench, so this was never wired. Everything here was built
> and tested without it (namespaces, and a dry run on the gateway). Enforcement stays tested in network namespaces only
> (`tests/host/test_enforcement.sh`); on the bench the gateway decides but does not block. Kept on this branch for whoever
> has the module.

Enforcement needs the endpoints on their own network segment, with the gateway routing between that segment and the
rest of the network. The Discovery Kit has one Ethernet port and the bench switch (a D-Link DGS-108) is unmanaged, so it
cannot make VLANs. This adds a second port: a WIZnet W5500 Ethernet module on the Raspberry Pi header, run by the
mainline Linux `w5100` driver. **No fabric change is needed.**

## Why the Raspberry Pi header and not the mikroBUS socket

Both the W5500 and the ENC28J60 drivers need an interrupt line; without one they do not start (`w5100.c` calls
`request_threaded_irq` unconditionally). Checked in the netlist that is programmed on the board
(`build/libero/work/.../MPFS_DISCOVERY_KIT.v`, build dv101):

| | mikroBUS socket (J5) | Raspberry Pi header (J10) |
|---|---|---|
| SPI | MSS SPI0, through the fabric | MSS SPI1, MSS pads (bank 2 B) |
| Interrupt pin | `MBUS_INT` is in the pin constraints but **not connected** in the design | `RPi_GPIO25` = MSS GPIO2 line 7 |
| Interrupt reaches Linux | no | **yes**: GPIO2 interrupts go through the GPIO2 shared line (`GPIO_INTERRUPT_FAB_CR` = 0); arming an edge on line 7 registered `MPFS GPIO 7 Edge` |
| Fabric change | yes (route `MBUS_INT` to a GPIO2 input, rebuild, reprogram) | none |

## What to buy

- A **W5500 module** with a 3.3 V supply and pin headers (WIZnet WIZ850io, or the common "W5500 Lite" board).
- 8 female-female jumper wires.
- One Ethernet cable from the STM32 board to the module (the STM32 leaves the switch).

## Wiring

| W5500 module | Discovery Kit J10 (Raspberry Pi numbering) | Signal |
|---|---|---|
| MOSI | pin 19 | SPI1 data out |
| MISO | pin 21 | SPI1 data in |
| SCLK | pin 23 | SPI1 clock |
| SCSn | pin 24 | SPI1 chip select 0 |
| INTn | pin 22 | RPi_GPIO25 = GPIO2 line 7 |
| 3.3V | pin 17 | |
| GND | pin 20 | |
| RSTn | leave unconnected (pulled up on the module) | |

Pins 22, 17 and 20 follow the Raspberry Pi convention that the board's signal names use. **The four SPI1 pins at
19, 21, 23 and 24 are the Raspberry Pi positions and are not yet checked against the board schematic**; check J10 in
the Discovery Kit schematic (or user guide, appendix "User Hardware Pinout") before powering on. Check also that the
3.3 V rail on the header can supply the module (a W5500 draws about 130 mA with the link up).

## Software (built and tested on the PC)

| File | What it does |
|---|---|
| `gateway/second-port/w5500-spi1.dtso` | Overlay: `wiznet,w5500` on SPI1 chip select 0, 20 MHz, interrupt GPIO2 line 7 level low (what the driver requests itself) |
| `tools/build_second_port.sh` | Builds `w5100.ko` and `w5100-spi.ko` out of tree, from the kernel's own sources, against the Yocto build of the gateway kernel (same release string, same `Module.symvers`); compiles the overlay; writes `SHA256SUMS` |
| `gateway/second-port/bringup.sh` | On the gateway: checks the sums, loads the drivers, applies the overlay through configfs, gives the new port `10.77.0.1/24`, starts busybox `udhcpd` on it (pool .10-.50, fixed leases from `static-leases`), turns on forwarding and masquerades endpoint traffic towards `end0` |
| `gateway/second-port/teardown.sh` | Undoes all of it. Nothing is written to flash; a reboot also undoes it |
| `tests/host/test_second_port.sh` | Runs `bringup.sh --no-hw` on a veth pair in three namespaces with the real enforcement hook: 12 checks (below) |

`tests/host/test_second_port.sh`, `sudo`, 12 of 12 pass (also in CI):

- the port gets its address and forwarding is on;
- the endpoint, which starts with no address, gets its fixed lease `10.77.0.20` and router `10.77.0.1` by DHCP;
- not attested: the network is blocked and the quote port is reachable;
- admitted: the network is reachable and sees the gateway's address (the network has no route back, so this only works
  through the masquerade);
- quarantined: blocked again;
- tear-down: masquerade table, forwarding, address and DHCP server are all back as before.

**On the gateway, without the module (17 November 2026):** the modules load (vermagic matches the running kernel), the
overlay applies (`status: applied`), `spi1.0` appears, and the driver stops at chip detection because nothing answers;
`teardown.sh` removes everything and `aegisd` and `aegis-fleet` stay active. The interrupt mapping was confirmed on an
untouched line (GPIO2 line 6). Line 7 itself reported `type mismatch` in that session because the earlier edge test had
left it mapped as an edge interrupt; that mapping is gone after a reboot. **Reboot the gateway once before the first
bring-up.**

## At the bench

1. Wire the module (check the SPI pins on the schematic first), connect the STM32's Ethernet cable to it.
2. Reboot the gateway. Copy `gateway/second-port/` with the built files (`tools/build_second_port.sh`) to `/root/aegis/`.
3. `./bringup.sh` prints the interface name. `dmesg | grep w5100` should show the driver's start-up line.
4. The STM32 gets an address from the pool; read it in `$STATE/udhcpd.leases` or on its console, and add a line
   `static_lease <its MAC> 10.77.0.20` to `static-leases` so it stays the same.
5. Change the STM32's `host` in the fleet policy to `10.77.0.20`, load the ruleset with
   `gateway/enforce/aegis-enforce.sh init <interface>`, restart `aegis-fleet`.
6. Check: the journal shows `ADMITTED` for the STM32; `tools/demo.sh` quarantine cuts its traffic to the rest of the
   network while the quote port stays open.
7. To go back: `./teardown.sh`, STM32 cable back to the switch, old `host` in the policy.

Throughput: the W5500 runs in MACRAW mode over a 20 MHz SPI bus, which gives a few Mbit/s. Attestation, credentials
and heartbeats are a few kilobytes every 30 s per endpoint.
