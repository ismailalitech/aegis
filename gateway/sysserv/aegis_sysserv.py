#!/usr/bin/env python3
"""Read-only access to the PolarFire SoC system controller from Linux.

Talks to /dev/mpfs_generic_service (kernel module mpfs-generic-service).
That driver forwards ANY command to the system controller, including
programming commands. This tool therefore only builds requests from a
fixed table of read-only services and refuses every other opcode.

Request layout expected by the driver (little endian):
    u8  opcode
    u16 cmd_data_size   (must equal len(data))
    u16 resp_size
    u16 mbox_offset
    u16 resp_offset
    u8  data[cmd_data_size]
A read returns one status byte followed by resp_size (rounded up to 4) bytes.

Offsets and sizes come from Microchip's bare-metal mss_sys_services driver.
"""
import argparse
import binascii
import json
import os
import struct
import sys

DEVICE = "/dev/mpfs_generic_service"

# name: (opcode, cmd_data_len, resp_len, resp_offset)
# Only services that read state or compute on supplied data. No service
# in this table writes to non-volatile memory or changes device state.
SERVICES = {
    "serial":      (0x00, 0, 16, 0),
    "usercode":    (0x01, 0, 4, 0),
    "design_info": (0x02, 0, 36, 0),
    "device_cert": (0x03, 0, 1024, 0),
    "digest":      (0x04, 0, 576, 0),
    "security":    (0x05, 0, 36, 0),
    "sign_raw":    (0x19, 48, 96, 48),
    "sign_der":    (0x1A, 48, 104, 48),
    "puf_emu":     (0x20, 20, 32, 20),
    "nonce":       (0x21, 0, 32, 0),
}
ALLOWED_OPCODES = frozenset(v[0] for v in SERVICES.values())


class ServiceError(Exception):
    pass


def build_request(name, data=b""):
    """Return the bytes to write for service `name`. Raises on anything else."""
    if name not in SERVICES:
        raise ServiceError("service not allowed: %r" % (name,))
    opcode, dlen, rlen, roff = SERVICES[name]
    if opcode not in ALLOWED_OPCODES:  # defensive; the table is the whitelist
        raise ServiceError("opcode not allowed: 0x%02x" % opcode)
    if len(data) != dlen:
        raise ServiceError("%s needs %d data bytes, got %d" % (name, dlen, len(data)))
    return struct.pack("<BHHHH", opcode, dlen, rlen, 0, roff) + bytes(data)


def parse_response(name, raw):
    """Split the driver's read result into (status, payload of resp_len bytes)."""
    rlen = SERVICES[name][2]
    if len(raw) < 1 + rlen:
        raise ServiceError("%s: short response (%d bytes)" % (name, len(raw)))
    return raw[0], bytes(raw[1:1 + rlen])


def call(name, data=b"", device=DEVICE, opener=None):
    req = build_request(name, data)
    rlen = SERVICES[name][2]
    opener = opener or (lambda: os.open(device, os.O_RDWR))
    fd = opener()
    try:
        n = os.write(fd, req)
        if n != len(req):
            raise ServiceError("%s: short write" % name)
        raw = os.read(fd, 1 + ((rlen + 3) // 4) * 4)
    finally:
        os.close(fd)
    status, payload = parse_response(name, raw)
    if status != 0:
        raise ServiceError("%s: system controller status %d" % (name, status))
    return payload


def puf_request(challenge, op_type=0):
    """Mailbox format used by the vendor driver: op_type, 3 zero bytes, 16-byte challenge."""
    if len(challenge) != 16:
        raise ServiceError("challenge must be 16 bytes")
    return bytes([op_type & 0xFF, 0, 0, 0]) + bytes(challenge)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("service", choices=sorted(SERVICES) + ["puf", "sign", "all"])
    p.add_argument("--hex", help="input as hex: 16-byte challenge (puf) or 48-byte SHA-384 (sign)")
    p.add_argument("--op", type=int, default=0, help="PUF emulation op_type (default 0)")
    p.add_argument("--out", help="write the raw payload to this file")
    p.add_argument("--device", default=DEVICE)
    a = p.parse_args(argv)

    if a.service == "all":
        out = {}
        for s in ("serial", "usercode", "design_info", "security", "nonce"):
            out[s] = call(s, device=a.device).hex()
        print(json.dumps(out, indent=1))
        return 0
    if a.service in ("puf", "puf_emu"):
        name, data = "puf_emu", puf_request(binascii.unhexlify(a.hex or "00" * 16), a.op)
    elif a.service in ("sign", "sign_raw", "sign_der"):
        name = "sign_der" if a.service == "sign_der" else "sign_raw"
        data = binascii.unhexlify(a.hex or "")
    else:
        name, data = a.service, b""
    payload = call(name, data, device=a.device)
    if a.out:
        with open(a.out, "wb") as f:
            f.write(payload)
    print(payload.hex())
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ServiceError, OSError) as e:
        print("error: %s" % e, file=sys.stderr)
        sys.exit(1)
