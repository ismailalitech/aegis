# SPDX-License-Identifier: Apache-2.0
"""Host tests for the read-only system-service tool (no board needed)."""
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "gateway", "sysserv"))
import aegis_sysserv as ss  # noqa: E402

# Opcodes that program or change the device (from the vendor header). None may ever be sent.
DANGEROUS = [0x10, 0x11, 0x12, 0x22, 0x23, 0x42, 0x43, 0x44, 0x47, 0x49, 0x4A]


class Whitelist(unittest.TestCase):
    def test_no_dangerous_opcode_in_table(self):
        for op in DANGEROUS:
            self.assertNotIn(op, ss.ALLOWED_OPCODES)

    def test_unknown_service_refused(self):
        for name in ("iap_program", "snvm_write", "", "SERIAL"):
            with self.assertRaises(ss.ServiceError):
                ss.build_request(name)

    def test_wrong_data_length_refused(self):
        with self.assertRaises(ss.ServiceError):
            ss.build_request("sign_raw", b"\0" * 47)
        with self.assertRaises(ss.ServiceError):
            ss.build_request("serial", b"\0")


class Layout(unittest.TestCase):
    def test_serial_request(self):
        self.assertEqual(ss.build_request("serial"), struct.pack("<BHHHH", 0, 0, 16, 0, 0))

    def test_sign_request(self):
        h = bytes(range(48))
        r = ss.build_request("sign_raw", h)
        self.assertEqual(r[:9], struct.pack("<BHHHH", 0x19, 48, 96, 0, 48))
        self.assertEqual(r[9:], h)

    def test_puf_request(self):
        c = bytes(range(16))
        d = ss.puf_request(c, 1)
        self.assertEqual(d, b"\x01\0\0\0" + c)
        self.assertEqual(ss.build_request("puf_emu", d)[:9], struct.pack("<BHHHH", 0x20, 20, 32, 0, 20))

    def test_call_with_fake_device(self):
        written = []

        def opener():
            return 99

        real_write, real_read, real_close = os.write, os.read, os.close
        try:
            os.write = lambda fd, b: written.append(b) or len(b)
            os.read = lambda fd, n: b"\x00" + bytes(range(16))
            os.close = lambda fd: None
            out = ss.call("serial", opener=opener)
        finally:
            os.write, os.read, os.close = real_write, real_read, real_close
        self.assertEqual(out, bytes(range(16)))
        self.assertEqual(written[0], ss.build_request("serial"))

    def test_nonzero_status_raises(self):
        real_write, real_read, real_close = os.write, os.read, os.close
        try:
            os.write = lambda fd, b: len(b)
            os.read = lambda fd, n: b"\x03" + bytes(32)
            os.close = lambda fd: None
            with self.assertRaises(ss.ServiceError):
                ss.call("nonce", opener=lambda: 1)
        finally:
            os.write, os.read, os.close = real_write, real_read, real_close


if __name__ == "__main__":
    unittest.main()
