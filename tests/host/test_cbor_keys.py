# SPDX-License-Identifier: Apache-2.0
"""A CBOR map whose key is an array or a map, or that repeats a key, is refused as a decoding error. Before this
check an array key raised TypeError inside the decoder, which fleet.attest() does not catch for the "psa" kind: one
malformed token stopped the fleet loop."""
import os, sys, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "common"))
import cbor, psa_token


class MapKeys(unittest.TestCase):
    def test_array_key_is_a_cbor_error(self):
        with self.assertRaises(cbor.CBORError):
            cbor.loads(bytes.fromhex("a1" "8101" "02"))        # {[1]: 2}

    def test_map_key_is_a_cbor_error(self):
        with self.assertRaises(cbor.CBORError):
            cbor.loads(bytes.fromhex("a1" "a0" "02"))          # {{}: 2}

    def test_duplicate_key_is_a_cbor_error(self):
        with self.assertRaises(cbor.CBORError):
            cbor.loads(bytes.fromhex("a2" "0102" "0103"))      # {1: 2, 1: 3}

    def test_ordinary_maps_still_decode(self):
        self.assertEqual(cbor.loads(cbor.dumps({1: b"a", "k": [1, 2], -75000: "p"})), {1: b"a", "k": [1, 2], -75000: "p"})

    def test_token_with_array_key_raises_only_valueerror(self):
        payload = bytes.fromhex("a1" "8101" "02")
        token = cbor.dumps(cbor.Tag(18, [cbor.dumps({1: -7}), {}, payload, b"\x00" * 64]))
        with self.assertRaises(ValueError):                     # CBORError and TokenError are both ValueError
            psa_token.parse(token)
        with self.assertRaises(ValueError):
            psa_token.parse_plain(payload)


if __name__ == "__main__":
    unittest.main()
