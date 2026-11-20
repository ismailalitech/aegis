# SPDX-License-Identifier: Apache-2.0
"""KMAC (common/kmac.py) against NIST's KMAC samples 1-6 (SP 800-185 example values, as reproduced in
pycryptodome's test suite), and against pycryptodome itself on random inputs when it is installed."""
import os, random, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "common"))
import kmac

NIST = [
    ('Sample #1', 'kmac128',
     '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
     '00010203',
     '',
     'e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e'),
    ('Sample #2', 'kmac128',
     '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
     '00010203',
     'My Tagged Application',
     '3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5'),
    ('Sample #3', 'kmac128',
     '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
     '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7',
     'My Tagged Application',
     '1f5b4e6cca02209e0dcb5ca635b89a15e271ecc760071dfd805faa38f9729230'),
    ('Sample #4', 'kmac256',
     '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
     '00010203',
     'My Tagged Application',
     '20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd'),
    ('Sample #5', 'kmac256',
     '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
     '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7',
     '',
     '75358cf39e41494e949707927cee0af20a3ff553904c86b08f21cc414bcfd691589d27cf5e15369cbbff8b9a4c2eb17800855d0235ff635da82533ec6b759b69'),
    ('Sample #6', 'kmac256',
     '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
     '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7',
     'My Tagged Application',
     'b58618f71f92e1d56c1b8c55ddd7cd188b97b4ca4d99831eb2699a837da2e4d970fbacfde50033aea585f1a2708510c32d07880801bd182898fe476876fc8965'),
]


class NistSamples(unittest.TestCase):
    def test_samples(self):
        for name, alg, key, data, custom, out in NIST:
            got = getattr(kmac, alg)(bytes.fromhex(key), bytes.fromhex(data), len(out) // 2, custom.encode())
            self.assertEqual(got.hex(), out, name)


class AgainstPycryptodome(unittest.TestCase):
    def test_random(self):
        try:
            from Crypto.Hash import KMAC128, KMAC256
        except ImportError:
            self.skipTest("pycryptodome not installed")
        rnd = random.Random(2026)
        for i in range(300):
            key = rnd.randbytes(rnd.choice([32, 33, 64, 200]))   # pycryptodome requires keys of 256 bits or more
            data = rnd.randbytes(rnd.randrange(0, 600))
            custom = rnd.randbytes(rnd.randrange(0, 40))
            n = rnd.choice([16, 32, 64, 137, 300])
            for ours, theirs in ((kmac.kmac128, KMAC128), (kmac.kmac256, KMAC256)):
                ref = theirs.new(key=key, data=data, mac_len=n, custom=custom).digest()
                self.assertEqual(ours(key, data, n, custom), ref, (i, ours.__name__))


if __name__ == "__main__":
    unittest.main()
