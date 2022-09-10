"""
Unit tests for the secp256k1 Koblitz 256-bit prime-order elliptic curve.
"""
import unittest

from Crypto.PublicKey import ECC
from Crypto.PublicKey.ECC import EccKey, EccPoint, _curves
from Crypto.SelfTest.st_common import list_test_cases


class TestEccKey_p256k1(unittest.TestCase):

    def test_private_key(self):
        key = EccKey(curve="p256k1", d=1)
        self.assertEqual(key.d, 1)
        self.assertTrue(key.has_private())
        self.assertEqual(key.pointQ.x, _curves['p256k1'].Gx)
        self.assertEqual(key.pointQ.y, _curves['p256k1'].Gy)

        point = EccPoint(_curves['p256k1'].Gx, _curves['p256k1'].Gy)
        key = EccKey(curve="p256k1", d=1, point=point)
        self.assertEqual(key.d, 1)
        self.assertTrue(key.has_private())
        self.assertEqual(key.pointQ, point)

        # Load via other names
        _ = EccKey(curve="prime256k1", d=1)
        _ = EccKey(curve="secp256k1", d=1)

        # Must not accept seed parameter
        self.assertRaises(ValueError, EccKey, curve="p256k1", seed=b'H'*32)

    def test_public_key(self):
        point = EccPoint(_curves['p256k1'].Gx, _curves['p256k1'].Gy)
        key = EccKey(curve="p256k1", point=point)
        self.assertFalse(key.has_private())
        self.assertEqual(key.pointQ, point)

    def test_public_key_derived(self):
        priv_key = EccKey(curve="p256k1", d=3)
        pub_key = priv_key.public_key()
        self.assertFalse(pub_key.has_private())
        self.assertEqual(priv_key.pointQ, pub_key.pointQ)

    def test_invalid_curve(self):
        self.assertRaises(ValueError, lambda: EccKey(curve="p257k1", d=1))

    def test_invalid_d(self):
        self.assertRaises(ValueError, lambda: EccKey(curve="p256k1", d=0))
        self.assertRaises(ValueError, lambda: EccKey(curve="p256k1", d=_curves['p256k1'].order))

    def test_equality(self):
        private_key = ECC.construct(d=3, curve="p256k1")
        private_key2 = ECC.construct(d=3, curve="p256k1")
        private_key3 = ECC.construct(d=4, curve="p256k1")

        public_key = private_key.public_key()
        public_key2 = private_key2.public_key()
        public_key3 = private_key3.public_key()

        self.assertEqual(private_key, private_key2)
        self.assertNotEqual(private_key, private_key3)

        self.assertEqual(public_key, public_key2)
        self.assertNotEqual(public_key, public_key3)

        self.assertNotEqual(public_key, private_key)


def get_tests(config={}):
    tests = []
    tests += list_test_cases(TestEccKey_p256k1)
    return tests


if __name__ == '__main__':
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')
