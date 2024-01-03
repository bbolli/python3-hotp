"""Tests for hotp.py"""

import unittest

from hotp import HOTP, TOTP, from_qr


class TestHOTP(unittest.TestCase):

    def test_token(self):
        """Secret and test values from appendix D of RFC 4226."""

        secret = b'12345678901234567890'
        h = HOTP(secret)
        self.assertEqual(h.token(0), '755224')
        self.assertEqual(h.token(1), '287082')
        self.assertEqual(h.token(2), '359152')
        self.assertEqual(h.token(3), '969429')
        self.assertEqual(h.token(4), '338314')
        self.assertEqual(h.token(5), '254676')
        self.assertEqual(h.token(6), '287922')
        self.assertEqual(h.token(7), '162583')
        self.assertEqual(h.token(8), '399871')
        self.assertEqual(h.token(9), '520489')

        # check for leading zeros
        self.assertEqual(HOTP(secret, digits=7, counter=4).token()[0], '0')


class TestTOTP(unittest.TestCase):

    def test_count(self):
        t = TOTP(b'')
        ts = 1400000010  # divisible by period
        base = t.count(ts)
        self.assertEqual(base, t.count(ts + 29))
        self.assertEqual(base + 1, t.count(ts + 30))
        self.assertEqual(base - 1, t.count(ts - 1))

        t = TOTP(b'', base=90)
        self.assertNotEqual(base, t.count(ts))
        self.assertEqual(base, t.count(ts + 90))

        t = TOTP(b'', period=60)
        self.assertNotEqual(base, t.count(ts + 90))
        self.assertNotEqual(base, t.count(ts))
        self.assertEqual(base, t.count(ts * 2))

    def test_match(self):
        t = TOTP(b'12345678901234567890')
        self.assertFalse(t.match('287082', ts=90))
        self.assertTrue(t.match('287082', ts=60))
        self.assertTrue(t.match('359152', ts=60))
        self.assertTrue(t.match('969429', ts=60))
        self.assertFalse(t.match('969429', ts=30))


class TestFromQR(unittest.TestCase):

    def test_hotp_from_qr(self):
        h = from_qr('otpauth://hotp/ACME%20Co:john.doe@email.com?'
                    'secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&'
                    'algorithm=SHA1&digits=6&counter=1')
        self.assertEqual('HOTP(digits=6, alg=sha1)', repr(h))
        self.assertEqual(b'=\xc6\xca\xa4\x82Jm(\x87g\xb23\x1e \xb41f\xcb\x85\xd9', h.secret)
        self.assertEqual('ACME Co', h.issuer)
        self.assertEqual('john.doe@email.com', h.user_account)

    def test_totp_from_qr(self):
        t = from_qr('otpauth://totp/ACME%20Co:john.doe@email.com?'
                    'secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=sha1')
        self.assertEqual('TOTP(digits=6, alg=sha1, period=30)', repr(t))


if __name__ == '__main__':
    unittest.main()