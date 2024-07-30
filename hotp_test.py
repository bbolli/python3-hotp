"""Tests for hotp.py"""

import unittest

from hotp import HOTP, TOTP, from_url


class TestHOTP(unittest.TestCase):

    def test_token(self) -> None:
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

    def test_count(self) -> None:
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

    @staticmethod
    def secret(size: int) -> bytes:
        mult = size // 10 + bool(size % 10)
        return (b'1234567890' * mult)[:size]

    def test_token_sha1(self) -> None:
        """Secret and test values from appendix B of RFC 6238."""
        t = TOTP(self.secret(20), digits=8)
        self.assertEqual('94287082', t.token(t.count(59)))
        self.assertEqual('07081804', t.token(t.count(1111111109)))
        self.assertEqual('14050471', t.token(t.count(1111111111)))
        self.assertEqual('89005924', t.token(t.count(1234567890)))
        self.assertEqual('69279037', t.token(t.count(2000000000)))
        self.assertEqual('65353130', t.token(t.count(20000000000)))

    def test_token_sha256(self) -> None:
        """Secret and test values from appendix B of RFC 6238."""
        t = TOTP(self.secret(32), digits=8, alg='sha256')
        self.assertEqual('46119246', t.token(t.count(59)))
        self.assertEqual('68084774', t.token(t.count(1111111109)))
        self.assertEqual('67062674', t.token(t.count(1111111111)))
        self.assertEqual('91819424', t.token(t.count(1234567890)))
        self.assertEqual('90698825', t.token(t.count(2000000000)))
        self.assertEqual('77737706', t.token(t.count(20000000000)))

    def test_token_sha512(self) -> None:
        """Secret and test values from appendix B of RFC 6238."""
        t = TOTP(self.secret(64), digits=8, alg='sha512')
        self.assertEqual('90693936', t.token(t.count(59)))
        self.assertEqual('25091201', t.token(t.count(1111111109)))
        self.assertEqual('99943326', t.token(t.count(1111111111)))
        self.assertEqual('93441116', t.token(t.count(1234567890)))
        self.assertEqual('38618901', t.token(t.count(2000000000)))
        self.assertEqual('47863826', t.token(t.count(20000000000)))

    def test_match(self) -> None:
        t = TOTP(b'12345678901234567890')
        self.assertFalse(t.match('287082', ts=90))
        self.assertTrue(t.match('287082', ts=60))
        self.assertTrue(t.match('359152', ts=60))
        self.assertTrue(t.match('969429', ts=60))
        self.assertFalse(t.match('969429', ts=30))


class TestFromURL(unittest.TestCase):

    def test_hotp_from_url(self) -> None:
        h = from_url('otpauth://hotp/ACME%20Co:john.doe@email.com?'
                     'secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&'
                     'algorithm=SHA1&digits=6&counter=1')
        self.assertEqual('HOTP(digits=6, alg=sha1)', repr(h))
        self.assertEqual(b'=\xc6\xca\xa4\x82Jm(\x87g\xb23\x1e \xb41f\xcb\x85\xd9', h.secret)
        self.assertEqual('ACME Co', h.issuer)
        self.assertEqual('john.doe@email.com', h.user_account)

    def test_totp_from_url(self) -> None:
        t = from_url('otpauth://totp/?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%26Co')
        self.assertEqual('TOTP(digits=6, alg=sha1, period=30)', repr(t))
        self.assertEqual('ACME&Co', t.issuer)
        self.assertEqual('', t.user_account)


class TestToURL(unittest.TestCase):

    def test_hotp_from_url(self) -> None:
        url = ('otpauth://hotp/ACME%20Co%3Ajohn.doe%40email.com?'
               'secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME+Co&'
               'algorithm=SHA256&counter=1')
        self.assertEqual(url, from_url(url).as_url())

    def test_totp_from_url(self) -> None:
        url = ('otpauth://totp/ACME%20Co%3Ajohn.doe%40email.com?'
               'secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME+Co&'
               'algorithm=SHA512&period=60')
        self.assertEqual(url, from_url(url).as_url())


if __name__ == '__main__':
    unittest.main()
