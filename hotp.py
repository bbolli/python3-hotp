"""HOTP/TOTP one time password (RFC 4226/RFC 6238) implementation"""

import base64
import hashlib
import hmac
import struct
import time
from typing import Optional, Type
import urllib.parse


__all__ = ['HOTP', 'TOTP', 'from_qr', 'default_alg']

default_alg = hashlib.sha1


class HOTP:
    secret: bytes
    alg: 'Type[hashlib._Hash]'
    digits: int
    counter: int
    issuer: Optional[str]
    user_account: Optional[str]

    def __init__(self, secret: bytes, digits: int = 6, alg=default_alg, counter: int = 0):
        self.secret = secret
        self.digits = digits
        self.alg = alg
        self.counter = counter
        self.issuer = self.user_account = None

    def __repr__(self) -> str:
        return f'HOTP(digits={self.digits}, alg={self.alg.name})'

    def token(self, counter: Optional[int] = None) -> str:
        """Calculate the HOTP value for the given counter.

        Secret and test values from appendix D of RFC 4226.

        >>> s = b'12345678901234567890'
        >>> h = HOTP(s)
        >>> [h.token(n) for n in range(10)]  #doctest: +NORMALIZE_WHITESPACE
        ['755224', '287082', '359152', '969429', '338314',
         '254676', '287922', '162583', '399871', '520489']
        >>> HOTP(s, digits=7, counter=4).token()[0]  # check for leading zeros
        '0'
        """
        if counter is None:
            counter = self.counter
        if counter < 0:
            raise ValueError("HOTP counter must be non-negative")
        counter = struct.pack('>Q', counter)
        digest = hmac.new(self.secret, counter, self.alg).digest()
        offset = digest[-1] & 0x0F
        result = digest[offset:offset + 4]
        result = struct.unpack('>L', result)[0] & 0x7FFFFFFF
        result %= 10 ** self.digits
        return f'{result:0{self.digits}}'


class TOTP(HOTP):
    period: int
    base: int

    def __init__(self, secret, digits=6, alg=default_alg, period=30, base=0):
        super().__init__(secret, digits, alg)
        self.period = period
        self.base = base

    def __repr__(self) -> str:
        return f'TOTP(digits={self.digits}, alg={self.alg.name}, period={self.period})'

    def count(self, ts: float) -> int:
        """Calculate the TOTP counter for a given timestamp.

        >>> t = TOTP(b'')
        >>> ts = 1400000010  # divisible by period
        >>> base = t.count(ts)
        >>> base == t.count(ts + 29)
        True
        >>> base + 1 == t.count(ts + 30)
        True
        >>> base - 1 == t.count(ts - 1)
        True
        >>> t = TOTP(b'', base=90)
        >>> base == t.count(ts)
        False
        >>> base == t.count(ts + 90)
        True
        >>> t = TOTP(b'', period=60)
        >>> base == t.count(ts)
        False
        >>> base == t.count(ts * 2)
        True
        """
        return (int(ts) - self.base) // self.period

    def match(self, token: str, *, fuzz: Optional[int] = 1, ts: Optional[float] = None) -> bool:
        """Return true if the TOTP token matches around the given timestamp.
        `fuzz` is the number of periods on each side of `ts` that are checked
        for a match.

        >>> s = b'12345678901234567890'
        >>> t = TOTP(s)
        >>> t.match('287082', ts=90)
        False
        >>> t.match('287082', ts=60)
        True
        >>> t.match('359152', ts=60)
        True
        >>> t.match('969429', ts=60)
        True
        >>> t.match('969429', ts=30)
        False
        """
        ctr = self.count(ts or time.time())
        return any(token == self.token(ctr + f) for f in range(-fuzz, fuzz + 1))


def from_qr(qr: str) -> HOTP:
    """Decode a HOTP or TOTP QR code URL into the appropriate object.

    >>> t = from_qr('otpauth://hotp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&counter=1')
    >>> t
    HOTP(digits=6, alg=sha1)
    >>> t.secret
    b'=\\xc6\\xca\\xa4\\x82Jm(\\x87g\\xb23\\x1e \\xb41f\\xcb\\x85\\xd9'
    >>> t.issuer
    'ACME Co'
    >>> t.user_account
    'john.doe@email.com'
    >>> t = from_qr('otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30')
    >>> t
    TOTP(digits=6, alg=sha1, period=30)
    """

    url = urllib.parse.urlparse(qr)
    if url.scheme != 'otpauth':
        raise ValueError(f'invalid scheme "{url.scheme}"')
    query = urllib.parse.parse_qs(url.query)
    for k in query:
        query[k] = query[k][0]
    secret = base64.b32decode(query['secret'])
    alg = hashlib.new(query.get('algorithm', 'sha1'))
    digits = int(query.get('digits', 6))
    if url.netloc == 'hotp':
        hotp = HOTP(secret, digits, alg, int(query['counter']))
    elif url.netloc == 'totp':
        hotp = TOTP(secret, digits, alg, int(query.get('period', 30)))
    else:
        raise ValueError(f'invalid protocol "{url.netloc}"')
    path = urllib.parse.unquote(url.path.lstrip('/')).split(':')
    if len(path) == 2:
        hotp.issuer = path[0]
        hotp.user_account = path[1].strip()
    elif len(path) == 1:
        hotp.user_account = path[0].strip()
    else:
        hotp.issuer = query.get('issuer')
    return hotp
