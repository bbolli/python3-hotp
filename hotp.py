"""HOTP/TOTP one time password (RFC 4226/RFC 6238) implementation"""

import base64
import hmac
import struct
import time
from typing import Optional, Type
import urllib.parse


__all__ = ['HOTP', 'TOTP', 'from_qr', 'default_alg']

default_alg = 'sha1'


class HOTP:
    secret: bytes
    alg: str
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
        return f'HOTP(digits={self.digits}, alg={self.alg.lower()})'

    def token(self, counter: Optional[int] = None) -> str:
        """Calculate the HOTP value for the given counter."""
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

    def to_qr(self) -> str:
        netloc = self.__class__.__name__.lower()
        params = {'secret': base64.b32encode(self.secret).rstrip(b'=')}
        if self.issuer:
            path = f'{self.issuer}:{self.user_account}'
            params['issuer'] = self.issuer
        else:
            path = self.user_account
        path = urllib.parse.quote(path)
        if self.alg != default_alg:
            params['algorithm'] = self.alg.upper()
        if self.digits != 6:
            params['digits'] = self.digits
        if self.__class__ is HOTP:
            params['counter'] = self.counter
        if self.__class__ is TOTP and self.period != 30:
            params['period'] = self.period
        query = urllib.parse.urlencode(params)
        return urllib.parse.urlunparse(('otpauth', netloc, path, None, query, None))


class TOTP(HOTP):
    period: int
    base: int

    def __init__(self, secret, digits=6, alg=default_alg, period=30, base=0):
        super().__init__(secret, digits, alg)
        self.period = period
        self.base = base

    def __repr__(self) -> str:
        return f'TOTP(digits={self.digits}, alg={self.alg.lower()}, period={self.period})'

    def count(self, ts: float) -> int:
        """Calculate the TOTP counter for a given timestamp."""
        return (int(ts) - self.base) // self.period

    def match(self, token: str, *, fuzz: Optional[int] = 1, ts: Optional[float] = None) -> bool:
        """Return true if the TOTP token matches around the given timestamp.
        `fuzz` is the number of periods on each side of `ts` that are checked
        for a match."""
        ctr = self.count(ts or time.time())
        return any(token == self.token(ctr + f) for f in range(-fuzz, fuzz + 1))


def from_qr(qr: str) -> HOTP:
    """Decode a HOTP or TOTP QR code URL into the appropriate object."""
    url = urllib.parse.urlparse(qr)
    if url.scheme != 'otpauth':
        raise ValueError(f'invalid scheme "{url.scheme}"')
    query = urllib.parse.parse_qs(url.query)
    for k in query:
        query[k] = query[k][0]
    secret = base64.b32decode(query['secret'])
    alg = query.get('algorithm', 'sha1')
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
    elif len(path) == 1 and path[0]:
        hotp.user_account = path[0].strip()
    else:
        hotp.issuer = query.get('issuer')
    return hotp
