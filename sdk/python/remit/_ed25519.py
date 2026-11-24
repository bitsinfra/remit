"""Ed25519 (RFC 8032). Uses `cryptography` when installed; otherwise a
compact pure-Python implementation of the RFC 8032 reference algorithm
(constant-time is NOT guaranteed — fine for signing remits on a trusted
Sender host; install `remit[fast]` for production)."""

import hashlib

try:  # pragma: no cover - exercised when cryptography is present
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives import serialization

    def public_key(seed: bytes) -> bytes:
        return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def sign(seed: bytes, msg: bytes) -> bytes:
        return Ed25519PrivateKey.from_private_bytes(seed).sign(msg)

    def verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
            return True
        except Exception:
            return False

    BACKEND = "cryptography"
except ImportError:
    BACKEND = "pure-python"
    p = 2**255 - 19
    L = 2**252 + 27742317777372353535851937790883648493
    d = -121665 * pow(121666, p - 2, p) % p
    I = pow(2, (p - 1) // 4, p)

    def _xrecover(y):
        xx = (y * y - 1) * pow(d * y * y + 1, p - 2, p)
        x = pow(xx, (p + 3) // 8, p)
        if (x * x - xx) % p != 0:
            x = x * I % p
        if x % 2 != 0:
            x = p - x
        return x

    By = 4 * pow(5, p - 2, p) % p
    Bx = _xrecover(By)
    B = (Bx, By, 1, Bx * By % p)

    def _add(P, Q):
        x1, y1, z1, t1 = P
        x2, y2, z2, t2 = Q
        a = (y1 - x1) * (y2 - x2) % p
        b = (y1 + x1) * (y2 + x2) % p
        c = t1 * 2 * d * t2 % p
        dd = z1 * 2 * z2 % p
        e, f, g, h = b - a, dd - c, dd + c, b + a
        return (e * f % p, g * h % p, f * g % p, e * h % p)

    def _mul(s, P):
        Q = (0, 1, 1, 0)
        while s > 0:
            if s & 1:
                Q = _add(Q, P)
            P = _add(P, P)
            s >>= 1
        return Q

    def _enc(P):
        x, y, z, _ = P
        zi = pow(z, p - 2, p)
        x, y = x * zi % p, y * zi % p
        return int.to_bytes(y | ((x & 1) << 255), 32, "little")

    def _dec(s):
        y = int.from_bytes(s, "little")
        sign = y >> 255
        y &= (1 << 255) - 1
        if y >= p:
            raise ValueError("bad point")
        x = _xrecover(y)
        if x & 1 != sign:
            x = p - x
        P = (x, y, 1, x * y % p)
        if (-x * x + y * y - 1 - d * x * x * y * y) % p != 0:
            raise ValueError("not on curve")
        return P

    def _expand(seed):
        h = hashlib.sha512(seed).digest()
        a = int.from_bytes(h[:32], "little")
        a &= (1 << 254) - 8
        a |= 1 << 254
        return a, h[32:]

    def public_key(seed: bytes) -> bytes:
        a, _ = _expand(seed)
        return _enc(_mul(a, B))

    def sign(seed: bytes, msg: bytes) -> bytes:
        a, prefix = _expand(seed)
        A = _enc(_mul(a, B))
        r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % L
        R = _enc(_mul(r, B))
        k = int.from_bytes(hashlib.sha512(R + A + msg).digest(), "little") % L
        return R + int.to_bytes((r + k * a) % L, 32, "little")

    def _eq(P, Q):
        x1, y1, z1, _ = P
        x2, y2, z2, _ = Q
        return (x1 * z2 - x2 * z1) % p == 0 and (y1 * z2 - y2 * z1) % p == 0

    def verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
        try:
            if len(sig) != 64:
                return False
            A = _dec(pk)
            R = _dec(sig[:32])
            s = int.from_bytes(sig[32:], "little")
            if s >= L:
                return False
            k = int.from_bytes(hashlib.sha512(sig[:32] + pk + msg).digest(), "little") % L
            return _eq(_mul(s, B), _add(R, _mul(k, A)))
        except ValueError:
            return False
