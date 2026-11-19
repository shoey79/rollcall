"""Rollcall's own signing key, for what agents must be able to trust even over plain HTTP: agent updates, and the
addresses agents are told to report to.

Before 1.92.1, updates were signed with an HMAC keyed by the agent's token. The token goes with every report, so
anyone able to read and change plain-HTTP traffic could capture it and sign an update of their own. Now Rollcall
signs with an RSA key that never leaves it; agents carry only the public half (built into the script when it's
downloaded), so a captured token is no help.

Signatures are RSASSA-PKCS1-v1_5 with SHA-256. Agents check them with plain modular arithmetic (Windows
PowerShell 5.1 has BigInteger; Python has pow()), by building the whole expected padded block and comparing it
byte for byte, the way RFC 8017 recommends: nothing is parsed, so there's nothing to trick. verify() below does
exactly what the agents do, so the tests check one against the other.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
from pathlib import Path

E = 65537
BITS = 3072
# DER DigestInfo prefix for SHA-256 (RFC 8017, section 9.2)
SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
CONFIG_HEADER = "rollcall-agent-config/1"


class SigningKey:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._key = None

    def _load(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        if self._key is not None:
            return self._key
        if self.path.exists():
            self._key = serialization.load_pem_private_key(self.path.read_bytes(), password=None)
        else:
            key = rsa.generate_private_key(public_exponent=E, key_size=BITS)
            pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(pem)
            os.replace(tmp, self.path)
            self._key = key
        return self._key

    def reload(self) -> None:
        """After an import replaced the key file."""
        self._key = None

    def public(self) -> str:
        """The modulus, big-endian, base64: what's built into agent scripts (the exponent is always 65537)."""
        n = self._load().public_key().public_numbers().n
        return base64.b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).decode()

    def fingerprint(self) -> str:
        """A short id for the key, for the log and Details: SHA-256 of the modulus, first 16 hex digits."""
        return hashlib.sha256(base64.b64decode(self.public())).hexdigest()[:16]

    def sign(self, data: bytes) -> str:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        return base64.b64encode(self._load().sign(data, padding.PKCS1v15(), hashes.SHA256())).decode()


def config_text(servers, route) -> bytes:
    """The addresses an agent is told to use, as the exact text that's signed. Agents build the same text from
    the same values in Rollcall's reply."""
    servers = [str(s) for s in servers or []]
    r = route or None
    rt = "" if not r else "|".join([str(r.get("inside") or ""), str(r.get("outside") or ""), ",".join(str(n) for n in r.get("networks") or [])])
    return f"{CONFIG_HEADER}\nservers={','.join(servers)}\nroute={rt}\n".encode("utf-8")


def verify(public_b64: str, data: bytes, sig_b64: str) -> bool:
    """What the agents do: s^e mod n, compared with the whole expected PKCS#1 v1.5 block."""
    try:
        nb = base64.b64decode(public_b64, validate=True)
        sig = base64.b64decode(sig_b64, validate=True)
    except (ValueError, TypeError):
        return False
    n = int.from_bytes(nb, "big")
    k = (n.bit_length() + 7) // 8
    if k < 256 or len(sig) != k:
        return False
    s = int.from_bytes(sig, "big")
    if s >= n:
        return False
    m = pow(s, E, n).to_bytes(k, "big")
    t = SHA256_PREFIX + hashlib.sha256(data).digest()
    expected = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return hmac.compare_digest(m, expected)
