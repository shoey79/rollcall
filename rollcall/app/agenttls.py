"""Built-in HTTPS for agents (1.93.0): Rollcall's own key and certificate, and agents that trust exactly that key.

No certificate to buy or install, and nothing in Windows' certificate store. Rollcall makes an EC P-256 key once
(kept in its data folder) and a self-signed certificate for it, and listens for agents over HTTPS on its own port
(8101 by default) beside plain HTTP on the agent port (8100), which stays on until an admin turns it off.

Agents check the server's public key itself (its SubjectPublicKeyInfo's SHA-256, "pinning"), not names or
certificate authorities, so a certificate for the right name from anyone else is refused. They learn the key's
fingerprint from the script they were downloaded with, or from Rollcall's reply signed with the update key they
already trust (updatesign.py), so the hand-over can't be changed on the way either. The router agent can't pin or
check signatures: it's given the certificate itself (uclient-fetch --ca-certificate), so the certificate lists the
addresses agents use (remade, same key, when a new one turns up).

Pinning the key, not the certificate, means the certificate can be remade (new addresses, or near its end in 25
years) without agents noticing.
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import ipaddress
import json
import os
import ssl
from pathlib import Path

# A P-256 public key's SubjectPublicKeyInfo is this header and then the 65-byte point (04 || X || Y). The Windows
# agent builds it the same way from the certificate's key, so all three sides hash the same bytes.
P256_SPKI_HEADER = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")
YEARS = 25


def tls_text(port: int, pin: str) -> bytes:
    """What's signed when Rollcall tells agents about its HTTPS port and key (agents build the same)."""
    return f"rollcall-agent-tls/1\nport={int(port)}\npin={pin}\n".encode()


class AgentTLS:
    def __init__(self, folder: Path):
        self.dir = Path(folder)
        self.key_path, self.cert_path, self.state_path = self.dir / "key.pem", self.dir / "cert.pem", self.dir / "state.json"
        self.ca_path = self.dir / "ca.pem"  # never reissued: what the router agent trusts (review F1)
        self.state = {"https": False, "plain_http": True}
        try:
            self.state.update(json.loads(self.state_path.read_text()))
        except (OSError, ValueError):
            pass
        self._key = None
        self._pin = None

    # -- settings ----------------------------------------------------------------
    @property
    def on(self) -> bool:
        return bool(self.state.get("https"))

    @property
    def plain_http(self) -> bool:
        return not self.on or bool(self.state.get("plain_http", True))

    def set(self, **kw) -> None:
        self.state.update(kw)
        self.dir.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.state))
        os.replace(tmp, self.state_path)

    def decided(self) -> bool:
        return self.state_path.exists()

    # -- key and certificate -------------------------------------------------------
    def key(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        if self._key is None:
            if self.key_path.exists():
                self._key = serialization.load_pem_private_key(self.key_path.read_bytes(), password=None)
            else:
                k = ec.generate_private_key(ec.SECP256R1())
                self.dir.mkdir(parents=True, exist_ok=True)
                fd = os.open(self.key_path.with_suffix(".tmp"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "wb") as f:
                    f.write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
                os.replace(self.key_path.with_suffix(".tmp"), self.key_path)
                self._key = k
        return self._key

    def pin(self) -> str:
        """base64 SHA-256 of the key's SubjectPublicKeyInfo: what agents check."""
        from cryptography.hazmat.primitives import serialization
        if self._pin is None:
            spki = self.key().public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            assert spki.startswith(P256_SPKI_HEADER) and len(spki) == len(P256_SPKI_HEADER) + 65
            self._pin = base64.b64encode(hashlib.sha256(spki).digest()).decode()
        return self._pin

    def names(self) -> list[str]:
        """The addresses the certificate lists now."""
        from cryptography import x509
        try:
            cert = x509.load_pem_x509_certificate(self.cert_path.read_bytes())
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            return sorted({str(n.value) for n in san})
        except Exception:  # noqa: BLE001
            return []

    def ensure_cert(self, hosts) -> bool:
        """A certificate for the key that lists these hosts (and what it already listed). True if it was (re)made."""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.x509.oid import NameOID
        want = {"localhost", "127.0.0.1"} | {str(h).strip().lower().strip("[]") for h in hosts if str(h).strip()}
        have = set(self.names())
        ca = self.ensure_ca()
        if self.cert_path.exists() and want <= have and self._issued_by_ca():
            return False
        names = sorted(want | have)[:100]
        sans = []
        for n in names:
            try:
                ip = ipaddress.ip_address(n)
                sans.append(x509.IPAddress(ip))
                if ip.version == 4:
                    sans.append(x509.DNSName(n))  # some TLS libraries (the router's) only compare names
            except ValueError:
                if all(c.isalnum() or c in "-." for c in n):
                    sans.append(x509.DNSName(n))
        now = datetime.datetime.now(datetime.timezone.utc)
        # The certificate Rollcall serves: its names, issued by its own authority (same key, so agents that pin the
        # key see no change), and sent with the authority so the router agent can check it against the one it trusts
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Rollcall agents")])
        pub = self.key().public_key()
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(ca.subject).public_key(pub)
                .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(min(now + datetime.timedelta(days=365 * YEARS), getattr(ca, "not_valid_after_utc", None) or ca.not_valid_after.replace(tzinfo=datetime.timezone.utc)))
                .add_extension(x509.SubjectAlternativeName(list(dict.fromkeys(sans))), critical=False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(pub), critical=False)
                .sign(self.key(), hashes.SHA256()))
        tmp = self.cert_path.with_suffix(".tmp")
        tmp.write_bytes(cert.public_bytes(serialization.Encoding.PEM) + self.ca_path.read_bytes())
        os.replace(tmp, self.cert_path)
        return True

    def ensure_ca(self):
        """Rollcall's own certificate authority for agent HTTPS: made once with the same key and never reissued, so a
        router agent that trusts it never needs a new one (review F1). Lasts 25 years."""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.x509.oid import NameOID
        if self.ca_path.exists():
            try:
                return x509.load_pem_x509_certificate(self.ca_path.read_bytes())
            except ValueError:
                pass
        now = datetime.datetime.now(datetime.timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Rollcall agents CA")])
        pub = self.key().public_key()
        ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(pub)
              .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
              .not_valid_after(now + datetime.timedelta(days=365 * 25))
              .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
              .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                           key_encipherment=False, data_encipherment=False, key_agreement=False,
                                           encipher_only=False, decipher_only=False), critical=True)
              .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
              .sign(self.key(), hashes.SHA256()))
        self.dir.mkdir(parents=True, exist_ok=True)
        tmp = self.ca_path.with_suffix(".tmp")
        tmp.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        os.replace(tmp, self.ca_path)
        return ca

    def _issued_by_ca(self) -> bool:
        """False for a certificate from before 1.99 (self-signed, no authority): it's remade once."""
        from cryptography import x509
        try:
            cert = x509.load_pem_x509_certificate(self.cert_path.read_bytes())
            return cert.issuer != cert.subject
        except (OSError, ValueError):
            return False

    def cert_pem(self) -> str:
        """What the router agent trusts: the authority, which never changes (not the served certificate, which does)."""
        try:
            return self.ca_path.read_text() if self.ca_path.exists() else ""
        except OSError:
            return ""

    def context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(self.cert_path, self.key_path)
        return ctx


def spki_pin_from_der(der: bytes) -> str:
    """What the Linux agent does: the SubjectPublicKeyInfo out of a DER certificate, hashed (standard library only)."""
    def tlv(b, i):
        tag, ln = b[i], b[i + 1]
        i += 2
        if ln & 0x80:
            n = ln & 0x7F
            ln = int.from_bytes(b[i:i + n], "big")
            i += n
        return tag, i, i + ln
    _, i, _ = tlv(der, 0)          # Certificate
    _, j, _ = tlv(der, i)          # tbsCertificate
    k = j
    fields = []
    while len(fields) < 7:
        tag, s, e = tlv(der, k)
        fields.append((tag, k, e))
        k = e
    if fields[0][0] != 0xA0:       # no [0] version: SPKI is the 6th field, not the 7th
        fields = fields[:6]
    _, start, end = fields[-1]
    return base64.b64encode(hashlib.sha256(der[start:end]).digest()).decode()
