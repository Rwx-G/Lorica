"""The throwaway PKI of the AD CS harness and the DER the fixture needs.

A root and an issuing CA are generated at every fixture start, so no key
ever outlives a run. The issuing CA signs the fixture's own TLS
certificates (one under SHA-256, one under SHA-512, for IV2) and the
certificates it issues; the root is what clients trust.
"""

import datetime
import hashlib
import secrets
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CES_HOST = "ces.corp.example.org"

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_PKI_RESPONSE = "1.3.6.1.5.5.7.12.3"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"


def _key_usage(**granted):
    flags = dict.fromkeys(
        (
            "digital_signature",
            "content_commitment",
            "key_encipherment",
            "data_encipherment",
            "key_agreement",
            "key_cert_sign",
            "crl_sign",
            "encipher_only",
            "decipher_only",
        ),
        False,
    )
    flags.update(granted)
    return x509.KeyUsage(**flags)


# OpenSSL and webpki refuse a CA certificate without keyCertSign.
CA_KEY_USAGE = _key_usage(key_cert_sign=True, crl_sign=True)
LEAF_KEY_USAGE = _key_usage(digital_signature=True, key_encipherment=True)


def _name(common_name):
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Lorica Harness"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def _validity(builder, days):
    now = datetime.datetime.now(datetime.timezone.utc)
    return builder.not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(
        now + datetime.timedelta(days=days)
    )


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class HarnessPki:
    def __init__(self):
        self.root_key = _key()
        root_builder = (
            x509.CertificateBuilder()
            .subject_name(_name("Lorica Harness Root CA"))
            .issuer_name(_name("Lorica Harness Root CA"))
            .public_key(self.root_key.public_key())
            .serial_number(x509.random_serial_number())
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(CA_KEY_USAGE, critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self.root_key.public_key()),
                critical=False,
            )
        )
        self.root = _validity(root_builder, 30).sign(self.root_key, hashes.SHA256())

        self.issuing_key = _key()
        issuing_builder = (
            x509.CertificateBuilder()
            .subject_name(_name("Lorica Harness Issuing CA"))
            .issuer_name(self.root.subject)
            .public_key(self.issuing_key.public_key())
            .serial_number(x509.random_serial_number())
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(CA_KEY_USAGE, critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self.issuing_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.root_key.public_key()),
                critical=False,
            )
        )
        self.issuing = _validity(issuing_builder, 30).sign(self.root_key, hashes.SHA256())

    def issue(self, subject, public_key, sans, server_auth, hash_algorithm):
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.issuing.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(LEAF_KEY_USAGE, critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.issuing_key.public_key()
                ),
                critical=False,
            )
        )
        if sans:
            builder = builder.add_extension(sans, critical=False)
        if server_auth:
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
            )
        return _validity(builder, 1).sign(self.issuing_key, hash_algorithm)

    def server_identity(self, hash_algorithm, directory, stem):
        """A TLS key and certificate for CES_HOST, signed under
        `hash_algorithm`, written as PEM chain (leaf then issuing CA) and
        key. Returns (chain path, key path, leaf DER)."""
        key = _key()
        leaf = self.issue(
            _name(CES_HOST),
            key.public_key(),
            x509.SubjectAlternativeName([x509.DNSName(CES_HOST)]),
            True,
            hash_algorithm,
        )
        chain_path = Path(directory) / f"{stem}.chain.pem"
        key_path = Path(directory) / f"{stem}.key.pem"
        chain_path.write_bytes(
            leaf.public_bytes(serialization.Encoding.PEM)
            + self.issuing.public_bytes(serialization.Encoding.PEM)
        )
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        return chain_path, key_path, leaf.public_bytes(serialization.Encoding.DER)

    def write_public(self, directory):
        """The CA certificates clients and tests read. Written under
        temporary names and renamed: the healthcheck keys on root.pem."""
        for stem, cert in (("issuing", self.issuing), ("root", self.root)):
            path = Path(directory) / f"{stem}.pem"
            temporary = path.with_suffix(".pem.tmp")
            temporary.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            temporary.replace(path)

    def cmc_response(self, certificates):
        """A CMC Full PKI Response (RFC 5272) as CMS SignedData signed by
        the issuing CA, with `certificates` in the order given: MS-WSTEP
        4.1.1.2 sends them unordered, root included."""
        pki_response = seq(seq(), seq(), seq())
        encap = seq(oid(OID_PKI_RESPONSE), tlv(0xA0, octets(pki_response)))
        signed_attrs = seq(oid(OID_CONTENT_TYPE), set_of(oid(OID_PKI_RESPONSE))) + seq(
            oid(OID_MESSAGE_DIGEST), set_of(octets(hashlib.sha256(pki_response).digest()))
        )
        # RFC 5652 5.4: the signature covers the attributes encoded as an
        # explicit SET OF, not under their [0] IMPLICIT tag.
        signature = self.issuing_key.sign(
            tlv(0x31, signed_attrs), padding.PKCS1v15(), hashes.SHA256()
        )
        sid = seq(
            self.issuing.issuer.public_bytes(), integer(self.issuing.serial_number)
        )
        signer_info = seq(
            integer(1),
            sid,
            seq(oid(OID_SHA256), NULL),
            tlv(0xA0, signed_attrs),
            seq(oid(OID_RSA_ENCRYPTION), NULL),
            octets(signature),
        )
        der_certs = b"".join(
            cert.public_bytes(serialization.Encoding.DER) for cert in certificates
        )
        signed_data = seq(
            integer(3),
            set_of(seq(oid(OID_SHA256), NULL)),
            encap,
            tlv(0xA0, der_certs),
            set_of(signer_info),
        )
        return seq(oid(OID_SIGNED_DATA), tlv(0xA0, signed_data))


def tls_server_end_point(cert_der):
    """RFC 5929 4.1: the certificate's own signature hash, with MD5 and
    SHA-1 upgraded to SHA-256."""
    cert = x509.load_der_x509_certificate(cert_der)
    algorithm = cert.signature_hash_algorithm
    if algorithm is None or isinstance(algorithm, (hashes.MD5, hashes.SHA1)):
        algorithm = hashes.SHA256()
    digest = hashes.Hash(algorithm)
    digest.update(cert_der)
    return b"tls-server-end-point:" + digest.finalize()


def random_request_id():
    return str(secrets.randbelow(900000) + 100000)


# A minimal DER writer, enough for the CMC response.

NULL = b"\x05\x00"


def tlv(tag, content):
    length = len(content)
    if length < 0x80:
        encoded = bytes([length])
    else:
        raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
        encoded = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + encoded + content


def seq(*items):
    return tlv(0x30, b"".join(items))


def set_of(*items):
    return tlv(0x31, b"".join(items))


def octets(data):
    return tlv(0x04, data)


def integer(value):
    raw = value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big", signed=True)
    return tlv(0x02, raw)


def oid(dotted):
    arcs = [int(arc) for arc in dotted.split(".")]
    body = bytes([40 * arcs[0] + arcs[1]])
    for arc in arcs[2:]:
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7F))
            arc >>= 7
        body += bytes(reversed(chunk))
    return tlv(0x06, body)
