"""DNSCrypt certificate parsing, signing, and selection."""

from __future__ import annotations

import struct
from dataclasses import dataclass, replace
from typing import Iterable, Sequence

from constants import (
    AEAD_ID_XCHACHA20_DJB_POLY1305,
    CERT_MAGIC,
    CLIENT_MAGIC_SIZE,
    ES_VERSION_XCHACHA20POLY1305,
    ES_VERSION_XWING,
    KDF_ID_HKDF_SHA256,
    PQ_PROFILE_EXTENSION_MAGIC,
    PQ_PROFILE_EXTENSION_VERSION,
    PROTOCOL_MINOR_VERSION,
    PUBLIC_KEY_SIZE,
    RESUME_MAGIC,
    SIGNATURE_SIZE,
    XWING_CIPHERTEXT_SIZE,
    XWING_PUBLIC_KEY_SIZE,
)
from crypto import ed25519_sign, ed25519_verify, require_size
from errors import CertificateError

__all__ = [
    "DNSCryptCertificate",
    "PQProfileExtension",
    "choose_certificate",
    "client_pk_len_for_es_version",
    "parse_pq_profile_extension",
    "pq_profile_extension",
    "resolver_pk_len_for_es_version",
]


def resolver_pk_len_for_es_version(es_version: bytes) -> int:
    """Return the certificate `<resolver-pk>` length for an encryption system."""

    if es_version == ES_VERSION_XCHACHA20POLY1305:
        return PUBLIC_KEY_SIZE
    if es_version == ES_VERSION_XWING:
        return XWING_PUBLIC_KEY_SIZE
    raise CertificateError(f"unsupported es-version: {es_version.hex()}")


def client_pk_len_for_es_version(es_version: bytes) -> int:
    """Return the query `<client-pk>` length for an encryption system."""

    if es_version == ES_VERSION_XCHACHA20POLY1305:
        return PUBLIC_KEY_SIZE
    if es_version == ES_VERSION_XWING:
        return XWING_CIPHERTEXT_SIZE
    raise CertificateError(f"unsupported es-version: {es_version.hex()}")


@dataclass(frozen=True)
class PQProfileExtension:
    """Parsed fields of the signed PQ profile extension."""

    ext_version: int
    es_version: bytes
    kdf_id: int
    aead_id: int
    resolver_pk_len: int
    client_kex_len: int


def pq_profile_extension(
    es_version: bytes = ES_VERSION_XWING,
    resolver_pk_len: int = XWING_PUBLIC_KEY_SIZE,
    client_kex_len: int = XWING_CIPHERTEXT_SIZE,
) -> bytes:
    """Build the signed 12-byte PQ profile extension."""

    require_size("es_version", es_version, 2)
    return (
        PQ_PROFILE_EXTENSION_MAGIC
        + bytes([PQ_PROFILE_EXTENSION_VERSION])
        + es_version
        + bytes([KDF_ID_HKDF_SHA256, AEAD_ID_XCHACHA20_DJB_POLY1305])
        + resolver_pk_len.to_bytes(2, "big")
        + client_kex_len.to_bytes(2, "big")
    )


def parse_pq_profile_extension(
    extensions: bytes, expected_es_version: bytes = ES_VERSION_XWING
) -> PQProfileExtension:
    """Parse and validate the signed PQ profile extension."""

    if len(extensions) != 12:
        raise CertificateError("PQ profile extension must be 12 bytes")
    if extensions[:3] != PQ_PROFILE_EXTENSION_MAGIC:
        raise CertificateError("PQ profile extension magic is invalid")
    parsed = PQProfileExtension(
        ext_version=extensions[3],
        es_version=extensions[4:6],
        kdf_id=extensions[6],
        aead_id=extensions[7],
        resolver_pk_len=int.from_bytes(extensions[8:10], "big"),
        client_kex_len=int.from_bytes(extensions[10:12], "big"),
    )
    if parsed.ext_version != PQ_PROFILE_EXTENSION_VERSION:
        raise CertificateError("unsupported PQ profile extension version")
    if parsed.es_version != expected_es_version:
        raise CertificateError("PQ extension es-version does not match certificate")
    if parsed.kdf_id != KDF_ID_HKDF_SHA256:
        raise CertificateError("unsupported PQ KDF")
    if parsed.aead_id != AEAD_ID_XCHACHA20_DJB_POLY1305:
        raise CertificateError("unsupported PQ AEAD")
    if parsed.resolver_pk_len != resolver_pk_len_for_es_version(expected_es_version):
        raise CertificateError("PQ resolver-pk length mismatch")
    if parsed.client_kex_len != client_pk_len_for_es_version(expected_es_version):
        raise CertificateError("PQ client-kex length mismatch")
    return parsed


@dataclass(frozen=True)
class DNSCryptCertificate:
    """DNSCrypt certificate fields after parsing."""

    es_version: bytes
    protocol_minor_version: bytes
    signature: bytes
    resolver_pk: bytes
    client_magic: bytes
    serial: int
    ts_start: int
    ts_end: int
    extensions: bytes = b""

    def signed_data(self) -> bytes:
        """Return the byte string covered by the Ed25519 signature."""

        return (
            self.resolver_pk
            + self.client_magic
            + self.serial.to_bytes(4, "big")
            + self.ts_start.to_bytes(4, "big")
            + self.ts_end.to_bytes(4, "big")
            + self.extensions
        )

    def to_bytes(self) -> bytes:
        """Serialize the certificate as it appears in a TXT record."""

        return (
            CERT_MAGIC
            + self.es_version
            + self.protocol_minor_version
            + self.signature
            + self.signed_data()
        )

    def verify(self, provider_public_key: bytes) -> None:
        """Verify the signature, validity interval shape, and PQ extension."""

        ed25519_verify(provider_public_key, self.signature, self.signed_data())
        if self.ts_start >= self.ts_end:
            raise CertificateError("certificate validity start must precede end")
        if self.es_version == ES_VERSION_XWING:
            parse_pq_profile_extension(self.extensions, self.es_version)

    @classmethod
    def sign(
        cls,
        provider_signing_seed: bytes,
        es_version: bytes,
        resolver_pk: bytes,
        client_magic: bytes,
        serial: int,
        ts_start: int,
        ts_end: int,
        extensions: bytes = b"",
        protocol_minor_version: bytes = PROTOCOL_MINOR_VERSION,
    ) -> "DNSCryptCertificate":
        """Create and sign a DNSCrypt certificate."""

        require_size("es_version", es_version, 2)
        require_size("protocol_minor_version", protocol_minor_version, 2)
        require_size("client_magic", client_magic, CLIENT_MAGIC_SIZE)
        if client_magic.startswith(b"\x00" * 7):
            raise CertificateError("client-magic must not start with 7 zero bytes")
        if client_magic == RESUME_MAGIC:
            raise CertificateError("client-magic must not equal the resume magic")
        if len(resolver_pk) != resolver_pk_len_for_es_version(es_version):
            raise CertificateError("resolver-pk length does not match es-version")
        unsigned = cls(
            es_version=es_version,
            protocol_minor_version=protocol_minor_version,
            signature=b"\x00" * SIGNATURE_SIZE,
            resolver_pk=resolver_pk,
            client_magic=client_magic,
            serial=serial,
            ts_start=ts_start,
            ts_end=ts_end,
            extensions=extensions,
        )
        signature = ed25519_sign(provider_signing_seed, unsigned.signed_data())
        return replace(unsigned, signature=signature)

    @classmethod
    def from_bytes(cls, certificate: bytes) -> "DNSCryptCertificate":
        """Parse a DNSCrypt certificate from its wire bytes."""

        resolver_pk_start = len(CERT_MAGIC) + 2 + 2 + SIGNATURE_SIZE
        if len(certificate) < resolver_pk_start:
            raise CertificateError("certificate is too short")
        if certificate[: len(CERT_MAGIC)] != CERT_MAGIC:
            raise CertificateError("invalid certificate magic")
        es_version = certificate[4:6]
        protocol_minor_version = certificate[6:8]
        signature = certificate[8:resolver_pk_start]
        resolver_pk_len = resolver_pk_len_for_es_version(es_version)
        tail_start = resolver_pk_start + resolver_pk_len
        tail_format = f">{CLIENT_MAGIC_SIZE}sIII"
        tail_end = tail_start + struct.calcsize(tail_format)
        if len(certificate) < tail_end:
            raise CertificateError("certificate is truncated")
        resolver_pk = certificate[resolver_pk_start:tail_start]
        client_magic, serial, ts_start, ts_end = struct.unpack(
            tail_format, certificate[tail_start:tail_end]
        )
        return cls(
            es_version=es_version,
            protocol_minor_version=protocol_minor_version,
            signature=signature,
            resolver_pk=resolver_pk,
            client_magic=client_magic,
            serial=serial,
            ts_start=ts_start,
            ts_end=ts_end,
            extensions=certificate[tail_end:],
        )


def choose_certificate(
    certificates: Iterable[DNSCryptCertificate],
    provider_public_key: bytes,
    now: int,
    supported_es_versions: Sequence[bytes] = (
        ES_VERSION_XCHACHA20POLY1305,
        ES_VERSION_XWING,
    ),
) -> DNSCryptCertificate:
    """Choose the valid certificate with the highest serial number.

    Certificates that are unsupported, invalid, or outside their validity
    window are skipped, never fatal: one bad record in a response must not
    prevent the client from using a valid one. Profile pinning, such as a
    PQ-only policy, is expressed through `supported_es_versions`.
    """

    usable = []
    for certificate in certificates:
        if certificate.es_version not in supported_es_versions:
            continue
        try:
            certificate.verify(provider_public_key)
        except CertificateError:
            continue
        if certificate.ts_start <= now <= certificate.ts_end:
            usable.append(certificate)
    if not usable:
        raise CertificateError("no usable certificate")
    return max(usable, key=lambda c: c.serial)
