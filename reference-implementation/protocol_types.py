"""Data containers shared by the classical and PQ packet modules."""

from __future__ import annotations

from dataclasses import dataclass

from certificates import DNSCryptCertificate

__all__ = [
    "DecryptedQuery",
    "PreparedQuery",
    "ResolverCertificate",
]


@dataclass(frozen=True)
class ResolverCertificate:
    """A certificate paired with the resolver secret needed to open queries."""

    certificate: DNSCryptCertificate
    resolver_sk: bytes


@dataclass(frozen=True)
class PreparedQuery:
    """A newly encrypted query and the state needed to decrypt its response.

    `client_pk` mirrors the wire `<client-pk>` slot: an X25519 public key for
    es-version 0x0002, an X-Wing ciphertext for 0x0003, or the resumption
    ticket in a resumed query.
    """

    dnscrypt_query: bytes
    shared_key: bytes
    client_pk: bytes
    client_nonce: bytes


@dataclass(frozen=True)
class DecryptedQuery:
    """A decrypted resolver-side query and its response-encryption state.

    `client_pk` mirrors the wire `<client-pk>` slot, as in `PreparedQuery`.
    """

    client_query: bytes
    shared_key: bytes
    client_pk: bytes
    client_nonce: bytes
    certificate: DNSCryptCertificate
