"""Small data containers shared across the reference implementation."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress

from certificates import DNSCryptCertificate


@dataclass(frozen=True)
class ResolverCertificate:
    """A certificate paired with the resolver secret needed to open queries."""

    certificate: DNSCryptCertificate
    resolver_sk: bytes


@dataclass(frozen=True)
class PreparedQuery:
    """A newly encrypted query and the state needed to decrypt its response."""

    dnscrypt_query: bytes
    shared_key: bytes
    client_pk: bytes
    client_nonce: bytes


@dataclass(frozen=True)
class DecryptedQuery:
    """A decrypted resolver-side query and its response-encryption state."""

    client_query: bytes
    shared_key: bytes
    client_pk: bytes
    client_nonce: bytes
    certificate: DNSCryptCertificate


@dataclass(frozen=True)
class AnonymizedDNSCryptQuery:
    """Parsed Anonymized DNSCrypt forwarding prefix and inner query."""

    server_ip: ipaddress.IPv6Address
    server_port: int
    dnscrypt_query: bytes


@dataclass(frozen=True)
class XWingKeyPair:
    """An X-Wing seed key pair represented by its seed and public key."""

    secret_seed: bytes
    public_key: bytes


@dataclass(frozen=True)
class XWingEncapsulation:
    """X-Wing encapsulation output: shared secret and ciphertext."""

    shared_secret: bytes
    ciphertext: bytes


@dataclass(frozen=True)
class TicketKey:
    """Server-wide key used to seal and open PQ resumption tickets."""

    ticket_key_id: bytes
    ticket_key: bytes


@dataclass(frozen=True)
class IssuedPQTicket:
    """A freshly issued ticket, its client resume secret, and control block."""

    resume_secret: bytes
    ticket: bytes
    control: bytes


@dataclass(frozen=True)
class PQDecryptedResponse:
    """A decrypted PQ response split into control data and DNS response."""

    control: bytes
    resolver_response: bytes


@dataclass(frozen=True)
class OpenedTicket:
    """Fields recovered from a valid PQ resumption ticket."""

    resume_secret: bytes
    es_version: bytes
    client_magic: bytes
    serial: int
    ts_end: int
    ticket_expiry: int
    profile_extension_hash: bytes
