"""PQDNSCrypt and X-Wing helpers."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Sequence

from cryptography.hazmat.primitives.asymmetric import mlkem, x25519

from certificates import DNSCryptCertificate, parse_pq_profile_extension
from constants import (
    CLIENT_NONCE_SIZE,
    ES_VERSION_XWING,
    MIN_QUERY_PLAINTEXT_LEN,
    PADDING_BLOCK_SIZE,
    PQ_CONTROL_MAGIC,
    PQ_CONTROL_VERSION,
    RESUME_MAGIC,
    TAG_SIZE,
    TICKET_KEY_ID_SIZE,
    TICKET_NONCE_SIZE,
    TICKET_PLAIN_SIZE,
    XWING_CIPHERTEXT_SIZE,
    XWING_LABEL,
    XWING_MLKEM_CIPHERTEXT_SIZE,
    XWING_MLKEM_PUBLIC_KEY_SIZE,
    XWING_PUBLIC_KEY_SIZE,
)
from crypto import (
    hkdf_sha256,
    pad_7816_4,
    query_nonce,
    require_size,
    unpad_7816_4,
    xchacha20_djb_poly1305_open,
    xchacha20_djb_poly1305_seal,
)
from errors import CertificateError, DecryptionError
from packets import decrypt_dnscrypt_response, encrypt_dnscrypt_response
from protocol_types import DecryptedQuery, PreparedQuery
from transport import check_query_size

__all__ = [
    "IssuedPQTicket",
    "OpenedTicket",
    "PQDecryptedResponse",
    "TicketKey",
    "XWingEncapsulation",
    "XWingKeyPair",
    "decrypt_pq_dnscrypt_response",
    "decrypt_pq_resume_query",
    "encrypt_pq_dnscrypt_query",
    "encrypt_pq_dnscrypt_response",
    "encrypt_pq_resume_query",
    "issue_pq_ticket",
    "open_pq_ticket",
    "pq_cert_context",
    "pq_resume_secret",
    "pq_resumed_shared_key",
    "pq_shared_key",
    "profile_extension_hash",
    "xwing_decapsulate",
    "xwing_encapsulate",
    "xwing_generate_key_pair",
    "xwing_generate_key_pair_derand",
]


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


def _xwing_expand_decapsulation_key(secret_seed: bytes):
    require_size("secret_seed", secret_seed, 32)
    expanded = hashlib.shake_256(secret_seed).digest(96)
    mlkem_sk = mlkem.MLKEM768PrivateKey.from_seed_bytes(expanded[:64])
    x25519_sk = x25519.X25519PrivateKey.from_private_bytes(expanded[64:96])
    mlkem_pk = mlkem_sk.public_key().public_bytes_raw()
    x25519_pk = x25519_sk.public_key().public_bytes_raw()
    return mlkem_sk, x25519_sk, mlkem_pk, x25519_pk


def xwing_generate_key_pair_derand(secret_seed: bytes) -> XWingKeyPair:
    """Generate an X-Wing key pair from a 32-byte seed."""

    _, _, mlkem_pk, x25519_pk = _xwing_expand_decapsulation_key(secret_seed)
    return XWingKeyPair(secret_seed=secret_seed, public_key=mlkem_pk + x25519_pk)


def xwing_generate_key_pair() -> XWingKeyPair:
    """Generate a fresh X-Wing key pair."""

    return xwing_generate_key_pair_derand(os.urandom(32))


def _xwing_combiner(ss_m: bytes, ss_x: bytes, ct_x: bytes, pk_x: bytes) -> bytes:
    return hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + XWING_LABEL).digest()


def _x25519(sk: x25519.X25519PrivateKey, public_bytes: bytes) -> bytes:
    """RFC 7748 X25519 without the low-order rejection X-Wing forgoes.

    pyca refuses to return an all-zero shared point, but X-Wing relies on
    implicit rejection instead: a low-order point must yield a garbage shared
    secret so authentication fails with no distinguishable error or timing.
    """

    try:
        return sk.exchange(x25519.X25519PublicKey.from_public_bytes(public_bytes))
    except ValueError:
        return b"\x00" * 32


def xwing_encapsulate(public_key: bytes) -> XWingEncapsulation:
    """Encapsulate to an X-Wing public key using fresh randomness."""

    require_size("public_key", public_key, XWING_PUBLIC_KEY_SIZE)
    pk_m = public_key[:XWING_MLKEM_PUBLIC_KEY_SIZE]
    pk_x = public_key[XWING_MLKEM_PUBLIC_KEY_SIZE:]
    ss_m, ct_m = mlkem.MLKEM768PublicKey.from_public_bytes(pk_m).encapsulate()
    x_sk = x25519.X25519PrivateKey.generate()
    ct_x = x_sk.public_key().public_bytes_raw()
    ss_x = _x25519(x_sk, pk_x)
    return XWingEncapsulation(
        shared_secret=_xwing_combiner(ss_m, ss_x, ct_x, pk_x),
        ciphertext=ct_m + ct_x,
    )


def xwing_decapsulate(ciphertext: bytes, secret_seed: bytes) -> bytes:
    """Decapsulate an X-Wing ciphertext with a 32-byte resolver seed.

    Mirroring X-Wing `Decaps`, the key is re-expanded from the seed on every
    call; a production resolver would cache the expanded key.
    """

    require_size("ciphertext", ciphertext, XWING_CIPHERTEXT_SIZE)
    mlkem_sk, x_sk, _, pk_x = _xwing_expand_decapsulation_key(secret_seed)
    ct_m = ciphertext[:XWING_MLKEM_CIPHERTEXT_SIZE]
    ct_x = ciphertext[XWING_MLKEM_CIPHERTEXT_SIZE:]
    ss_m = mlkem_sk.decapsulate(ct_m)
    ss_x = _x25519(x_sk, ct_x)
    return _xwing_combiner(ss_m, ss_x, ct_x, pk_x)


def pq_cert_context(certificate: DNSCryptCertificate) -> bytes:
    """Build the PQ HKDF certificate context for a signed certificate."""

    return (
        b"DNSCrypt-PQ-v1"
        + certificate.es_version
        + certificate.protocol_minor_version
        + certificate.signed_data()
    )


def profile_extension_hash(certificate: DNSCryptCertificate) -> bytes:
    """Compute `<profile-extension-hash>`: SHA-256 of the extensions field."""

    return hashlib.sha256(certificate.extensions).digest()


def pq_shared_key(
    certificate: DNSCryptCertificate, kem_ss: bytes, client_kex: bytes
) -> bytes:
    """Derive PQDNSCrypt `<shared-key>` from X-Wing `<kem-ss>`.

    The PQ profile extension is validated at certificate acceptance, in
    `DNSCryptCertificate.verify` and `encrypt_pq_dnscrypt_query`, not here.
    """

    return hkdf_sha256(
        ikm=kem_ss,
        salt=certificate.es_version + certificate.client_magic,
        info=pq_cert_context(certificate) + client_kex,
        length=32,
    )


def encrypt_pq_dnscrypt_query(
    certificate: DNSCryptCertificate,
    client_query: bytes,
    client_nonce: bytes | None = None,
    min_plaintext_len: int = PADDING_BLOCK_SIZE,
) -> PreparedQuery:
    """Construct a PQ query carrying a full X-Wing ciphertext.

    The plaintext floor is one padding block because the 1120-byte ciphertext
    already makes the packet far larger than any anti-amplification target.
    """

    if certificate.es_version != ES_VERSION_XWING:
        raise CertificateError("encrypt_pq_dnscrypt_query expects es-version 0x0003")
    parse_pq_profile_extension(certificate.extensions, certificate.es_version)
    if client_nonce is None:
        client_nonce = os.urandom(CLIENT_NONCE_SIZE)
    require_size("client_nonce", client_nonce, CLIENT_NONCE_SIZE)
    encapsulation = xwing_encapsulate(certificate.resolver_pk)
    shared_key = pq_shared_key(
        certificate, encapsulation.shared_secret, encapsulation.ciphertext
    )
    plaintext = pad_7816_4(client_query, min_plaintext_len)
    encrypted_query = xchacha20_djb_poly1305_seal(
        shared_key, query_nonce(client_nonce), plaintext
    )
    dnscrypt_query = (
        certificate.client_magic
        + encapsulation.ciphertext
        + client_nonce
        + encrypted_query
    )
    check_query_size(dnscrypt_query)
    return PreparedQuery(
        dnscrypt_query=dnscrypt_query,
        shared_key=shared_key,
        client_pk=encapsulation.ciphertext,
        client_nonce=client_nonce,
    )


def pq_resume_secret(
    shared_key: bytes, client_magic: bytes, client_nonce: bytes
) -> bytes:
    """Derive the resumption secret after a full PQ query."""

    return hkdf_sha256(
        ikm=shared_key,
        salt=client_magic + client_nonce,
        info=b"DNSCrypt-PQ-resume-secret-v1",
        length=32,
    )


def issue_pq_ticket(
    certificate: DNSCryptCertificate,
    shared_key: bytes,
    client_nonce: bytes,
    ticket_key: TicketKey,
    ticket_nonce: bytes,
    ticket_expiry: int,
    ticket_lifetime: int,
) -> IssuedPQTicket:
    """Seal a stateless PQ resumption ticket and response control block.

    The caller sets `ticket_expiry` to the issuance time plus `ticket_lifetime`,
    so the advertised lifetime and the sealed expiry stay consistent; neither
    may run past the certificate expiry.
    """

    require_size("ticket_key_id", ticket_key.ticket_key_id, TICKET_KEY_ID_SIZE)
    require_size("ticket_key", ticket_key.ticket_key, 32)
    require_size("ticket_nonce", ticket_nonce, TICKET_NONCE_SIZE)
    if ticket_expiry > certificate.ts_end:
        raise ValueError("ticket_expiry must not exceed the certificate ts_end")
    resume_secret = pq_resume_secret(shared_key, certificate.client_magic, client_nonce)
    ticket_plain = (
        resume_secret
        + certificate.es_version
        + certificate.client_magic
        + certificate.serial.to_bytes(4, "big")
        + certificate.ts_end.to_bytes(4, "big")
        + ticket_expiry.to_bytes(4, "big")
        + profile_extension_hash(certificate)
    )
    assert len(ticket_plain) == TICKET_PLAIN_SIZE
    ticket = (
        ticket_key.ticket_key_id
        + ticket_nonce
        + xchacha20_djb_poly1305_seal(ticket_key.ticket_key, ticket_nonce, ticket_plain)
    )
    control = (
        PQ_CONTROL_MAGIC
        + bytes([PQ_CONTROL_VERSION])
        + ticket_lifetime.to_bytes(4, "big")
        + len(ticket).to_bytes(2, "big")
        + ticket
    )
    return IssuedPQTicket(resume_secret=resume_secret, ticket=ticket, control=control)


def encrypt_pq_dnscrypt_response(
    resolver_response: bytes,
    shared_key: bytes,
    client_nonce: bytes,
    resolver_nonce: bytes | None = None,
    control: bytes = b"",
    min_plaintext_len: int = PADDING_BLOCK_SIZE,
) -> bytes:
    """Construct a PQ response with `<control-len> <control>` in plaintext."""

    if len(control) > 0xFFFF:
        raise ValueError("control block is too large")
    plaintext = len(control).to_bytes(2, "big") + control + resolver_response
    return encrypt_dnscrypt_response(
        plaintext,
        shared_key,
        client_nonce,
        resolver_nonce=resolver_nonce,
        min_plaintext_len=min_plaintext_len,
    )


def decrypt_pq_dnscrypt_response(
    dnscrypt_response: bytes,
    shared_key: bytes,
    expected_client_nonce: bytes,
) -> PQDecryptedResponse:
    """Open a PQ response and split its control block from the DNS response."""

    plaintext = decrypt_dnscrypt_response(
        dnscrypt_response, shared_key, expected_client_nonce
    )
    if len(plaintext) < 2:
        raise DecryptionError("PQ response plaintext is too short")
    control_len = int.from_bytes(plaintext[:2], "big")
    if len(plaintext) < 2 + control_len:
        raise DecryptionError("PQ control block is truncated")
    return PQDecryptedResponse(
        control=plaintext[2 : 2 + control_len],
        resolver_response=plaintext[2 + control_len :],
    )


def pq_resumed_shared_key(
    resume_secret: bytes, client_magic: bytes, client_nonce: bytes, ticket: bytes
) -> bytes:
    """Derive the per-query key for a resumed PQ query."""

    return hkdf_sha256(
        ikm=resume_secret,
        salt=client_magic + client_nonce,
        info=b"DNSCrypt-PQ-resumed-query-v1" + hashlib.sha256(ticket).digest(),
        length=32,
    )


def encrypt_pq_resume_query(
    ticket: bytes,
    resume_secret: bytes,
    client_magic: bytes,
    client_query: bytes,
    client_nonce: bytes | None = None,
    min_plaintext_len: int = MIN_QUERY_PLAINTEXT_LEN,
) -> PreparedQuery:
    """Construct `<pq-resume-query>`.

    `client_magic` is the value from the certificate under which the ticket
    was issued; the client keeps it together with the ticket and the resume
    secret. A resumed query is small, so the plaintext floor defaults to 256
    bytes to keep the packet above the UDP query-size target.
    """

    if client_nonce is None:
        client_nonce = os.urandom(CLIENT_NONCE_SIZE)
    require_size("client_nonce", client_nonce, CLIENT_NONCE_SIZE)
    if len(ticket) > 0xFFFF:
        raise ValueError("ticket is too large")
    shared_key = pq_resumed_shared_key(resume_secret, client_magic, client_nonce, ticket)
    plaintext = pad_7816_4(client_query, min_plaintext_len)
    encrypted_query = xchacha20_djb_poly1305_seal(
        shared_key, query_nonce(client_nonce), plaintext
    )
    dnscrypt_query = (
        RESUME_MAGIC
        + len(ticket).to_bytes(2, "big")
        + ticket
        + client_nonce
        + encrypted_query
    )
    check_query_size(dnscrypt_query)
    return PreparedQuery(
        dnscrypt_query=dnscrypt_query,
        shared_key=shared_key,
        client_pk=ticket,
        client_nonce=client_nonce,
    )


def open_pq_ticket(
    ticket: bytes,
    ticket_keys: Sequence[TicketKey],
) -> OpenedTicket:
    """Open a PQ resumption ticket with one of the active ticket keys."""

    if len(ticket) < TICKET_KEY_ID_SIZE + TICKET_NONCE_SIZE + TAG_SIZE:
        raise DecryptionError("ticket is too short")
    ticket_key_id = ticket[:TICKET_KEY_ID_SIZE]
    ticket_nonce = ticket[TICKET_KEY_ID_SIZE : TICKET_KEY_ID_SIZE + TICKET_NONCE_SIZE]
    sealed = ticket[TICKET_KEY_ID_SIZE + TICKET_NONCE_SIZE :]
    match = next((tk for tk in ticket_keys if tk.ticket_key_id == ticket_key_id), None)
    if match is None:
        raise DecryptionError("unknown ticket-key-id")
    ticket_plain = xchacha20_djb_poly1305_open(match.ticket_key, ticket_nonce, sealed)
    if len(ticket_plain) != TICKET_PLAIN_SIZE:
        raise DecryptionError("ticket plaintext has an invalid length")
    return OpenedTicket(
        resume_secret=ticket_plain[:32],
        es_version=ticket_plain[32:34],
        client_magic=ticket_plain[34:42],
        serial=int.from_bytes(ticket_plain[42:46], "big"),
        ts_end=int.from_bytes(ticket_plain[46:50], "big"),
        ticket_expiry=int.from_bytes(ticket_plain[50:54], "big"),
        profile_extension_hash=ticket_plain[54:86],
    )


def _ticket_matches_certificate(
    opened_ticket: OpenedTicket, certificate: DNSCryptCertificate
) -> bool:
    return (
        opened_ticket.es_version == certificate.es_version
        and opened_ticket.client_magic == certificate.client_magic
        and opened_ticket.serial == certificate.serial
        and opened_ticket.ts_end == certificate.ts_end
        and opened_ticket.profile_extension_hash == profile_extension_hash(certificate)
    )


def decrypt_pq_resume_query(
    pq_resume_query: bytes,
    ticket_keys: Sequence[TicketKey],
    certificates: Sequence[DNSCryptCertificate],
    now: int,
) -> DecryptedQuery:
    """Open a resumed PQ query after validating its ticket context."""

    if not pq_resume_query.startswith(RESUME_MAGIC):
        raise DecryptionError("invalid resume magic")
    if len(pq_resume_query) < len(RESUME_MAGIC) + 2:
        raise DecryptionError("resume query is too short")
    ticket_len = int.from_bytes(
        pq_resume_query[len(RESUME_MAGIC) : len(RESUME_MAGIC) + 2], "big"
    )
    ticket_start = len(RESUME_MAGIC) + 2
    ticket_end = ticket_start + ticket_len
    header_len = ticket_end + CLIENT_NONCE_SIZE
    if len(pq_resume_query) < header_len + TAG_SIZE:
        raise DecryptionError("resume query is truncated")
    ticket = pq_resume_query[ticket_start:ticket_end]
    client_nonce = pq_resume_query[ticket_end:header_len]
    opened = open_pq_ticket(ticket, ticket_keys)
    if now > opened.ticket_expiry:
        raise DecryptionError("ticket is expired")
    certificate = next(
        (c for c in certificates if _ticket_matches_certificate(opened, c)),
        None,
    )
    if certificate is None:
        raise DecryptionError("ticket context does not match any certificate")
    if not certificate.ts_start <= now <= certificate.ts_end:
        raise DecryptionError("certificate for this ticket is no longer valid")
    shared_key = pq_resumed_shared_key(
        opened.resume_secret, opened.client_magic, client_nonce, ticket
    )
    plaintext = xchacha20_djb_poly1305_open(
        shared_key,
        query_nonce(client_nonce),
        pq_resume_query[header_len:],
    )
    return DecryptedQuery(
        client_query=unpad_7816_4(plaintext),
        shared_key=shared_key,
        client_pk=ticket,
        client_nonce=client_nonce,
        certificate=certificate,
    )
