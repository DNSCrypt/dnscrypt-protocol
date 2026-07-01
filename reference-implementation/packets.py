"""Regular DNSCrypt query and response packet construction."""

from __future__ import annotations

import os
from typing import Sequence

from certificates import DNSCryptCertificate, client_pk_len_for_es_version
from constants import (
    CLIENT_MAGIC_SIZE,
    CLIENT_NONCE_SIZE,
    ES_VERSION_XCHACHA20POLY1305,
    MIN_QUERY_PLAINTEXT_LEN,
    NONCE_SIZE,
    PADDING_BLOCK_SIZE,
    RESOLVER_MAGIC,
    RESOLVER_NONCE_SIZE,
    TAG_SIZE,
)
from crypto import (
    box_xchacha20_shared_key,
    pad_7816_4,
    query_nonce,
    require_size,
    unpad_7816_4,
    x25519_public_key,
    xchacha20_djb_poly1305_open,
    xchacha20_djb_poly1305_seal,
)
from errors import CertificateError, DecryptionError
from protocol_types import DecryptedQuery, PreparedQuery, ResolverCertificate
from transport import check_query_size, check_response_size

__all__ = [
    "decrypt_dnscrypt_query",
    "decrypt_dnscrypt_response",
    "encrypt_dnscrypt_query",
    "encrypt_dnscrypt_response",
]


def encrypt_dnscrypt_query(
    certificate: DNSCryptCertificate,
    client_sk: bytes,
    client_query: bytes,
    client_nonce: bytes | None = None,
    min_plaintext_len: int = MIN_QUERY_PLAINTEXT_LEN,
) -> PreparedQuery:
    """Construct `<dnscrypt-query>` for es-version 0x0002.

    `min_plaintext_len` is the ISO/IEC 7816-4 padding floor for the plaintext,
    not the spec's `<min-query-len>`, which targets the complete packet; the
    default floor keeps the packet above the initial 256-byte target.
    """

    if certificate.es_version != ES_VERSION_XCHACHA20POLY1305:
        raise CertificateError("encrypt_dnscrypt_query expects es-version 0x0002")
    if client_nonce is None:
        client_nonce = os.urandom(CLIENT_NONCE_SIZE)
    require_size("client_nonce", client_nonce, CLIENT_NONCE_SIZE)
    client_pk = x25519_public_key(client_sk)
    shared_key = box_xchacha20_shared_key(client_sk, certificate.resolver_pk)
    nonce = query_nonce(client_nonce)
    plaintext = pad_7816_4(client_query, min_plaintext_len)
    encrypted_query = xchacha20_djb_poly1305_seal(shared_key, nonce, plaintext)
    dnscrypt_query = (
        certificate.client_magic + client_pk + client_nonce + encrypted_query
    )
    check_query_size(dnscrypt_query)
    return PreparedQuery(
        dnscrypt_query=dnscrypt_query,
        shared_key=shared_key,
        client_pk=client_pk,
        client_nonce=client_nonce,
    )


def decrypt_dnscrypt_query(
    dnscrypt_query: bytes,
    resolver_certificates: Sequence[ResolverCertificate],
) -> DecryptedQuery:
    """Open `<dnscrypt-query>` at a resolver."""

    client_magic = dnscrypt_query[:CLIENT_MAGIC_SIZE]
    match = next(
        (
            rc
            for rc in resolver_certificates
            if rc.certificate.client_magic == client_magic
        ),
        None,
    )
    if match is None:
        raise DecryptionError("client-magic does not match any certificate")
    certificate = match.certificate
    client_pk_len = client_pk_len_for_es_version(certificate.es_version)
    header_len = CLIENT_MAGIC_SIZE + client_pk_len + CLIENT_NONCE_SIZE
    if len(dnscrypt_query) < header_len + TAG_SIZE:
        raise DecryptionError("query is truncated")
    client_pk = dnscrypt_query[CLIENT_MAGIC_SIZE : CLIENT_MAGIC_SIZE + client_pk_len]
    client_nonce = dnscrypt_query[CLIENT_MAGIC_SIZE + client_pk_len : header_len]
    encrypted_query = dnscrypt_query[header_len:]
    if certificate.es_version == ES_VERSION_XCHACHA20POLY1305:
        shared_key = box_xchacha20_shared_key(match.resolver_sk, client_pk)
    else:
        # es-version 0x0003, the only other value client_pk_len_for_es_version
        # accepts. Imported here because pq builds on this module; a top-level
        # import would be circular.
        from pq import pq_shared_key, xwing_decapsulate

        kem_ss = xwing_decapsulate(ciphertext=client_pk, secret_seed=match.resolver_sk)
        shared_key = pq_shared_key(certificate, kem_ss, client_pk)
    plaintext = xchacha20_djb_poly1305_open(
        shared_key, query_nonce(client_nonce), encrypted_query
    )
    return DecryptedQuery(
        client_query=unpad_7816_4(plaintext),
        shared_key=shared_key,
        client_pk=client_pk,
        client_nonce=client_nonce,
        certificate=certificate,
    )


def encrypt_dnscrypt_response(
    resolver_response: bytes,
    shared_key: bytes,
    client_nonce: bytes,
    resolver_nonce: bytes | None = None,
    min_plaintext_len: int = PADDING_BLOCK_SIZE,
) -> bytes:
    """Construct `<dnscrypt-response>` for regular DNSCrypt.

    The caller enforces the transport rules: over UDP the encrypted response
    must not exceed the encrypted query, so the DNS response is truncated with
    the TC flag set before calling this function when it would not fit.
    """

    if resolver_nonce is None:
        resolver_nonce = os.urandom(RESOLVER_NONCE_SIZE)
    require_size("client_nonce", client_nonce, CLIENT_NONCE_SIZE)
    require_size("resolver_nonce", resolver_nonce, RESOLVER_NONCE_SIZE)
    nonce = client_nonce + resolver_nonce
    plaintext = pad_7816_4(resolver_response, min_plaintext_len)
    encrypted_response = xchacha20_djb_poly1305_seal(shared_key, nonce, plaintext)
    dnscrypt_response = RESOLVER_MAGIC + nonce + encrypted_response
    check_response_size(dnscrypt_response)
    return dnscrypt_response


def decrypt_dnscrypt_response(
    dnscrypt_response: bytes,
    shared_key: bytes,
    expected_client_nonce: bytes,
) -> bytes:
    """Open `<dnscrypt-response>` and return `<resolver-response>`."""

    require_size("expected_client_nonce", expected_client_nonce, CLIENT_NONCE_SIZE)
    header_len = len(RESOLVER_MAGIC) + NONCE_SIZE
    if len(dnscrypt_response) < header_len + TAG_SIZE:
        raise DecryptionError("response is too short")
    if dnscrypt_response[: len(RESOLVER_MAGIC)] != RESOLVER_MAGIC:
        raise DecryptionError("invalid resolver magic")
    nonce = dnscrypt_response[len(RESOLVER_MAGIC) : header_len]
    if nonce[:CLIENT_NONCE_SIZE] != expected_client_nonce:
        raise DecryptionError("response client-nonce does not match query")
    plaintext = xchacha20_djb_poly1305_open(
        shared_key, nonce, dnscrypt_response[header_len:]
    )
    return unpad_7816_4(plaintext)
