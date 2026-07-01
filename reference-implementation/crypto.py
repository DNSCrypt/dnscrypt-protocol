"""Cryptographic primitives and small helpers used by DNSCrypt."""

from __future__ import annotations

import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.poly1305 import Poly1305

from constants import (
    PADDING_BLOCK_SIZE,
    PUBLIC_KEY_SIZE,
    RESOLVER_NONCE_SIZE,
    SIGNATURE_SIZE,
    TAG_SIZE,
    XCHACHA20_NONCE_SIZE,
)
from errors import CertificateError, DecryptionError, PaddingError

__all__ = [
    "box_xchacha20_shared_key",
    "chacha20_djb",
    "ed25519_public_key_from_seed",
    "ed25519_sign",
    "ed25519_verify",
    "hchacha20",
    "hkdf_sha256",
    "pad_7816_4",
    "query_nonce",
    "require_size",
    "unpad_7816_4",
    "x25519_public_key",
    "x25519_shared_point",
    "xchacha20_djb_poly1305_open",
    "xchacha20_djb_poly1305_seal",
]


def require_size(name: str, value: bytes, size: int) -> None:
    if len(value) != size:
        raise ValueError(f"{name} must be {size} bytes, got {len(value)}")


def _rotl32(x: int, n: int) -> int:
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))


def _quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rotl32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotl32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rotl32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotl32(state[b] ^ state[c], 7)


def hchacha20(k: bytes, input16: bytes) -> bytes:
    """HChaCha20 as specified in Appendix 1."""

    require_size("k", k, 32)
    require_size("input16", input16, 16)
    state = [
        0x61707865,
        0x3320646E,
        0x79622D32,
        0x6B206574,
        *struct.unpack("<8I", k),
        *struct.unpack("<4I", input16),
    ]
    for _ in range(10):
        _quarter_round(state, 0, 4, 8, 12)
        _quarter_round(state, 1, 5, 9, 13)
        _quarter_round(state, 2, 6, 10, 14)
        _quarter_round(state, 3, 7, 11, 15)
        _quarter_round(state, 0, 5, 10, 15)
        _quarter_round(state, 1, 6, 11, 12)
        _quarter_round(state, 2, 7, 8, 13)
        _quarter_round(state, 3, 4, 9, 14)
    return struct.pack(
        "<8I",
        state[0],
        state[1],
        state[2],
        state[3],
        state[12],
        state[13],
        state[14],
        state[15],
    )


def chacha20_djb(key: bytes, nonce8: bytes, data: bytes, counter: int = 0) -> bytes:
    """ChaCha20 with the original 64-bit nonce and 64-bit counter."""

    require_size("key", key, 32)
    require_size("nonce8", nonce8, 8)
    nonce = counter.to_bytes(8, "little") + nonce8
    return Cipher(algorithms.ChaCha20(key, nonce), mode=None).encryptor().update(data)


def _xchacha20_djb_poly1305(k: bytes, nonce: bytes, data: bytes) -> tuple[bytes, bytes]:
    """Run XChaCha20_DJB over `<zero32> || data` as in Appendix 1.

    The first 32 output bytes are the one-time Poly1305 key; the rest is the
    input combined with the keystream that immediately follows it.
    """

    subkey = hchacha20(k, nonce[:16])
    block = chacha20_djb(subkey, nonce[16:], b"\x00" * 32 + data)
    return block[:32], block[32:]


def xchacha20_djb_poly1305_seal(k: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    """Seal with DNSCrypt's NaCl secretbox-style XChaCha20_DJB-Poly1305."""

    require_size("k", k, 32)
    require_size("nonce", nonce, XCHACHA20_NONCE_SIZE)
    poly_key, ciphertext = _xchacha20_djb_poly1305(k, nonce, plaintext)
    tag = Poly1305.generate_tag(poly_key, ciphertext)
    return tag + ciphertext


def xchacha20_djb_poly1305_open(k: bytes, nonce: bytes, sealed: bytes) -> bytes:
    """Open a tag-prepended DNSCrypt XChaCha20_DJB-Poly1305 ciphertext."""

    require_size("k", k, 32)
    require_size("nonce", nonce, XCHACHA20_NONCE_SIZE)
    if len(sealed) < TAG_SIZE:
        raise DecryptionError("ciphertext is shorter than the authentication tag")
    tag, ciphertext = sealed[:TAG_SIZE], sealed[TAG_SIZE:]
    poly_key, plaintext = _xchacha20_djb_poly1305(k, nonce, ciphertext)
    try:
        Poly1305.verify_tag(poly_key, ciphertext, tag)
    except InvalidSignature as exc:
        raise DecryptionError("authentication failed") from exc
    return plaintext


def query_nonce(client_nonce: bytes) -> bytes:
    """Build a query AEAD nonce: the client-nonce with a zeroed resolver-nonce."""

    return client_nonce + b"\x00" * RESOLVER_NONCE_SIZE


def pad_7816_4(plaintext: bytes, minimum_length: int = 0) -> bytes:
    """Pad with 0x80 then NUL bytes to a block boundary and optional floor."""

    if minimum_length % PADDING_BLOCK_SIZE != 0:
        raise ValueError("minimum_length must be a multiple of the block size")
    padded_len = (
        (len(plaintext) + PADDING_BLOCK_SIZE) // PADDING_BLOCK_SIZE
    ) * PADDING_BLOCK_SIZE
    padded_len = max(padded_len, minimum_length)
    return plaintext + b"\x80" + b"\x00" * (padded_len - len(plaintext) - 1)


def unpad_7816_4(padded: bytes) -> bytes:
    """Remove ISO/IEC 7816-4 padding: strip trailing NULs, expect 0x80."""

    stripped = padded.rstrip(b"\x00")
    if not stripped.endswith(b"\x80"):
        raise PaddingError("padding delimiter not found")
    return stripped[:-1]


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256 extract-and-expand (RFC 5869)."""

    return HKDF(
        algorithm=hashes.SHA256(), length=length, salt=salt, info=info
    ).derive(ikm)


def ed25519_public_key_from_seed(signing_seed: bytes) -> bytes:
    """Return the Ed25519 public key for a 32-byte signing seed."""

    require_size("signing_seed", signing_seed, 32)
    sk = ed25519.Ed25519PrivateKey.from_private_bytes(signing_seed)
    return sk.public_key().public_bytes_raw()


def ed25519_sign(signing_seed: bytes, message: bytes) -> bytes:
    """Sign a message with a 32-byte Ed25519 signing seed."""

    require_size("signing_seed", signing_seed, 32)
    return ed25519.Ed25519PrivateKey.from_private_bytes(signing_seed).sign(message)


def ed25519_verify(public_key: bytes, signature: bytes, message: bytes) -> None:
    """Verify an Ed25519 signature or raise `CertificateError`."""

    require_size("public_key", public_key, PUBLIC_KEY_SIZE)
    require_size("signature", signature, SIGNATURE_SIZE)
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, message
        )
    except InvalidSignature as exc:
        raise CertificateError("certificate signature verification failed") from exc


def x25519_public_key(secret_key: bytes) -> bytes:
    """Return the X25519 public key for a raw 32-byte secret key."""

    require_size("secret_key", secret_key, 32)
    sk = x25519.X25519PrivateKey.from_private_bytes(secret_key)
    return sk.public_key().public_bytes_raw()


def x25519_shared_point(secret_key: bytes, public_key: bytes) -> bytes:
    """Compute the raw X25519 shared point and reject weak public keys."""

    require_size("secret_key", secret_key, 32)
    require_size("public_key", public_key, PUBLIC_KEY_SIZE)
    sk = x25519.X25519PrivateKey.from_private_bytes(secret_key)
    pk = x25519.X25519PublicKey.from_public_bytes(public_key)
    try:
        return sk.exchange(pk)
    except ValueError as exc:
        raise DecryptionError("weak X25519 public key") from exc


def box_xchacha20_shared_key(secret_key: bytes, public_key: bytes) -> bytes:
    """Compute `<shared-key>` for es-version 0x0002."""

    return hchacha20(x25519_shared_point(secret_key, public_key), b"\x00" * 16)
