"""Cryptographic primitives and small helpers used by DNSCrypt."""

from __future__ import annotations

import hashlib
import hmac
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.poly1305 import Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from constants import NONCE_SIZE, PADDING_BLOCK_SIZE, RESOLVER_NONCE_SIZE, TAG_SIZE
from errors import CertificateError, DecryptionError, PaddingError


def _require_size(name: str, value: bytes, size: int) -> None:
    if len(value) != size:
        raise ValueError(f"{name} must be {size} bytes, got {len(value)}")


def iota(start: int, size: int) -> bytes:
    """Return size bytes: start, start + 1, ... modulo 256."""

    return bytes((start + i) & 0xFF for i in range(size))


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

    _require_size("k", k, 32)
    _require_size("input16", input16, 16)
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


def chacha20_djb_keystream(
    key: bytes, nonce8: bytes, length: int, counter: int = 0
) -> bytes:
    """ChaCha20 with the original 64-bit nonce and 64-bit counter."""

    _require_size("key", key, 32)
    _require_size("nonce8", nonce8, 8)
    nonce = counter.to_bytes(8, "little") + nonce8
    encryptor = Cipher(algorithms.ChaCha20(key, nonce), mode=None).encryptor()
    return encryptor.update(b"\x00" * length)


def xchacha20_djb_poly1305_seal(k: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    """Seal with DNSCrypt's NaCl secretbox-style XChaCha20_DJB-Poly1305."""

    _require_size("k", k, 32)
    _require_size("nonce", nonce, NONCE_SIZE)
    subkey = hchacha20(k, nonce[:16])
    keystream = chacha20_djb_keystream(subkey, nonce[16:], 32 + len(plaintext))
    poly_key = keystream[:32]
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, keystream[32:]))
    tag = Poly1305.generate_tag(poly_key, ciphertext)
    return tag + ciphertext


def xchacha20_djb_poly1305_open(k: bytes, nonce: bytes, sealed: bytes) -> bytes:
    """Open a tag-prepended DNSCrypt XChaCha20_DJB-Poly1305 ciphertext."""

    _require_size("k", k, 32)
    _require_size("nonce", nonce, NONCE_SIZE)
    if len(sealed) < TAG_SIZE:
        raise DecryptionError("ciphertext is shorter than the authentication tag")
    tag, ciphertext = sealed[:TAG_SIZE], sealed[TAG_SIZE:]
    subkey = hchacha20(k, nonce[:16])
    keystream = chacha20_djb_keystream(subkey, nonce[16:], 32 + len(ciphertext))
    poly_key = keystream[:32]
    try:
        Poly1305.verify_tag(poly_key, ciphertext, tag)
    except InvalidSignature as exc:
        raise DecryptionError("authentication failed") from exc
    return bytes(a ^ b for a, b in zip(ciphertext, keystream[32:]))


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
    """Remove ISO/IEC 7816-4 padding."""

    i = len(padded) - 1
    while i >= 0 and padded[i] == 0:
        i -= 1
    if i < 0 or padded[i] != 0x80:
        raise PaddingError("padding delimiter not found")
    return padded[:i]


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256 extract-and-expand."""

    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    previous = b""
    counter = 1
    while len(okm) < length:
        previous = hmac.new(
            prk, previous + info + bytes([counter]), hashlib.sha256
        ).digest()
        okm += previous
        counter += 1
    return okm[:length]


def ed25519_public_key_from_seed(signing_seed: bytes) -> bytes:
    """Return the Ed25519 public key for a 32-byte signing seed."""

    _require_size("signing_seed", signing_seed, 32)
    sk = ed25519.Ed25519PrivateKey.from_private_bytes(signing_seed)
    return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def ed25519_sign(signing_seed: bytes, message: bytes) -> bytes:
    """Sign a message with a 32-byte Ed25519 signing seed."""

    _require_size("signing_seed", signing_seed, 32)
    return ed25519.Ed25519PrivateKey.from_private_bytes(signing_seed).sign(message)


def ed25519_verify(public_key: bytes, signature: bytes, message: bytes) -> None:
    """Verify an Ed25519 signature or raise `CertificateError`."""

    _require_size("public_key", public_key, 32)
    _require_size("signature", signature, 64)
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, message
        )
    except InvalidSignature as exc:
        raise CertificateError("certificate signature verification failed") from exc


def x25519_public_key(secret_key: bytes) -> bytes:
    """Return the X25519 public key for a raw 32-byte secret key."""

    _require_size("secret_key", secret_key, 32)
    sk = x25519.X25519PrivateKey.from_private_bytes(secret_key)
    return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def x25519_shared_point(secret_key: bytes, public_key: bytes) -> bytes:
    """Compute the raw X25519 shared point and reject weak public keys."""

    _require_size("secret_key", secret_key, 32)
    _require_size("public_key", public_key, 32)
    sk = x25519.X25519PrivateKey.from_private_bytes(secret_key)
    pk = x25519.X25519PublicKey.from_public_bytes(public_key)
    try:
        return sk.exchange(pk)
    except ValueError as exc:
        raise DecryptionError("weak X25519 public key") from exc


def box_xchacha20_shared_key(secret_key: bytes, public_key: bytes) -> bytes:
    """Compute `<shared-key>` for es-version 0x0002."""

    return hchacha20(x25519_shared_point(secret_key, public_key), b"\x00" * 16)
