# DNSCrypt Reference Implementation

This directory contains a small Python reference implementation for DNSCrypt v2
and the PQDNSCrypt extension.

The code is intended to be read alongside the specification.

It keeps the specification names and favors direct field construction
over abstraction.

The implementation is split by topic:

- `constants.py` and `errors.py`: protocol constants and exception types
- `crypto.py`: HChaCha20, DNSCrypt's XChaCha20_DJB-Poly1305, HKDF, X25519, Ed25519
- `certificates.py`: certificate parsing, signing, profile extensions, selection
- `certificate_retrieval.py`: certificate queries, responses, and the anti-amplification size rule
- `packets.py` and `transport.py`: DNSCrypt packets, TCP framing, Anonymized DNSCrypt, relay validation
- `pq.py`: X-Wing, PQ key derivation, tickets, responses, resumed queries
- `dnscrypt.py`: re-exports the public reference API

Run the tests from the repository root with Python 3.10 or later and `uv`:

```sh
uv run --with 'cryptography>=48' --directory reference-implementation python -B -m unittest -v
```

The tests cover the draft's classical and PQ vectors, randomized exchanges,
packet limits, and rejection of malformed inputs.

`pq-client-kex.hex` contains the Appendix C X-Wing ciphertext generated with
Circl's X-Wing implementation from resolver seed `20 21 ... 3f` and
encapsulation seed `40 41 ... 7f`.

The tests decapsulate it and check the resulting shared secret and packet bytes
against the draft.

The `cryptography` API does not expose deterministic encapsulation.

These helpers illustrate wire formats and cryptographic operations.

Callers supply verified certificates, maintain nonce uniqueness and ticket
lifetimes, parse the decrypted DNS messages, and enforce UDP response budgets
and TCP connection handling.

The Python code is not intended as a production server or a constant-time
cryptographic implementation.
