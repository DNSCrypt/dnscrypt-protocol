# DNSCrypt Reference Implementation

This directory contains a small Python reference implementation for the
DNSCrypt v2 protocol.

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
