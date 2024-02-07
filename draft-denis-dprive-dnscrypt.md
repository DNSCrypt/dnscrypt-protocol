---
title: "The DNSCrypt protocol"
abbrev: "DNSCrypt"
category: info

ipr: trust200902
docname: draft-denis-dprive-dnscrypt-latest
submissiontype: independent
keyword:
 - dns
 - encryption
 - privacy
venue:
  group: "DNS PRIVate Exchange"
  type: "Working Group"
  github: "DNSCrypt/dnscrypt-protocol"

author:
 -
    fullname: Frank Denis
    organization: Individual Contributor
    email: fde@00f.net

normative:

informative:


--- abstract

The DNSCrypt protocol is designed to encrypt and authenticate DNS traffic between clients and resolvers. This document specifies the protocol and its implementation.

--- middle

# Introduction

The document defines the DNSCrypt protocol, which encrypts and authenticates DNS {{!RFC1035}} queries and responses, improving confidentiality, integrity, and resistance to attacks affecting the original DNS protocol.

The protocol is designed to be lightweight, extensible, and simple to implement securely on top of an existing DNS client, server or proxy.

DNS packets do not need to be parsed or rewritten. DNSCrypt simply wraps them in a secure, encrypted container. Encrypted packets are then exchanged the same way as regular packets, using the standard DNS transport mechanisms. Queries and responses are sent over UDP, falling back to TCP for large responses only if necessary.

DNSCrypt is stateless. Every query can be processed independently from other queries. There are no session identifiers. In order to better defend against fingerprinting, clients can replace their keys whenever they want, without extra interactions with servers.

DNSCrypt packets can securely be proxied without having to be decrypted, allowing client IP addresses to be hidden from resolvers ("Anonymized DNSCrypt").

Recursive DNS servers can accept DNSCrypt queries on the same IP address and port used for regular DNS traffic. Similarly, DNSCrypt and DoH can also share the same IP address and TCP port.

Lastly, DNSCrypt mitigates two common security vulnerabilities in regular DNS over UDP: amplification and fragmentation attacks.

# Conventions And Definitions

{::boilerplate bcp14-tagged}

Definitions for client queries:

- `<dnscrypt-query>`:  `<client-magic>` `<client-pk>` `<client-nonce>` `<encrypted-query>`
- `<client-magic>`: a 8 byte identifier for the resolver certificate
chosen by the client.
- `<client-pk>`: the client's public key, whose length depends on the encryption algorithm defined in the chosen certificate.
- `<client-sk>`: the client's secret key.
- `<resolver-pk>`: the resolver's public key.
- `<client-nonce>`: a unique query identifier for a given (`<client-sk>`, `<resolver-pk>`) tuple. The same query sent twice for the same (`<client-sk>`, `<resolver-pk>`) tuple MUST use two distinct `<client-nonce>` values. The length of `<client-nonce>` is determined by the chosen encryption algorithm.
- `AE`: the authenticated encryption function.
- `<encrypted-query>`: `AE(<shared-key> <client-nonce> <client-nonce-pad>, <client-query> <client-query-pad>)`
- `<shared-key>`: the shared key derived from `<resolver-pk>` and `<client-sk>`, using the key exchange algorithm defined in the chosen certificate.
-`<client-query>`: the unencrypted client query. The query is not modified; in particular, the query flags are not altered and the query length MUST be kept in queries prepared to be sent over TCP.
- `<client-nonce-pad>`: `<client-nonce>` length is half the nonce length required by the encryption algorithm. In client queries, the other half, `<client-nonce-pad>` is filled with NUL bytes.
- `<client-query-pad>`: the variable-length padding.

Definitions for server responses:

- `<dnscrypt-response>`: `<resolver-magic>` `<nonce>` `<encrypted-response>`
- `<resolver-magic>`: the `0x72 0x36 0x66 0x6e 0x76 0x57 0x6a 0x38` byte sequence
- `<nonce>`: `<client-nonce>` `<resolver-nonce>`
- `<client-nonce>`: the nonce sent by the client in the related query.
- `<client-pk>`: the client's public key.
- `<resolver-sk>`: the resolver's secret key.
- `<resolver-nonce>`: a unique response identifier for a given `(<client-pk>, <resolver-sk>)` tuple. The length of `<resolver-nonce>` depends on the chosen encryption algorithm.
- `DE`: the authenticated decryption function.
- `<encrypted-response>`: `DE(<shared-key>, <nonce>, <resolver-response> <resolver-response-pad>)`
- `<shared-key>`: the shared key derived from `<resolver-sk>` and `<client-pk>`, using the key exchange algorithm defined in the chosen certificate.
- `<resolver-response>`: the unencrypted resolver response. The response is not modified; in particular, the query flags are not altered and the response length MUST be kept in responses prepared to be sent over TCP.
- `<resolver-response-pad>`: the variable-length padding.


# Protocol Overview

The DNSCrypt protocol operates through the following steps:

1. The DNSCrypt client sends a DNS query to a DNSCrypt server to retrieve the server's public keys.
2. The client generates its own key pair.
3. The client encrypts unmodified DNS queries using a server's public key, padding them as necessary, and concatenates them to a nonce and a copy of the client's public key. The resulting output is transmitted to the server via standard DNS transport mechanisms.
4. Encrypted queries are decrypted by the server using the attached client public key and the server's own secret key. The output is a regular DNS packet that doesn't require any special processing.
5. To send an encrypted response, the server adds padding to the unmodified response, encrypts the result using the client's public key and the client's nonce, and truncates the response if necessary. The resulting packet, truncated or not, is sent to the client using standard DNS mechanisms.
6. The client authenticates and decrypts the response using its secret key, the server's public key, the client's nonce included in the response, and the client's original nonce. If the response was truncated, the client MAY adjust internal parameters and retry over TCP. If not, the output is a regular DNS response that can be directly forwarded to applications and stub resolvers.

# Key Management

Both clients and resolvers generate short-term key pairs for each encryption system they support.

Clients generate unique key pairs for each resolver they communicate with, while resolvers create individual key pairs for every client they interact with. Additionally, the resolver creates a public key for each encryption system it supports.


# Session Establishment

From the client's perspective, a DNSCrypt session is initiated when the client sends an unauthenticated DNS query to a DNSCrypt-capable resolver. This DNS query contains encoded information about the certificate versions supported by the client and a public identifier of the desired provider.

The resolver sends back a collection of signed certificates that the client MUST verify using the pre-distributed provider public key. Each certificate includes a validity period, a serial number, a version that defines a key exchange mechanism, an authenticated encryption algorithm and its parameters, as well as a short-term public key, known as the resolver public key.

Resolvers have the ability to support various algorithms and can concurrently advertise multiple short-term public keys (resolver public keys). The client picks the one with the highest serial number among the currently valid ones that match a supported protocol version.

Every certificate contains a unique magic number that the client MUST include at the beginning of their queries. This allows the resolver to identify which certificate the client selected for crafting a particular query.

The encryption algorithm, resolver public key, and client magic number from the chosen certificate are then used by the client to send encrypted queries. These queries include the client public key.

With the knowledge of the chosen certificate and corresponding secret key, along with the client's public key, the resolver is able to verify, decrypt the query, and then encrypt the response utilizing identical parameters.

# Transport

The DNSCrypt protocol can use the UDP and TCP transport protocols.
DNSCrypt clients and resolvers SHOULD support the protocol via UDP, and MUST support it over TCP.

Both TCP and UDP connections using DNSCrypt SHOULD employ port 443 by default.

# Padding For Client Queries Over UDP

Before encryption takes place, queries are padded according to the ISO/IEC 7816-4 standard. Padding begins with a single byte holding the value `0x80`, succeeded by any number of `NUL` bytes.

`<client-query>` `<client-query-pad>` MUST be at least `<min-query-len>` bytes.
In this context, `<client-query>` represents the original client query, while `<client-query-pad>` denotes the added padding.

Should the client query's length fall short of  `<min-query-len>` bytes, the padding length MUST be adjusted in order to satisfy the length requirement.

`<min-query-len>` is a variable length, initially set to 256 bytes, and MUST be a multiple of 64 bytes. It represents the minimum permitted length for a client query, inclusive of padding.

# Client Queries Over UDP

UDP-based client queries need to follow the padding guidelines outlined in section 3.

Each UDP packet MUST hold one query, with the complete content comprising the `<dnscrypt-query>` structure specified in section 2.

UDP packets employing the DNSCrypt protocol have the capability to be split into distinct IP packets sharing the same source port.

Upon receiving a query, the resolver may choose to either disregard it or send back a response encrypted using DNSCrypt.

The client MUST authenticate and, if authentication succeeds, decrypt the response with the help of the resolver's public key, the shared secret, and the obtained nonce. In case the response fails verification, it MUST be disregarded by the client.

If the response has the TC flag set, the client MUST:

1. send the query again using TCP
2. set the new minimum query length as:

`<min-query-len> ::= min(<min-query-len> + 64, <max-query-len>)`

`<min-query-len>` denotes the minimum permitted length for a client query, including padding. That value MUST be capped so that the full length of a DNSCrypt packet doesn't exceed the maximum size required by the transport layer.

The client MAY decrease `<min-query-len>`, but the length MUST remain a multiple of 64 bytes.

# Padding For Client Queries Over TCP

Queries MUST undergo padding using the ISO/IEC 7816-4 format before being encrypted. The padding starts with a byte valued `0x80` followed by a
variable number of NUL bytes.

The length of `<client-query-pad>` is selected randomly, ranging from 1 to 256 bytes, including the initial byte valued at `0x80`. The total length of `<client-query>` `<client-query-pad>` MUST be a multiple of 64 bytes.

For example, an originally unpadded 56-bytes DNS query can be padded as:

`<56-bytes-query> 0x80 0x00 0x00 0x00 0x00 0x00 0x00 0x00`

or

`<56-bytes-query> 0x80 (0x00 * 71)`

or

`<56-bytes-query> 0x80 (0x00 * 135)`

or

`<56-bytes-query> 0x80 (0x00 * 199)`


# Client Queries Over TCP

The sole differences between encrypted client queries transmitted via TCP and those sent using UDP lie in the padding length calculation and the inclusion of a length prefix, represented as two big-endian bytes.

In contrast, cleartext DNS query payloads do not necessitate a length prefix, regardless of whether they are transmitted via TCP.

Unlike UDP queries, a query sent over TCP can be shorter than the response.

After having received a response from the resolver, the client and the resolver MUST close the TCP connection to ensure security and comply with this revision of the protocol, which prohibits multiple transactions over the same TCP connection.

# Authenticated Encryption And Key Exchange Algorithm

The `Box-XChaChaPoly` construction, and the way to use it described in this section, MUST be referenced in certificates as version `2` of the public-key authenticated encryption system.

The construction, originally implemented in the libsodium cryptographic library and exposed under the name "crypto_box_curve25519xchacha20poly1305", uses the Curve25119 elliptic curve in Montgomery form and the `hchacha20` hash function for key exchange, the `XChaCha20` stream cipher, and `Poly1305` for message authentication.

The public and secret keys are 32 bytes long in storage. The MAC is 16 bytes long, and is prepended to the ciphertext.

When using `Box-XChaChaPoly`, this construction necessitates the use of a 24 bytes nonce, that MUST NOT be reused for a given shared secret.

With a 24 bytes nonce, a question sent by a DNSCrypt client must be encrypted using the shared secret, and a nonce constructed as follows: 12 bytes chosen by the client followed by 12 NUL (`0x00`) bytes.

A response to this question MUST be encrypted using the shared secret, and a nonce constructed as follows: the bytes originally chosen by the client, followed by bytes chosen by the resolver.

Randomly selecting the resolver's portion of the nonce is RECOMMENDED.

The client's half of the nonce MAY include a timestamp in addition to a counter or to random bytes. Incorporating a timestamp allows for prompt elimination of responses to queries that were sent too long ago or are dated in the future. This practice enhances security and prevents potential replay attacks.

# Certificates

To initiate a DNSCrypt session, a client transmits an ordinary unencrypted `TXT` DNS query to the resolver's IP address and DNSCrypt port. The attempt is first made using UDP; if unsuccessful due to failure, timeout, or truncation, the client then proceeds with TCP.

Resolvers are not required to serve certificates both on UDP and TCP.

The name in the question (`<provider name`) MUST follow this scheme:

`<protocol-major-version> . dnscrypt-cert . <zone>`

A major protocol version has only one certificate format.

A DNSCrypt client implementing the second version of the protocol MUST send a query with the `TXT` type and a name of the form:

`2.dnscrypt-cert.example.com`

The zone MUST be a valid DNS name, but MAY not be registered in the DNS hierarchy.

A single provider name can be shared by multiple resolvers operated by the same entity, and a resolver can respond to multiple provider
names, especially to support multiple protocol versions simultaneously.

In order to use a DNSCrypt-enabled resolver, a client must know the following information:

- The resolver IP address and port
- The provider name
- The provider public key

The provider public key is a long-term key whose sole purpose is to verify the certificates. It is never used to encrypt or verify DNS queries. A single provider public key can be employed to sign multiple certificates.

For example, an organization operating multiple resolvers can use a unique provider name and provider public key across all resolvers,
and just provide a list of IP addresses and ports. Each resolver MAY have its unique set of certificates that can be signed with the
same key.

It is RECOMMENDED that certificates are signed using specialized hardware rather than directly on the resolvers themselves. Once signed, resolvers SHOULD make these certificates available to clients. Signing certificates on dedicated hardware helps ensure security and integrity, as it isolates the process from potential vulnerabilities present in the resolver's system.

A successful response to a certificate request contains one or more `TXT` records, each record containing a certificate encoded as follows:

- `<cert>`: `<cert-magic> <es-version> <protocol-minor-version> <signature> <resolver-pk> <client-magic> <serial> <ts-start> <ts-end> <extensions>`
- `<cert-magic>`: `0x44 0x4e 0x53 0x43`
- `<es-version>`: the cryptographic construction to use with this certificate. For Box-XChaChaPoly, `<es-version>` MUST be `0x00 0x02`.
- `<protocol-minor-version>`: `0x00 0x00`
- `<signature>`: a 64-byte signature of `(<resolver-pk> <client-magic> <serial> <ts-start> <ts-end> <extensions>)` using the Ed25519 algorithm and the provider secret key. Ed25519 MUST be used in this version of the protocol.
- `<resolver-pk>`: the resolver short-term public key, which is 32 bytes when using X25519.
- `<client-magic>`: The first 8 bytes of a client query that was built using the information from this certificate. It MAY be a truncated public key. Two valid certificates cannot share the same `<client-magic>`. `<client-magic>` MUST NOT start with `0x00 0x00 0x00 0x00 0x00 0x00 0x00` (seven all-zero bytes) in order to avoid confusion with the QUIC protocol.
- `<serial>`: a 4-byte serial number in big-endian format. If more than one certificate is valid, the client MUST prefer the certificate with a higher serial number.
- `<ts-start>`: the date the certificate is valid from, as a big-endian 4-byte unsigned Unix timestamp.
- `<ts-end>`: the date the certificate is valid until (inclusive), as a big-endian 4-byte unsigned Unix timestamp.
- `<extensions>`: empty in the current protocol version, but may contain additional data in future revisions, including minor versions. The computation and verification of the signature MUST include the extensions. An implementation not supporting these extensions MUST ignore them.

Certificates made of this information, without extensions, are 116 bytes long. With the addition of `<cert-magic>`, `<es-version>`, and `<protocol-minor-version>`, the record is 124 bytes long.

After receiving a set of certificates, the client checks their validity based on the current date, filters out the ones designed for encryption systems that are not supported by the client, and chooses the certificate with the higher serial number.

DNSCrypt queries sent by the client MUST use the `<client-magic>` header of the chosen certificate, as well as the specified encryption system and public key.

The client MUST check for new certificates every hour and switch to a new certificate if:

- The current certificate is not present or not valid anymore,

or

- A certificate with a higher serial number than the current one is available.

# Implementation Status

*This note is to be removed before publishing as an RFC.*

Multiple implementations of the protocol described in this document have been developed and verified for interoperability.

A comprehensive list of known implementations can be found at [](https://dnscrypt.info/implementations).

# Security Considerations

DNSCrypt does not protect against attacks on DNS infrastructure.

# Operational Considerations

Special attention should be paid to the uniqueness of the generated secret keys.

Client public keys can be used by resolvers to authenticate clients, link queries to customer accounts, and unlock business-specific features such as redirecting specific domain names to a sinkhole.

Resolvers accessible from any client IP address can also opt for only responding to a set of whitelisted public keys.

Resolvers accepting queries from any client MUST accept any client public key. In particular, an anonymous client can generate a new key pair for every session, or even for every query. This mitigates the ability for a resolver to group queries by client public keys and discover the set of IP addresses a user might have been operating.

Resolvers MUST rotate the short-term key pair every 24 hours at most, and MUST throw away the previous secret key. After a key rotation, a resolver MUST still accept all the previous keys that haven't expired.

Provider public keys MAY be published as DNSSEC-signed `TXT` records, in the same zone as the provider name. For example, a query for the `TXT` type on the name `"2.pubkey.example.com"` may return a signed record containing a hexadecimal-encoded provider public key for the provider name `"2.dnscrypt-cert.example.com"`.

As a client is likely to reuse the same key pair many times, servers are encouraged to cache shared keys instead of performing the X25519 operation for each query. This makes the computational overhead of DNSCrypt negligible compared to plain DNS.

# IANA Considerations

This document has no IANA actions.

# Appendix 1: The Box-XChaChaPoly Algorithm

The `Box-XChaChaPoly` algorithm combines the `X25519` {{!RFC7748}} key exchange mechanism with a variant of the ChaCha20-Poly1305 construction specified in {{!RFC8439}}.

## HChaCha20

`HChaCha20` is an intermediate step based on the construction and security proof used to create `XSalsa20`, an extended-nonce Salsa20 variant.

`HChaCha20` is initialized in the same way as the ChaCha20 cipher defined in {{!RFC8439}}, except that `HChaCha20` uses a 128-bit nonce and has no counter. Instead, the block counter is replaced by the first 32 bits of the nonce.

Consider the two figures below, where each non-whitespace character represents one nibble of information about the ChaCha states (all numbers little-endian):

~~~
                  cccccccc  cccccccc  cccccccc  cccccccc
                  kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
                  kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
                  bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn

           ChaCha20 State: c=constant k=key b=blockcount n=nonce


                  cccccccc  cccccccc  cccccccc  cccccccc
                  kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
                  kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
                  nnnnnnnn  nnnnnnnn  nnnnnnnn  nnnnnnnn

                 HChaCha20 State: c=constant k=key n=nonce
~~~

After initialization, proceed through the ChaCha rounds as usual. Once the 20 ChaCha rounds have been completed, the first 128 bits and last 128 bits of the ChaCha state (both little-endian) are concatenated, and this 256-bit subkey is returned.

## Test Vector For The HChaCha20 Block Function

~~~
   o  Key = 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:
      14:15:16:17:18:19:1a:1b:1c:1d:1e:1f.  The key is a sequence of
      octets with no particular structure before we copy it into the
      HChaCha state.

   o  Nonce = (00:00:00:09:00:00:00:4a:00:00:00:00:31:41:59:27)

   After setting up the HChaCha state, it looks like this:

                    61707865 3320646e 79622d32 6b206574
                    03020100 07060504 0b0a0908 0f0e0d0c
                    13121110 17161514 1b1a1918 1f1e1d1c
                    09000000 4a000000 00000000 27594131

                     ChaCha state with the key setup.

   After running 20 rounds (10 column rounds interleaved with 10
   "diagonal rounds"), the HChaCha state looks like this:

                    423b4182 fe7bb227 50420ed3 737d878a
                    0aa76448 7954cdf3 846acd37 7b3c58ad
                    77e35583 83e77c12 e0076a2d bc6cd0e5
                    d5e4f9a0 53a8748a 13c42ec1 dcecd326

                       HChaCha state after 20 rounds

   HChaCha20 will then return only the first and last rows, in little
   endian, resulting in the following 256-bit key:

                    82413b42 27b27bfe d30e4250 8a877d73
                    a0f9e4d5 8a74a853 c12ec413 26d3ecdc

                        Resultant HChaCha20 subkey
~~~

## ChaCha20_DJB

ChaCha20 was originally designed to have a 8 byte nonce.

For the needs of TLS, {{!RFC8439}} changed this by setting `N_MIN` and `N_MAX` to `12`, at the expense of a smaller internal counter.

DNSCrypt uses ChaCha20 as originally specified, with `N_MIN = N_MAX = 8`. We refer to this variant as `ChaCha20_DJB`.

Common implementations may just refer to it as `ChaCha20`, and the IETF version as `ChaCha20-IETF`.

The internal counter in `ChaCha20_DJB` is 4 bytes larger than `ChaCha20`. There are no other differences between `ChaCha20_DJB` and `ChaCha20`.

## XChaCha20_DJB

XChaCha20_DJB can be constructed from an existing ChaCha20 implementation and the HChaCha20 function.

All that needs to be done is:

1. Pass the key and the first 16 bytes of the 24-byte nonce to `HChaCha20` to obtain the subkey.
2. Use the subkey and remaining 8 byte nonce with `ChaCha20_DJB`.

## XChaCha20_DJB-Poly1305

XChaCha20 is a stream cipher and offers no integrity guarantees without being combined with a MAC algorithm (e.g. Poly1305).

`XChaCha20_DJB-Poly1305` adds an authentication tag to the ciphertext encrypted with `XChaCha20_DJB`.

The Poly1305 key is computed as in {{!RFC8439}}, by encrypting an empty block.

Finally, the output of the Poly1305 function is prepended to the ciphertext:

- `<k>`: encryption key
- `<m>`: message to encrypt
- `<ct>`: `XChaCha20_DJB(<k>, <m>)`
- `XChaCha20_DJB-Poly1305(<k>, <m>)`: `Poly1305(<ct>) || <ct>`

## The Box-XChaChaPoly Algorithm

The Box-XChaChaPoly algorithm combines the key exchange mechanism X25519 defined {{!RFC7748}} with the `XChaCha20_DJB-Poly1305` authenticated encryption algorithm.

- `<k>`: encryption key
- `<m>`: message to encrypt
- `<pk>`: recipent's public key
- `<sk>`: sender's secret key
- `<sk'>`: `HChaCha20(X25519(<pk>, <sk>))`
- `Box-XChaChaPoly(pk, sk, m)`: `XChaCha20_DJB-Poly1305(<sk'>, <m>)`


--- back
