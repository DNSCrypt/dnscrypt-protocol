---
title: "The DNSCrypt Protocol"
abbrev: "DNSCrypt"
docname: draft-denis-dprive-dnscrypt-latest
category: info
ipr: trust200902
submissiontype: independent
keyword: Internet-Draft
pi: [toc, sortrefs, symrefs]
venue:
  github: "DNSCrypt/dnscrypt-protocol"
  latest: "https://dnscrypt.github.io/dnscrypt-protocol/"

author:
 -
    fullname: Frank Denis
    organization: Individual Contributor
    email: fde@00f.net

normative:
  FIPS203:
    title: "Module-Lattice-Based Key-Encapsulation Mechanism Standard"
    target: "https://doi.org/10.6028/NIST.FIPS.203"
    author:
      - org: National Institute of Standards and Technology
    date: 2024-08
    seriesinfo:
      FIPS: "203"

informative:

--- abstract

DNSCrypt encrypts and authenticates DNS queries and responses between a client and a resolver.

This document describes version 2 of the protocol, including certificate discovery, packet formats, and cryptographic constructions.

It also specifies Anonymized DNSCrypt, which sends queries through a relay, and PQDNSCrypt, which adds hybrid post-quantum key exchange and ticket-based resumption.

--- middle

# Introduction

DNSCrypt protects DNS traffic between a client and a recursive resolver.

It authenticates the resolver using a provider public key that the client obtains through a trusted channel.

It does not authenticate DNS data beyond that resolver or replace DNSSEC validation.

A provider signs certificates containing short-term resolver public keys.

The client retrieves these certificates with an ordinary DNS query, verifies a certificate, and uses its public key to encrypt subsequent queries.

Each encrypted query carries the information the resolver needs to decrypt it and encrypt a response, without a separate handshake or per-client session state.

Clients can issue concurrent queries, and UDP responses can arrive out of order.

This document specifies the X25519-based `Box-XChaChaPoly` encryption system for DNSCrypt version 2.

{{anonymized-dnscrypt}} describes relay operation, and {{pq}} defines an additional encryption system using X-Wing and optional stateless resumption.

The cryptographic primitives and DNS wire format are defined by the normative references; this document specifies how DNSCrypt uses them.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

A *provider* signs resolver certificates.
A *resolver* accepts DNSCrypt queries and returns encrypted DNS responses.
A *client* may be a stub resolver or a local proxy acting on behalf of applications.
A *relay* forwards Anonymized DNSCrypt traffic without decrypting it.

A byte is an octet.
Unless specified otherwise, integers are unsigned and encoded in big-endian order.

Adjacent fields and `||` both denote byte-string concatenation, without separators or implicit length fields.

Quoted strings in cryptographic inputs are ASCII bytes without a terminating NUL byte.
Field lengths are in bytes; `NUL` denotes `0x00`.

# Protocol Overview

Before contacting a resolver, the client needs its IP address and port, provider name, and 32-byte Ed25519 provider public key.

These values MUST be obtained through an authenticated configuration or distribution mechanism.
Their distribution is outside the scope of this document.

~~~
Client                                      Resolver
   |                                            |
   |  DNS TXT query for the provider name       |
   |------------------------------------------->|
   |  DNS TXT response containing certificates  |
   |<-------------------------------------------|
   |                                            |
   |  Encrypted DNS query                       |
   |------------------------------------------->|
   |  Encrypted DNS response                    |
   |<-------------------------------------------|
~~~

The client verifies the returned certificates and selects one as described in {{certificate-validation}}.

For `Box-XChaChaPoly`, it generates an X25519 key pair and derives a shared key from its secret key and the certificate's resolver public key.

It pads and encrypts a DNS query, then sends it with the certificate identifier, client public key, and client nonce.

The resolver derives the same shared key, authenticates and decrypts the query, and processes the enclosed DNS message.

Its encrypted response includes the client nonce so the client can associate it with the outstanding query.

Certificate retrieval is repeated before the selected certificate expires and when recovery from a failed exchange requires it.

It is separate from encrypted query processing; a cached valid certificate can be used for many queries.

# Certificates {#certificates}

## Retrieval {#certificate-retrieval}

The client sends an ordinary unencrypted DNS query {{!RFC1035}} of type `TXT` and class `IN` to the resolver's IP address and DNSCrypt port.

The question name is the configured provider name, conventionally:

~~~
<protocol-major-version>.dnscrypt-cert.<zone>
~~~

For version 2, an example is `2.dnscrypt-cert.example.com`.
The zone must be a syntactically valid DNS name, but need not be registered.

Clients MAY support other explicitly configured provider names, although relays may recognize only the `2.dnscrypt-cert.` prefix.

The query does not advertise supported encryption systems; the client filters the returned certificates.

The RD bit MAY be set and is ignored by a resolver serving its own certificates.

Resolvers MUST serve certificates over UDP and TCP.

Clients SHOULD try UDP first and retry over TCP after timeout, failure, or a response with the TC flag set.

A client on a path known to block fragmented UDP MAY use TCP immediately.
PQ-capable clients use the larger request-padding target in {{pq-certificate-retrieval}}.
TCP certificate queries and responses use ordinary DNS length framing.

A UDP certificate query MAY include an EDNS(0) OPT record {{!RFC6891}} with an EDNS(0) Padding option {{!RFC7830}}.

The sender fills the padding with NUL bytes; the resolver ignores its contents.

Padding increases the request size available for the response-size checks in {{pq-certificate-retrieval}} and {{relay-behavior}}.

The advertised EDNS UDP payload size is a receive limit, not an amplification budget.

The client MUST check that QR is set and that the DNS response transaction ID and single question match its request, including the question name, type, and class.

DNS names are compared without regard to ASCII letter case.
A truncated response is a signal to retry, even if it contains no answers.

A non-truncated response with a nonzero RCODE, no matching TXT answers, or no acceptable certificate is a retrieval failure.

A client MUST NOT send an unencrypted application query as a fallback when certificate retrieval fails.

Each TXT answer contains one binary certificate, without hexadecimal or base64 encoding.
TXT RDATA is a sequence of character-strings, each prefixed by a one-byte length.
The client MUST concatenate the strings within each record before parsing its certificate.
Separate TXT records contain separate certificates and MUST NOT be concatenated.

## Certificate Format {#certificate-format}

~~~
<cert> ::= <cert-magic> <es-version> <protocol-minor-version>
           <signature> <resolver-pk> <client-magic>
           <serial> <ts-start> <ts-end> <extensions>
~~~

| Field                      | Length   | Meaning                    |
| -------------------------- | -------- | -------------------------- |
| `<cert-magic>`             | 4        | `44 4e 53 43` ("DNSC")     |
| `<es-version>`             | 2        | Encryption system          |
| `<protocol-minor-version>` | 2        | `00 00` in this revision   |
| `<signature>`              | 64       | Ed25519 signature          |
| `<resolver-pk>`            | variable | Resolver public key        |
| `<client-magic>`           | 8        | Certificate identifier     |
| `<serial>`                 | 4        | Certificate serial number  |
| `<ts-start>`               | 4        | First valid Unix timestamp |
| `<ts-end>`                 | 4        | Last valid Unix timestamp  |
| `<extensions>`             | variable | Signed extension data      |

The signature uses Ed25519 {{!RFC8032}}, without prehashing or a context, and covers every byte from `<resolver-pk>` to the end of `<extensions>`.

It excludes the first eight bytes and the signature itself.
The provider secret key signs certificates; it is not used for query encryption.

`<client-magic>` is an opaque identifier copied into queries.

A provider MUST NOT assign the same value to distinct concurrently usable certificates at the same resolver address and port.

It MAY be a truncated resolver public key.

It MUST NOT equal eight `0xff` bytes, which could combine with the next field to form an Anonymized DNSCrypt prefix.

It MUST NOT start with seven NUL bytes, to avoid confusion with QUIC {{?RFC9000}}, and MUST NOT equal the reserved `<resume-magic>` in {{pq-resumption}}.

`<serial>` is compared as an unsigned integer, without wraparound arithmetic.
Within a selected encryption system, a larger serial identifies the preferred certificate.
`<ts-start>` and `<ts-end>` count seconds since 1970-01-01 00:00:00 UTC.

The validity interval includes both endpoints, and `<ts-start>` MUST be strictly less than `<ts-end>`.

This document defines the following encryption systems:

`0x00 0x02`, `Box-XChaChaPoly`:
: The resolver and client public keys are each 32 bytes.
  The shared key is derived with X25519 and HChaCha20 as specified in {{box-xchachapoly}}.
  The certificate is 124 bytes without extensions.
  Extensions are empty in this revision; unknown extensions are ignored after signature verification.

`0x00 0x03`, X-Wing PQDNSCrypt:
: The resolver public key is 1216 bytes and the client key-exchange field is a 1120-byte KEM ciphertext.
  The certificate contains the required 12-byte profile extension in {{pq-certificates}}, for a total of 1320 bytes.
  {{pq-key-derivation}} defines the shared key.

The certificate has 92 fixed bytes in addition to the resolver public key and extensions.
The record length determines the extension length.

## Validation and Selection {#certificate-validation}

For each certificate, the client MUST:

1. Check `<cert-magic>` and read the encryption-system and minor-version fields.
   Ignore an unsupported encryption system without guessing its public key length.
2. Check that all fields for the selected encryption system are present.

3. Verify the Ed25519 signature with the configured provider public key, including all extension bytes in the signed input.

4. Check that `<ts-start>` is strictly less than `<ts-end>` and that the current time is within the certificate's validity interval.

5. Validate any mandatory profile extension, including the PQ extension when applicable.

A certificate that fails any check MUST be ignored without preventing the use of other valid certificates in the response.

The minor version does not change the base field layout; clients MUST accept an otherwise valid certificate with an unrecognized minor version and ignore unsupported extensions unless the selected encryption system requires their validation.

The client first applies its configured encryption-system policy.
If provisioning requires a particular system, it MUST NOT fall back to another one.

Otherwise, it chooses its preferred supported system, then the valid certificate with the highest serial within that system.

A client with no system preference MAY select the highest serial across all supported systems, using local policy to break ties.

Clients MUST refresh certificates periodically, early enough to avoid using an expired certificate.
An hourly refresh is suitable.

After a successful refresh, the client repeats selection over the returned valid certificates, replacing a withdrawn, expired, or superseded certificate.

An unauthenticated failure does not invalidate a cached certificate that remains valid, but clients MUST NOT extend its validity period.

# Encrypted Queries and Responses

## Transport {#transport}

Clients and resolvers MUST support TCP and SHOULD support UDP.
Port 443 is RECOMMENDED for both transports unless a different port is configured.
DNSCrypt does not use TLS on this port, and its framing is distinguishable from HTTPS.

A UDP datagram contains exactly one encrypted DNSCrypt packet.

Over TCP, each packet is prefixed with a two-byte big-endian length covering the complete encrypted packet and excluding the prefix itself.

The DNS messages inside the encryption have no TCP length prefix.
Receivers MUST read the advertised number of bytes, regardless of TCP segment boundaries.

A query MUST NOT exceed 4096 bytes, excluding TCP framing or an Anonymized DNSCrypt prefix.
Resolvers MUST accept queries up to this size.

An encrypted response MUST be smaller than 4096 bytes for compatibility with deployed clients.
If a DNS response cannot fit, the resolver truncates it and sets TC before padding and encryption.

UDP packets also obey {{udp-sizing}} and the limits of the transport path.

Clients and resolvers MUST support one query and response per TCP connection.
They MAY close the connection after that exchange.
A client MUST tolerate this closure and open a new connection for further queries.

An implementation MAY also support multiple exchanges on one connection; clients using this option must handle peers that close after the first response.

## Query Format {#query-format}

~~~
<dnscrypt-query> ::= <client-magic> <client-pk> <client-nonce>
                    <encrypted-query>

<encrypted-query> ::= AE(<shared-key>,
                         <client-nonce> || <client-nonce-pad>,
                         <client-query> || <client-query-pad>)
~~~

For `Box-XChaChaPoly`, fields have these offsets:

| Offset | Length   | Field                                           |
| ------ | -------- | ----------------------------------------------- |
| 0      | 8        | `<client-magic>` from the selected certificate  |
| 8      | 32       | `<client-pk>`, the client's X25519 public key   |
| 40     | 12       | `<client-nonce>`                                |
| 52     | variable | `<encrypted-query>`, tag followed by ciphertext |

`<shared-key>` is derived from the client secret key and the resolver public key using {{box-xchachapoly}}.
`AE` is the `XChaCha20_DJB-Poly1305` construction in that appendix: a 16-byte tag followed by ciphertext, with no associated data.

It uses the NaCl secretbox layout, which is not interchangeable with the ChaCha20-Poly1305 AEAD in {{!RFC8439}}.

`<client-query>` is the unmodified DNS wire message.
It MUST have QR clear and contain exactly one question.
`<client-query-pad>` is the padding in {{padding}}.
`<client-nonce-pad>` is 12 NUL bytes, making a 24-byte encryption nonce.

Every newly encrypted query under the same shared key MUST use a distinct `<client-nonce>`, including a query re-encrypted for a TCP retry.

Retransmitting an identical encrypted packet does not require a new nonce.

## Response Format {#response-format}

~~~
<dnscrypt-response> ::= <resolver-magic> <nonce> <encrypted-response>
<nonce> ::= <client-nonce> <resolver-nonce>

<encrypted-response> ::= AE(<shared-key>, <nonce>,
                            <resolver-response> ||
                            <resolver-response-pad>)
~~~

| Offset | Length   | Field                                                      |
| ------ | -------- | ---------------------------------------------------------- |
| 0      | 8        | `<resolver-magic>`: `72 36 66 6e 76 57 6a 38` ("r6fnvWj8") |
| 8      | 12       | `<client-nonce>` copied from the query                     |
| 20     | 12       | `<resolver-nonce>`                                         |
| 32     | variable | `<encrypted-response>`, tag followed by ciphertext         |

The response uses the query's shared key.
`<resolver-response>` is a DNS response, truncated when required by the transport size limits.
It MUST have QR set and match the query's transaction ID and question name, type, and class.
Question names are compared without regard to ASCII letter case.
The resolver pads it as described in {{padding}} before encryption.
PQ changes the response plaintext as described in {{pq-response-format}}.

The resolver MUST choose `<resolver-nonce>` so that the complete 24-byte nonce is not reused for different plaintexts under the same shared key, including when answering a replayed query.

It MUST NOT be all NUL bytes, because that would reuse the query's encryption nonce.
A cryptographically random 12-byte value, regenerated if it is all zero, is suitable.

## Padding {#padding}

Every encrypted query and response MUST use ISO/IEC 7816-4 padding: append one `0x80` byte, then zero or more NUL bytes.

To remove it, scan backward past trailing NUL bytes and require the preceding byte to be `0x80`; remove that byte and everything after it.

A missing delimiter or a result that is not a valid DNS message MUST cause rejection.
For PQ responses, remove and validate the control prefix as well before parsing the DNS message.

Receivers MUST accept any valid padding length within the transport limits.
They MUST NOT require a multiple of 64 bytes or enforce the sender's preferred padding range.

For UDP queries, `<min-query-len>` is a target for the complete encrypted packet, including headers and the authentication tag.

It starts at 256 bytes; clients MAY start with a larger value such as 512 bytes.

Clients pad queries to at least this target and SHOULD round the padded plaintext length up to a multiple of 64 when practical.

They MAY adjust the target as response sizes and path limits become known.
The target MUST stay within the transport size limits.
Full PQ queries use the padding rule in {{pq-padding}}.

For TCP queries, a client SHOULD add a random padding component to reduce length-based identification of repeated queries.

The UDP minimum does not apply.

For responses, the resolver SHOULD round the padded plaintext length to a multiple of 64 and SHOULD use between 1 and 256 padding bytes, including the delimiter.

It SHOULD choose the padding length as a deterministic pseudorandom function of the client nonce and either the resolver secret key or the shared key, so identical queries do not reveal more length information through repeated padding samples.

If this padding exceeds the UDP size budget, it MAY use shorter valid padding before truncating the DNS response.

## Processing and Failure Handling {#query-processing}

The resolver selects a certificate using `<client-magic>` and derives the shared key from its secret key and `<client-pk>`.

It MUST reject an unknown identifier, invalid key exchange, failed authentication, invalid padding, or malformed DNS query.

Rejected encrypted queries are silently discarded.
The resolver MUST authenticate the query before passing its plaintext to DNS processing.
Any 12-byte client nonce is acceptable to the resolver; uniqueness is the sender's responsibility.

For the classical encryption system, a public resolver accepting anonymous clients MUST accept arbitrary client public keys, subject to the cryptographic checks in {{box-xchachapoly}}.

A resolver serving known clients MAY restrict those keys by local policy.

The client MUST check the response magic and match the client-nonce prefix to an outstanding query.

It MUST authenticate the response with that query's shared key, remove padding, and check the DNS transaction ID and question before delivering it.

Invalid, unmatched, duplicate, or expired responses MUST be discarded.

When an authenticated UDP DNS response has TC set, the client MUST retry over TCP {{!RFC7766}}.

It SHOULD increase its UDP padding target if a larger query would have avoided truncation and the path permits it.

TCP to an Anonymized DNSCrypt relay still uses UDP on the upstream leg; {{anonymized-dnscrypt}} describes the resulting limits.

## UDP Response Size {#udp-sizing}

The complete encrypted UDP response MUST NOT exceed the encrypted query that triggered it.

Neither an EDNS receive-buffer advertisement inside the DNS query nor the Anonymized DNSCrypt prefix increases this budget.

This rule limits response amplification {{?RFC5358}}.

If the full response will not fit with at least one padding byte, the resolver MUST send a truncated DNS response with TC set, then pad and encrypt it.

It MUST NOT silently discard an otherwise valid query merely because the full response is too large.

The truncated response remains subject to the same size limit and retains the question and transaction ID.

PQ resolvers first omit optional ticket data as described in {{pq-response-format}}.

# Key Management {#key-management}

A provider name and signing key may be shared by multiple resolver addresses, each with its own short-term keys.

The provider signing key SHOULD be kept separate from the resolver's query-processing environment, for example on dedicated signing hardware.

A resolver needs only its short-term secret keys and the corresponding signed certificates to answer queries.

Resolvers MUST rotate short-term key pairs at least every 24 hours.

They MUST retain the secret key for every previously advertised certificate that remains valid, including certificates cached by clients after a newer certificate replaces them in discovery responses.

Once all certificates referring to an old key have expired, they MUST erase it and any cached shared keys derived from it.

If a key is compromised, they MUST withdraw its certificates and erase it immediately.

Clients may still have a withdrawn certificate cached, so withdrawing it can interrupt service until they refresh.

Clients MAY generate a new key pair for each query or reuse a key pair across queries.
Resolvers may cache classical shared keys to avoid repeating X25519 for each query.

Clients that change networks SHOULD replace their keys to avoid linking their old and new addresses through a visible public key.

PQ ticket handling has the corresponding privacy considerations in {{pq-resumption}}.

# Anonymized DNSCrypt {#anonymized-dnscrypt}

Anonymized DNSCrypt lets a client reach a resolver through a relay.
The relay learns the client's address and the chosen resolver, but cannot decrypt the DNS messages.
The resolver sees the relay's address instead of the client's.
The client still authenticates the resolver and encrypts queries as specified above.

This separation is useful when the relay and resolver do not collude.

It does not prevent them, or an observer of both connections, from correlating traffic by its timing and size.

## Relay Query Format {#relay-query}

The client prefixes an encrypted DNSCrypt query or an unencrypted certificate query with the destination address:

~~~
<anondnscrypt-query> ::=
    <anon-magic> <server-ip> <server-port> <dnscrypt-query>
~~~

| Field              |    Bytes | Value                                           |
| :----------------- | -------: | :---------------------------------------------- |
| `<anon-magic>`     |       10 | Eight `0xff` bytes followed by two `0x00` bytes |
| `<server-ip>`      |       16 | IPv6 address in network byte order              |
| `<server-port>`    |        2 | Destination port, big-endian                    |
| `<dnscrypt-query>` | Variable | Complete inner query                            |

An IPv4 destination uses its IPv4-mapped IPv6 address, `::ffff:<IPv4 address>` {{!RFC4291}}.
For example, the prefix for 192.0.2.1:443 is:

~~~
ff ff ff ff ff ff ff ff 00 00
00 00 00 00 00 00 00 00 00 00 ff ff c0 00 02 01
01 bb
~~~

This documentation address illustrates the encoding; a relay would reject it as a destination.

Over UDP, the packet is exactly this byte string.
Over TCP, a two-byte big-endian length precedes the complete `<anondnscrypt-query>`.
The relay removes that length and the 28-byte destination prefix before forwarding the inner query.

Responses have no Anonymized DNSCrypt prefix; only responses to a TCP client receive a TCP length prefix.

## Forwarding and Validation {#relay-behavior}

A relay MUST accept queries over UDP and TCP and MUST forward them to the resolver over UDP.

The inner query therefore remains subject to the UDP limits in {{transport}}, including when the client uses TCP to the relay.

The relay MUST leave the inner query unchanged.

Before forwarding, the relay MUST:

- Check the packet length before reading any field.
- Reject destinations that are not globally routable, including unspecified, loopback, private-use, unique-local, link-local, multicast, documentation, and benchmarking addresses.
  For an IPv4-mapped address, it MUST apply this check to the embedded IPv4 address.
- Check the destination port against its configured policy and reject its own listening endpoints.
- Reject an inner query beginning with `<anon-magic>`, to prevent relay chaining.
- Reject an inner query whose first eight bytes are `00 00 00 00 00 00 00 01`, a reserved prefix used to avoid protocol confusion with QUIC {{!RFC9000}}.
  A relay MAY reject additional prefixes by local policy.

The relay MUST accept a response only from the addressed resolver and only if it is no larger than the inner query sent upstream.

An encrypted response MUST begin with `<resolver-magic>` and contain at least 61 bytes: the 32-byte header, 16-byte tag, 12-byte DNS header, and one padding byte.

This is only a preliminary length check; the client validates the decrypted contents.

For a certificate response, the relay MUST check the DNS response flag, transaction ID, question name, type `TXT`, and class `IN` against the forwarded query.

The standard certificate name begins with `2.dnscrypt-cert.`; relays MAY reject other names.

The relay MUST discard responses that fail these checks and forward an accepted response unchanged, apart from TCP framing.

Authentication of encrypted responses and certificates remains the client's responsibility.

A relay MAY cache a validated certificate response briefly and reuse it for an identical certificate query to the same resolver.

It MUST update the DNS transaction ID and recheck the size limit against the current query before returning a cached response.

Clients retrieving certificates through a relay MUST pad the inner certificate query enough to receive the expected response.

{{pq-certificate-retrieval}} gives the larger padding requirements for PQ certificates.

An encrypted query's padding similarly determines the response budget on the relay-to-resolver UDP connection.

If an encrypted DNS response is truncated, a client can retry with a larger padded inner query, within the UDP limit.

Using TCP to the relay alone does not increase that budget or provide TCP to the resolver.

Clients SHOULD choose a relay and resolver operated by different organizations, preferably on different networks.

Relay operators SHOULD restrict destination ports, maintain their address policy as special-use allocations change, and limit abusive traffic.

Repeated client public keys, KEM ciphertexts, and resumption tickets can link queries across addresses; clients seeking unlinkability need fresh key material as described in {{key-management}} and {{pq-security}}.

# Post-Quantum Key Exchange (PQDNSCrypt) {#pq}

PQDNSCrypt uses a hybrid key encapsulation mechanism (KEM) to protect recorded queries against a future quantum attack on X25519.

It uses encryption system version `0x00 0x03` within the existing certificate format and provider name.

A resolver MAY publish classical and PQ certificates together; clients ignore encryption systems they do not support.

The extension changes the key exchange and adds an encrypted response control field for optional resumption tickets.

The authenticated encryption, nonce construction, DNS messages, and transport framing remain those of DNSCrypt.

## Key Encapsulation {#pq-kem}

PQDNSCrypt uses X-Wing {{!I-D.connolly-cfrg-xwing-kem}}, which combines ML-KEM-768 {{FIPS203}} and X25519 {{!RFC7748}}.

Its encapsulation key is 1216 bytes, its ciphertext is 1120 bytes, and its shared secret is 32 bytes.

Implementations MUST use the X-Wing key generation, encapsulation, decapsulation, and input checks defined in that specification.

In particular, encapsulation checks the ML-KEM public key, and X-Wing does not apply the standalone X25519 all-zero shared-point rejection described in {{box-xchachapoly}}.

The resolver publishes its X-Wing encapsulation key as `<resolver-pk>`.
The client encapsulates to that key, obtaining a shared secret and a ciphertext.
It sends the ciphertext in the query's `<client-pk>` field, called `<client-kex>` below.
The resolver decapsulates it to obtain the same shared secret.
No additional round trip is needed.

A client MAY reuse a ciphertext and its derived shared key with the same certificate, provided it uses a fresh `<client-nonce>` for every query.

Reuse makes those queries linkable and increases the amount of traffic protected by one shared key.

A client seeking unlinkability SHOULD generate a fresh encapsulation for each query and avoid resumption.

## PQ Certificates {#pq-certificates}

A PQ certificate follows {{certificates}}, with `<es-version>` set to `00 03` and a 1216-byte `<resolver-pk>`.

The signed region remains `<resolver-pk> <client-magic> <serial> <ts-start> <ts-end> <extensions>`.

The `<client-magic>` is a certificate selector and follows the uniqueness and reserved-value rules in {{certificates}}.

For this profile, `<extensions>` MUST consist of the following 12 bytes:

~~~
<pq-profile-ext> ::= "PQD" <ext-version> <es-version> <kdf-id>
                    <aead-id> <resolver-pk-len> <client-kex-len>
~~~

| Field               | Bytes | Required value               |
| :------------------ | ----: | :--------------------------- |
| `"PQD"`             |     3 | `50 51 44`                   |
| `<ext-version>`     |     1 | `01`                         |
| `<es-version>`      |     2 | `00 03`                      |
| `<kdf-id>`          |     1 | `01`, HKDF-SHA256            |
| `<aead-id>`         |     1 | `01`, XChaCha20_DJB-Poly1305 |
| `<resolver-pk-len>` |     2 | `04 c0`, 1216 bytes          |
| `<client-kex-len>`  |     2 | `04 60`, 1120 bytes          |

The two lengths are big-endian integers.

A client MUST reject a PQ certificate with a missing or malformed extension, an unsupported identifier, or values that disagree with the outer `<es-version>` or the specified field lengths.

The signature authenticates the profile extension, explicitly binding these parameters to the resolver key.

The certificate validation and selection rules in {{certificate-validation}} also apply.

## Certificate Retrieval {#pq-certificate-retrieval}

A PQ certificate is 1320 bytes.
It occupies six DNS `TXT` character-strings and approximately 1338 bytes as a compressed answer RR.

A certificate response with one classical and one PQ certificate is typically about 1.5 KB; two of each during rollover require about 3 KB.

Even one PQ certificate exceeds the usual 1232-byte UDP payload target after DNS framing.

Certificate retrieval is unauthenticated, so large responses to small UDP queries could amplify spoofed traffic.

A resolver MAY return a small classical certificate response to an ordinary UDP query for compatibility with existing clients.

It MUST NOT include PQ certificates in a UDP response larger than the query that triggered it.
The advertised EDNS(0) UDP payload size is a receiver limit, not an amplification allowance.
Both limits apply independently.

A client retrieving PQ certificates over UDP MUST use EDNS(0) padding {{!RFC7830}} to make the complete DNS query large enough for the expected rollover certificate response, and advertise a receive size at least that large.

For the certificate sets above, 3200 bytes is a practical query target for typical provider names; longer names, extensions, or additional records can require more.

The client MUST include DNS framing in this calculation.

Resolvers SHOULD keep their UDP certificate sets to one classical and one PQ certificate normally, or two of each during rollover, and SHOULD keep complete certificate responses below 4096 bytes.

Clients SHOULD try this padded UDP query first and retry over TCP after timeout or truncation.
A client on a path known to block fragmented UDP MAY use TCP immediately.

If the PQ certificate set does not fit the UDP query's size budget, the resolver SHOULD return the classical certificates that fit with TC set.

A PQ-capable client MUST treat TC as an incomplete certificate set and retry before selecting a certificate.

Direct TCP certificate retrieval does not require request padding to cover the response.

Through an Anonymized DNSCrypt relay, the response MUST also fit the inner query's size, including for classical certificates.

After a timeout or truncated certificate response, the client SHOULD retry over TCP to the relay with the same rollover-sized inner query.

The relay still uses UDP upstream, so this avoids fragmentation only on the client-to-relay connection.

If that path cannot carry the certificate response, direct TCP retrieval is an alternative allowed by client policy, but discloses the client's address to the resolver.

## Shared-Key Derivation {#pq-key-derivation}

Both parties derive `<shared-key>` from the X-Wing shared secret using HKDF-SHA256 {{!RFC5869}}:

~~~
cert-context ::= "DNSCrypt-PQ-v1" <es-version>
                 <protocol-minor-version> <resolver-pk>
                 <client-magic> <serial> <ts-start> <ts-end>
                 <extensions>

<shared-key> ::= HKDF-SHA256(IKM  = <kem-ss>,
                           salt = <es-version> <client-magic>,
                           info = cert-context <client-kex>,
                           L    = 32)
~~~

`<kem-ss>` is the 32-byte X-Wing shared secret.

All certificate fields use their exact wire encodings, and quoted strings are ASCII without a terminating NUL byte.

The derivation binds the key to the certificate and the transmitted KEM ciphertext.

The resulting key is used with XChaCha20_DJB-Poly1305 from {{box-xchachapoly}} and the nonce construction in {{query-format}} and {{response-format}}.

## Query and Response Format {#pq-response-format}

A query carrying a KEM ciphertext uses {{query-format}} with a 1120-byte `<client-pk>`.

It needs valid padding from {{padding}}, but its large key-exchange field already exceeds the ordinary 256-byte UDP query-size target.

A query with a 64-byte padded DNS payload is 1220 bytes before any relay prefix.
Longer DNS messages require larger packets.

A PQ response uses the wire format in {{response-format}}, but its authenticated plaintext is:

~~~
<pq-response-plain> ::= <control-len> <control>
                       <resolver-response> <resolver-response-pad>
~~~

`<control-len>` is a two-byte big-endian length; zero means no control block.
Padding covers the complete plaintext, including both control fields.

After authentication and padding validation, the client MUST reject a response if `<control-len>` extends beyond the plaintext or leaves no complete DNS response.

It removes the control fields before processing the DNS response.

The client MUST skip an unknown control type or version and process an otherwise valid DNS response normally.

## Padding and Transport {#pq-padding}

The UDP response-size rule in {{udp-sizing}} applies to the complete encrypted response, including control data and padding.

A resolver MUST omit an optional ticket if doing so allows the DNS response to fit, before truncating DNS data.

The KEM ciphertext gives the resolver a larger response budget, but does not guarantee that every DNS response will fit.

PQ clients and resolvers MUST support TCP.

A client SHOULD use a configurable UDP payload target, initially 1232 bytes, and use TCP when an encrypted query exceeds it.

For a relayed query, the 28-byte relay prefix counts toward this target on the client-to-relay connection.

The relay-to-resolver connection remains UDP and its response budget is the size of the inner query, as described in {{relay-behavior}}.

## Stateless Resumption {#pq-resumption}

A resolver can issue an opaque ticket so that later queries avoid the KEM ciphertext and decapsulation.

The client stores the ticket and a resumption secret; the resolver recovers the secret from the ticket using a server-wide ticket key `TK`.

Resumption is optional, but resolvers SHOULD support it to reduce packet sizes and KEM processing.

### Ticket Issuance and Renewal {#pq-ticket-issuance}

For each response that carries a new ticket, both parties derive:

~~~
resume-secret ::= HKDF-SHA256(IKM  = <shared-key>,
                            salt = <client-magic> <client-nonce>,
                            info = "DNSCrypt-PQ-resume-secret-v1",
                            L    = 32)
~~~

Here `<shared-key>` and `<client-nonce>` belong to the query being answered.

This rule also applies when renewing a ticket in response to a resumed query: the new secret is derived from that query's per-query key, not copied from its old ticket.

The certificate context remains the one used for that query.

The resolver seals the secret, certificate context, and an expiry time into a ticket.
Its internal format is private to the resolver and need not interoperate between resolvers.
The reference construction is:

~~~
ticket-plain ::= resume-secret <es-version> <client-magic>
                <serial> <ts-end> <ticket-expiry>
                <profile-extension-hash>

ticket ::= <ticket-key-id> <ticket-nonce>
           AE(TK, <ticket-nonce>, ticket-plain)
~~~

`<ticket-key-id>` is four bytes, `<ticket-nonce>` is 24 bytes, and `<ticket-expiry>` is a four-byte big-endian Unix timestamp.

`<profile-extension-hash>` is the 32-byte SHA-256 hash of `<extensions>`.
`AE` is XChaCha20_DJB-Poly1305 from {{box-xchachapoly}}, with a dedicated 32-byte ticket key.
The ticket nonce MUST NOT repeat under that key.
This construction produces an 86-byte plaintext and a 130-byte ticket.

The response carries the ticket in its control block:

~~~
<control> ::= "PQDR" <control-version> <ticket-lifetime>
              <ticket-len> <ticket>
~~~

`"PQDR"` is `50 51 44 52`, `<control-version>` is the byte `01`, `<ticket-lifetime>` is a four-byte big-endian number of seconds, and `<ticket-len>` is a two-byte big-endian length.

For version 1, `<control-len>` MUST equal `11 + <ticket-len>`.

The client MUST reject a response with a recognized version 1 control block if its lifetime or ticket length is zero, or if its control fields are malformed.

It MAY ignore tickets that are too large for its supported query size.

The resolver SHOULD issue a ticket in its first PQ response and MAY renew it in later responses.

A client SHOULD adopt a newly received valid ticket together with the secret derived for that response.

It computes its local expiry from receipt time plus `<ticket-lifetime>`, capped by the certificate expiry and local policy.

It MUST NOT resume with an expired ticket or one whose certificate is no longer acceptable.
The sealed expiry is not visible to the client; the resolver remains responsible for enforcing it.

Ticket lifetimes SHOULD be short.

The advertised lifetime and sealed expiry MUST NOT extend past the certificate's remaining validity or the scheduled destruction of the ticket key.

Resolvers MUST generate ticket keys independently of retained long-term keys and erase retired ticket keys after their acceptance period.

A resolver MAY retain an old ticket key for an overlap no longer than its maximum advertised ticket lifetime.

Resolvers sharing a certificate SHOULD coordinate their ticket keys if clients can reach any of them with the same ticket.

### Resumed Queries {#pq-resumed-query}

A resumed query is:

~~~
<pq-resume-query> ::= <resume-magic> <ticket-len> <ticket>
                     <client-nonce> <encrypted-query>
~~~

`<resume-magic>` is the reserved eight-byte value `50 51 52 65 73 75 6d 65` (`"PQResume"`), which MUST NOT be used as a certificate's `<client-magic>`.

`<ticket-len>` is a two-byte big-endian integer, and `<client-nonce>` is 12 bytes.

The ticket replaces the key-exchange field; the encrypted DNS query and nonce construction are otherwise unchanged.

The resolver MUST validate the packet lengths, open the ticket, and check its expiry before accepting the query.

It MUST also check that the sealed `<es-version>`, `<client-magic>`, `<serial>`, `<ts-end>`, and hash of `<extensions>` identify an acceptable current certificate.

It then derives:

~~~
<shared-key> ::= HKDF-SHA256(IKM  = resume-secret,
                           salt = <client-magic> <client-nonce>,
                           info = "DNSCrypt-PQ-resumed-query-v1"
                                  SHA-256(<ticket>),
                           L    = 32)
~~~

The client uses the same derivation, retaining the certificate's `<client-magic>` with its ticket and resumption secret.

The nonce in this derivation is the fresh nonce from the resumed query, not the nonce that produced the ticket.

Each newly encrypted resumed query using the same ticket MUST have a distinct `<client-nonce>`.

Retransmitting an identical encrypted packet is permitted, as in {{query-format}}.

The response uses this per-query key and the PQ plaintext format in {{pq-response-format}}; it sets `<control-len>` to zero if no new ticket is issued.

The normal requirements for a fresh, nonzero resolver nonce still apply, including when a query is replayed.

Resumed UDP queries use the normal query-size target in {{padding}}, initially 256 bytes for the complete DNSCrypt packet.

Through a relay, that inner packet also determines the upstream response budget, even if the client uses TCP to the relay.

A resolver MUST silently discard a query with an invalid or expired ticket.

After a resumed query times out, the client SHOULD retry with a query carrying a KEM ciphertext, so a lost or retired ticket key does not prevent recovery.

## Downgrade Protection {#pq-downgrade}

Certificate signatures prevent forgery but do not prevent an attacker from removing PQ certificates from an unauthenticated DNS response.

A client provisioned to require PQ for a resolver MUST NOT select a classical certificate for that resolver, including after timeout or truncation.

A client without that policy MAY fall back to a classical certificate, but then has no protection against this downgrade.

Authenticated provisioning of that policy is outside this specification.

## Security and Privacy {#pq-security}

X-Wing provides hybrid confidentiality under the assumptions in {{!I-D.connolly-cfrg-xwing-kem}}.

Against a passive quantum adversary that breaks X25519, this protection depends on ML-KEM-768 remaining secure.

Certificates still use Ed25519, so PQDNSCrypt does not provide post-quantum authentication against an active adversary able to forge those signatures.

ML-KEM uses implicit rejection for invalid, correctly sized ciphertexts.

The resolver MUST perform X-Wing decapsulation as specified and MUST authenticate the encrypted query before using its plaintext.

Authentication or ticket-validation failure MUST produce no response.

Cryptographic operations MUST avoid secret-dependent timing and other side channels; public length checks need not take as long as a decapsulation.

Resolvers SHOULD limit unauthenticated KEM work under load.

Compromise of a resolver's KEM secret key exposes recorded queries carrying ciphertexts for that key.

If the initial query was recorded, the attacker can also reconstruct its resumption secret and follow subsequent ticket renewals.

Compromise of a ticket key exposes the resumption secrets in recorded tickets sealed under it, but does not by itself reveal the initial KEM query key.

Erasing ticket keys alone therefore does not establish forward secrecy for a resumption chain; the relevant KEM keys and retained client secrets must also be erased.

Renewal does not establish a new KEM secret or restore security after compromise of that chain.

A reused KEM ciphertext or ticket is visible and can link queries across source addresses.
Clients SHOULD discard both cached encapsulations and resumption state when changing networks.
Clients that need unlinkability SHOULD use fresh encapsulations instead of tickets.

The replay considerations in {{security}} still apply: resumption does not make a stateless resolver able to detect repeated queries.

# Security Considerations {#security}

## Authentication and Key Compromise

DNSCrypt authenticates a resolver through the configured provider public key, its signed certificate, and possession of the corresponding resolver secret key.

An attacker who replaces the configured provider key can impersonate the resolver.

An attacker who obtains the provider signing key can issue new certificates, but that key alone does not derive the shared keys of previously recorded classical queries.

Resolver authentication does not establish that DNS answers are correct; clients that need DNSSEC validation must arrange it separately.

A public resolver does not authenticate the client's identity.
Anyone with its certificate can encrypt a valid query.

A service using an allowlist of classical client public keys relies on secure provisioning of those keys.

The PQ KEM ciphertext is not a client identity.

DNSCrypt does not provide per-query forward secrecy against compromise of a resolver secret key.
That key and the public fields of a recorded query suffice to recover its shared key.

Short-term key rotation limits the exposure only after the old secret key and cached shared keys have been erased.

PQ resumption introduces additional key dependencies described in {{pq-security}}.

Certificate signatures do not prevent an attacker from suppressing newer certificates or replaying an older certificate within its validity interval.

Correct certificate validation also depends on a sufficiently accurate local clock.

Encryption-system downgrade protection requires authenticated provisioning, as described in {{pq-downgrade}}.

## Cryptographic Implementation

Keys and random nonces MUST be generated with a cryptographically secure random number generator.

Implementations MUST protect secret-dependent cryptographic operations against timing attacks and compare authentication tags in constant time.

They MUST NOT release unauthenticated plaintext.

Using a cryptographic library avoids many implementation errors, but its encryption API must implement the exact construction in {{box-xchachapoly}}.

An API named XChaCha20-Poly1305 may instead implement an incompatible AEAD layout.

Reusing a key and nonce for different plaintexts compromises confidentiality and authentication.
This applies to client retries, resolver responses to replayed queries, and ticket sealing.

Clients SHOULD use unpredictable nonces, or a secret-key construction that ensures uniqueness without exposing timestamps or stable client state.

State rollback or reuse across processes must not cause nonce reuse.

## Replay and Denial of Service

A stateless resolver cannot distinguish a replayed valid query from a retransmission.

An attacker can therefore cause repeated DNS processing by replaying queries, although it cannot change their authenticated contents.

Clients limit response replay by accepting only an authenticated response for a currently outstanding nonce and consuming that outstanding-query state once answered.

DNS operations with effects beyond ordinary resolution require their own replay protection.

The UDP response-size rule limits encrypted-response amplification.

Certificate retrieval has separate rules because its requests are unauthenticated and its responses can contain large public keys.

These measures do not prevent resource exhaustion: attackers can create valid queries or force failed key exchanges and authentication attempts.

Resolvers and relays may need rate limits and bounded caches.

Padding does not prevent IP fragmentation.
Large UDP packets may be fragmented or dropped, especially for PQ certificate retrieval.

TCP recovery and suitable UDP size targets improve reliability, but an attacker can still block traffic.

## Privacy

The resolver sees the DNS contents and, without a relay, the client's source address.
Observers can see packet sizes, timing, certificate requests, public keys, and nonces.
Padding reduces length information without hiding traffic patterns completely.
Using port 443 does not make DNSCrypt indistinguishable from HTTPS.

Reusing a client public key, KEM ciphertext, or resumption ticket links queries, including queries sent from different networks.

Certificate retrieval also reveals the provider name and selected resolver to observers.

Anonymized DNSCrypt separates knowledge of the client address from knowledge of the query contents only when the relay and resolver do not collude and the observer cannot correlate both sides of the exchange.

It does not protect against a global traffic observer, and the client reveals its queries to the resolver by design.

# Implementation Status

*RFC Editor: Remove this section before publication.*

The dnscrypt-proxy client and encrypted-dns-server resolver implement DNSCrypt and Anonymized DNSCrypt.

Their source repositories also contain implementations of the PQ extension described here.

These implementations informed the wire formats in this document; this statement does not imply conformance to every requirement of this revision.

A Python reference implementation and tests accompany the draft at [the document repository](https://github.com/DNSCrypt/dnscrypt-protocol).

# IANA Considerations

This document has no IANA actions.

--- back

# The Box-XChaChaPoly Algorithm {#box-xchachapoly}

The `Box-XChaChaPoly` algorithm combines the `X25519` {{!RFC7748}} key exchange mechanism with a variant of the ChaCha20-Poly1305 construction specified in {{!RFC8439}}.

## Conventions and Definitions

- `x[a..]`: the subarray of `x` starting at index `a`, and extending to the last index of `x`
- `x[a..b]`: the subarray of `x` starting at index `a` and ending immediately before index `b`.
- `LOAD32_LE(p)`: reads a little-endian 32-bit unsigned integer from the 4-byte array `p`.
- `STORE32_LE(p, x)`: stores the 32-bit unsigned integer `x` in little-endian order into the 4-byte array `p`.

## HChaCha20

`HChaCha20` is the subkey derivation step used by the extended-nonce ChaCha20 construction in this appendix.

The `HChaCha20` function takes the following input parameters:

- `<k>`: 32-byte secret key
- `<in>`: a 128-bit input

and returns a 256-bit subkey.
All subtractions below are modulo 2^32.
The loop visits indices 0 through 7.

The function can be implemented using an existing IETF-compliant `ChaCha20` implementation as follows:

~~~
block_bytes = ChaCha20(msg=zero_bytes(64), nonce=in[4..16],
                       counter=LOAD32_LE(in[0..4]), key=k)

block_out[0] = LOAD32_LE(block_bytes[ 0..][0..4]) - 0x61707865
block_out[1] = LOAD32_LE(block_bytes[ 4..][0..4]) - 0x3320646e
block_out[2] = LOAD32_LE(block_bytes[ 8..][0..4]) - 0x79622d32
block_out[3] = LOAD32_LE(block_bytes[12..][0..4]) - 0x6b206574
block_out[4] =
   LOAD32_LE(block_bytes[48..][0..4]) - LOAD32_LE(in[ 0..][0..4])
block_out[5] =
   LOAD32_LE(block_bytes[52..][0..4]) - LOAD32_LE(in[ 4..][0..4])
block_out[6] =
   LOAD32_LE(block_bytes[56..][0..4]) - LOAD32_LE(in[ 8..][0..4])
block_out[7] =
   LOAD32_LE(block_bytes[60..][0..4]) - LOAD32_LE(in[12..][0..4])

for i in 0..8:
    STORE32_LE(out[i * 4..][0..4], block_out[i])

return out
~~~

## Test Vector For The HChaCha20 Block Function

~~~ test-vectors
k:
  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f

in:
  000102030405060708090a0b0c0d0e0f

out:
  51e3ff45a895675c4b33b46c64f4a9ace110d34df6a2ceab486372bacbd3eff6
~~~

## ChaCha20_DJB

`ChaCha20_DJB` uses the ChaCha20 block function and 20 rounds of {{!RFC8439}}, with an 8-byte nonce and a 64-bit block counter.

The initial state words 0 through 3 are the constants, and words 4 through 11 hold the 32-byte key, as in RFC 8439.

Words 12 and 13 hold the low and high 32 bits of the block counter, respectively.
Words 14 and 15 hold the 8-byte nonce as two little-endian words.
The counter starts at zero unless otherwise specified and increments after each 64-byte block.
All input and output word encodings are little-endian.

## XChaCha20_DJB

XChaCha20_DJB can be constructed from an existing ChaCha20 implementation and the HChaCha20 function.

All that needs to be done is:

1. Pass the key and the first 16 bytes of the 24-byte nonce to `HChaCha20` to obtain the subkey.
2. Use the subkey and remaining 8 byte nonce with `ChaCha20_DJB`.

## XChaCha20_DJB-Poly1305

XChaCha20 is a stream cipher and offers no integrity guarantees without being combined with a MAC algorithm (e.g. Poly1305).

`XChaCha20_DJB-Poly1305` adds an authentication tag to the ciphertext encrypted with `XChaCha20_DJB`.

It is the combined mode used by the NaCl `secretbox` and `crypto_box` constructions, instantiated with `XChaCha20_DJB`.

The one-time Poly1305 key is taken from the start of the keystream, and the message is encrypted with the keystream that immediately follows it.

No separate keystream block is reserved for the Poly1305 key, so this layout differs from the AEAD of {{!RFC8439}}, where the message starts at block counter 1 and the rest of the first keystream block is discarded.

Concretely, for a key `<k>`, nonce `<n>`, and message `<m>`:

- `<k>`: encryption key
- `<n>`: 24-byte nonce
- `<m>`: message to encrypt
- `<keystream>`: the `XChaCha20_DJB` keystream produced from `<k>` and `<n>`, starting at block counter 0.
- `<poly-key>`: `<keystream>[0..32]`, the one-time Poly1305 key. These bytes are not transmitted.
- `<ct>`: `<m>` XOR `<keystream>[32..32 + length(<m>)]`, the ciphertext.
- `<tag>`: `Poly1305(<poly-key>, <ct>)`, the 16-byte tag.
- `XChaCha20_DJB-Poly1305(<k>, <n>, <m>)`: `<tag> || <ct>`

Poly1305 is computed over the ciphertext alone, using the key processing in {{!RFC8439}}.
There is no associated data, padding for MAC input, or encoded length trailer.

To decrypt, verify the 16-byte tag in constant time before releasing the plaintext; reject a short input or a tag mismatch.

Equivalently, `XChaCha20_DJB` is run over the buffer `<zero32> || <m>`, where `<zero32>` is 32 NUL bytes, starting at block counter 0; the first 32 output bytes are taken as `<poly-key>`, and the remaining `length(<m>)` bytes are `<ct>`.

## The Box-XChaChaPoly Algorithm

The Box-XChaChaPoly algorithm uses X25519 from {{!RFC7748}} with a 32-byte secret scalar as its first argument and a 32-byte public u-coordinate as its second.

It applies the scalar decoding and public-key decoding rules of that specification.

The shared X25519 result MUST be rejected if it consists entirely of NUL bytes, before applying HChaCha20.

Otherwise, the following construction derives a 32-byte key and encrypts the message:

- `<m>`: message to encrypt
- `<n>`: 24-byte nonce
- `<pk>`: recipient's public key
- `<sk>`: sender's secret key
- `<zero16>`: 16 NUL bytes
- `<sk'>`: `HChaCha20(X25519(<sk>, <pk>), <zero16>)`, the shared key
- `Box-XChaChaPoly(pk, sk, n, m)`: `XChaCha20_DJB-Poly1305(<sk'>, <n>, <m>)`

# DNSCrypt Test Vectors {#classical-vectors}

This appendix provides complete, reproducible test vectors for the regular DNSCrypt protocol with the `Box-XChaChaPoly` encryption system of {{box-xchachapoly}}, that is, `<es-version>` `0x00 0x02`: X25519 key exchange, the `XChaCha20_DJB-Poly1305` AEAD, and Ed25519 certificate signatures.

All randomness is pinned so the vectors are reproducible.

Every value is given in full as a hexadecimal string, wrapped to 32 bytes per line.

The field and byte order follow {{certificate-format}}, {{query-format}}, and {{response-format}}.

## Pinned Inputs

The secret keys below are the raw 32-byte X25519 scalars as stored by an implementation; X25519 clamps them internally.

The provider signing key is given as its 32-byte Ed25519 seed.

| Input                         | Length | Value                     |
| ----------------------------- | ------ | ------------------------- |
| provider Ed25519 signing seed | 32     | `00 01 02 ... 1f`         |
| resolver X25519 secret key    | 32     | `20 21 22 ... 3f`         |
| client X25519 secret key      | 32     | `40 41 42 ... 5f`         |
| `<client-magic>`              | 8      | `b1 b2 b3 b4 b5 b6 b7 b8` |
| `<es-version>`                | 2      | `00 02`                   |
| `<protocol-minor-version>`    | 2      | `00 00`                   |
| `<serial>`                    | 4      | `00 00 00 01`             |
| `<ts-start>`                  | 4      | `68 00 00 00`             |
| `<ts-end>`                    | 4      | `68 01 51 80`             |
| query `<client-nonce>`        | 12     | `a0 a1 a2 ... ab`         |
| response `<resolver-nonce>`   | 12     | `c0 c1 c2 ... cb`         |
| `<extensions>`                | 0      | empty                     |

`<client-magic>` is chosen by the resolver and carried in the certificate; the client copies it verbatim into the first 8 bytes of every query.

`<ts-start>` and `<ts-end>` span exactly 86400 seconds (a one-day validity window).

The fixed protocol constants are `<cert-magic>` = `44 4e 53 43`, `<es-version>` = `00 02`, and `<resolver-magic>` = `72 36 66 6e 76 57 6a 38`.

The example DNS messages are a query and its answer for `www.example.com`:

~~~
dns-query (33 bytes), id 0x1234, RD set, A? www.example.com IN:
  12340100000100000000000003777777076578616d706c6503636f6d00000100
  01
dns-response (49 bytes), A 93.184.216.34, TTL 3600:
  12348180000100010000000003777777076578616d706c6503636f6d00000100
  01c00c0001000100000e1000045db8d822
~~~

## Public Keys and Shared Key

~~~
provider-ed25519-pk = Ed25519 public key for the signing seed:
  03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8
resolver-pk = X25519 base-point mult of the resolver secret key:
  358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254
client-pk = X25519 base-point mult of the client secret key:
  79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a

x25519-shared-point = X25519(client-sk, resolver-pk)
                    = X25519(resolver-sk, client-pk):
  04c304fb1ca83cee75e206344231f33797e07d9929db670994b7c6fbeb1dc255
shared-key = HChaCha20(key = x25519-shared-point, in = 16 NUL bytes):
  335d32f2d65e6623cbbd05b6539c9575fee16cb5405fe839ab4bd291fdf13262
~~~

The same `shared-key` is computed by the client from `(client-sk, resolver-pk)` and by the resolver from `(resolver-sk, client-pk)`.

## Certificate

The signature covers `<resolver-pk> <client-magic> <serial> <ts-start> <ts-end> <extensions>`, with `<extensions>` empty in this vector:

~~~
signed input (52 bytes):
  358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254
  b1b2b3b4b5b6b7b8000000016800000068015180
signature (64 bytes), Ed25519.Sign(provider seed, signed input):
  3a570ea17f47b80217977fbb455840bfd50ab32f5fbf2aabc173a6a49b7a49ca
  55362a6c5dec47657cf515e9f99382a316dfecd964b94d1c4659cac45961400c
~~~

The full certificate, as carried in a `TXT` record, is 124 bytes:

| Offset | Field                      | Length | Value                     |
| ------ | -------------------------- | ------ | ------------------------- |
| 0      | `<cert-magic>`             | 4      | `44 4e 53 43`             |
| 4      | `<es-version>`             | 2      | `00 02`                   |
| 6      | `<protocol-minor-version>` | 2      | `00 00`                   |
| 8      | `<signature>`              | 64     | `3a 57 ... 40 0c`         |
| 72     | `<resolver-pk>`            | 32     | `35 80 ... 62 54`         |
| 104    | `<client-magic>`           | 8      | `b1 b2 b3 b4 b5 b6 b7 b8` |
| 112    | `<serial>`                 | 4      | `00 00 00 01`             |
| 116    | `<ts-start>`               | 4      | `68 00 00 00`             |
| 120    | `<ts-end>`                 | 4      | `68 01 51 80`             |

~~~
certificate (124 bytes):
  444e5343000200003a570ea17f47b80217977fbb455840bfd50ab32f5fbf2aab
  c173a6a49b7a49ca55362a6c5dec47657cf515e9f99382a316dfecd964b94d1c
  4659cac45961400c358072d6365880d1aeea329adf9121383851ed21a28e3b75
  e965d0d2cd166254b1b2b3b4b5b6b7b8000000016800000068015180
~~~

## Certificate Retrieval {#classical-certificate-retrieval-vector}

The certificate lookup name is `2.dnscrypt-cert.example.com`.

With DNS transaction ID `0xabcd`, RD set, one `TXT`/`IN` question, and no EDNS(0) padding, the DNS request is:

~~~
certificate query (45 bytes):
  abcd0100000100000000000001320d646e7363727970742d6365727407657861
  6d706c6503636f6d0000100001
~~~

The successful response carrying the 124-byte certificate above is 182 bytes.

This is the classical certificate response used by deployed DNSCrypt v2 resolvers: the flags word `0x8180` sets QR and RA, echoes RD from the query, and leaves RCODE at 0.

The TXT record TTL is an operational choice, 86400 seconds in this vector.

If larger PQ certificate records are also available, a resolver can return this classical response with the TC flag set when the complete classical-plus-PQ response would exceed the triggering UDP request.

~~~
certificate response with one TXT answer (182 bytes):
  abcd8180000100010000000001320d646e7363727970742d6365727407657861
  6d706c6503636f6d0000100001c00c0010000100015180007d7c444e53430002
  00003a570ea17f47b80217977fbb455840bfd50ab32f5fbf2aabc173a6a49b7a
  49ca55362a6c5dec47657cf515e9f99382a316dfecd964b94d1c4659cac45961
  400c358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd
  166254b1b2b3b4b5b6b7b8000000016800000068015180
~~~

An EDNS(0)-padded UDP certificate query for the same question and transaction ID can be built by setting `ARCOUNT = 1` and appending one `OPT` pseudo-RR with UDP payload size 4096 and a Padding option.

For a 512-byte request, the Padding option data is 452 NUL bytes:

~~~
base question length       = 45
OPT pseudo-RR fixed header = 11
Padding option header      = 4
Padding option data        = 452
total request length       = 512

OPT pseudo-RR:
  00002910000000000001c8000c01c4 || (452 * 00)
~~~

## Client Query (UDP)

For this fixed vector, the plaintext is the DNS query padded with ISO/IEC 7816-4 to 256 bytes: one `0x80` byte followed by NUL bytes.

The complete encrypted DNSCrypt query is 324 bytes, which is above the initial 256-byte UDP query-size target.

The 24-byte AEAD nonce is the 12-byte client nonce followed by 12 NUL bytes.

~~~
padded query plaintext (256 bytes):
  12340100000100000000000003777777076578616d706c6503636f6d00000100
  0180000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000
query AEAD nonce (24 bytes):
  a0a1a2a3a4a5a6a7a8a9aaab000000000000000000000000
encrypted-query = tag (16) || ciphertext (256) (272 bytes):
  2dae527c26386d5cd4e61152db6dd1812ff6aaf7644fc122afc70b1b580b18f1
  0fbc26577abc759152cde31cd0afc5c5f452f8654815469723300819bed5a120
  15c044b94d63ec1f79e48a23968e437feb8bb8720cf4e60a0499746190c8b3eb
  83aeb0d858df77794270b861f86644502be0d22d6f0b2b132e9ca68538300c8d
  68b8e3c48190cbbf96d602f38dfc3b4d642016ceeaf4bc2c2ded9483b9f9d4ee
  d703a0bebc252add8822d4b9152e30670bcde9ea75a0e3e67ea576e9b1262bb2
  b25b4f9432311b75a2238b34bf4f868da182b85dccb1762a703bba31d04d77b4
  c57ec9039663959793677588b3a74ae409b0f16374dd64cbd6d47d801725b014
  ce9ddaf6f1aa30688c8efcbfde1d5d1d
~~~

Query on the wire (324 bytes):

| Offset | Field               | Length | Value                     |
| ------ | ------------------- | ------ | ------------------------- |
| 0      | `<client-magic>`    | 8      | `b1 b2 b3 b4 b5 b6 b7 b8` |
| 8      | `<client-pk>`       | 32     | `79 a6 ... a5 1a`         |
| 40     | `<client-nonce>`    | 12     | `a0 a1 ... ab`            |
| 52     | `<encrypted-query>` | 272    | `2d ae ... d5 1d`         |

~~~
full query wire (324 bytes):
  b1b2b3b4b5b6b7b879a631eede1bf9c98f12032cdeadd0e7a079398fc786b88c
  c846ec89af85a51aa0a1a2a3a4a5a6a7a8a9aaab2dae527c26386d5cd4e61152
  db6dd1812ff6aaf7644fc122afc70b1b580b18f10fbc26577abc759152cde31c
  d0afc5c5f452f8654815469723300819bed5a12015c044b94d63ec1f79e48a23
  968e437feb8bb8720cf4e60a0499746190c8b3eb83aeb0d858df77794270b861
  f86644502be0d22d6f0b2b132e9ca68538300c8d68b8e3c48190cbbf96d602f3
  8dfc3b4d642016ceeaf4bc2c2ded9483b9f9d4eed703a0bebc252add8822d4b9
  152e30670bcde9ea75a0e3e67ea576e9b1262bb2b25b4f9432311b75a2238b34
  bf4f868da182b85dccb1762a703bba31d04d77b4c57ec9039663959793677588
  b3a74ae409b0f16374dd64cbd6d47d801725b014ce9ddaf6f1aa30688c8efcbf
  de1d5d1d
~~~

## Server Response (UDP)

The plaintext is the DNS response padded with ISO/IEC 7816-4 to 64 bytes.

The 24-byte AEAD nonce is the client nonce followed by the resolver nonce.

~~~
padded response plaintext (64 bytes):
  12348180000100010000000003777777076578616d706c6503636f6d00000100
  01c00c0001000100000e1000045db8d822800000000000000000000000000000
response AEAD nonce (24 bytes):
  a0a1a2a3a4a5a6a7a8a9aaabc0c1c2c3c4c5c6c7c8c9cacb
encrypted-response = tag (16) || ciphertext (64) (80 bytes):
  f2670995c6d37c2f8d2016029dd5970b893de83c02815ece9b48d9fd0b0dca87
  41674142fbd8e12c1120b111f366326aa71c89823a2931ac5c860dad49685ed6
  cc22cc13e829d2e51d1c00ea64d1d39d
~~~

Response on the wire (112 bytes):

| Offset | Field                  | Length | Value                                 |
| ------ | ---------------------- | ------ | ------------------------------------- |
| 0      | `<resolver-magic>`     | 8      | `72 36 66 6e 76 57 6a 38`             |
| 8      | `<nonce>`              | 24     | `a0..ab` (client) `c0..cb` (resolver) |
| 32     | `<encrypted-response>` | 80     | `f2 67 ... d3 9d`                     |

~~~
full response wire (112 bytes):
  7236666e76576a38a0a1a2a3a4a5a6a7a8a9aaabc0c1c2c3c4c5c6c7c8c9cacb
  f2670995c6d37c2f8d2016029dd5970b893de83c02815ece9b48d9fd0b0dca87
  41674142fbd8e12c1120b111f366326aa71c89823a2931ac5c860dad49685ed6
  cc22cc13e829d2e51d1c00ea64d1d39d
~~~

## Padding and Transport Notes

The vectors fix the padded plaintext lengths so they are reproducible:

- The query plaintext is padded to 256 bytes for this vector. Production clients can choose larger targets for the complete encrypted DNSCrypt packet; for example, a client can target a 512-byte-or-larger UDP packet and compute the plaintext padding after subtracting DNSCrypt overhead.
- The response plaintext is padded to the smallest multiple of 64 that holds the response plus at least one padding byte, here 64 bytes. The exact response padding length is otherwise an implementation choice, subject to the encrypted UDP response being no larger than the encrypted query.
- Over TCP the encryption is identical, but each packet is prefixed with a two-byte big-endian length, and the query padding length is chosen at random as described in {{padding}}. For the fixed packets above, the 324-byte query is prefixed with `01 44`, and the 112-byte response is prefixed with `00 70`.

## Negative Cases

The following cases exercise certificate validation and packet rejection.

1. Tampered ciphertext: flipping any byte of `<encrypted-query>` or `<encrypted-response>` makes Poly1305 verification fail. The receiver MUST drop the packet.

2. Bad padding: after a successful decryption, the plaintext MUST end with a `0x80` byte followed by zero or more NUL bytes. A plaintext that does not MUST be rejected.

3. Wrong `<client-magic>`: a query whose first 8 bytes do not match the `<client-magic>` of any certificate the resolver currently serves is not a DNSCrypt query for this resolver. The resolver MUST NOT treat it as one.

4. Response nonce mismatch: the client MUST verify that the `<client-nonce>` prefix (first 12 bytes) of the response nonce matches an outstanding query, and otherwise drop the response.

5. Weak public key: if the X25519 shared point is the all-zero value, the public key is of low order and the shared key MUST be rejected.

6. Certificate outside its validity window: a certificate whose `<ts-start>`/`<ts-end>` does not include the current time MUST NOT be used, and selection follows {{certificate-validation}}.

# PQ Test Vectors {#pq-vectors}

This appendix fixes the exact field order and byte order for PQ.

The layouts below name the intermediate cryptographic values.
The Generated Values subsection gives their bytes or SHA-256 digests for comparison.

All integers are big-endian.

Every AEAD operation is `XChaCha20_DJB-Poly1305` as defined in {{box-xchachapoly}}, with the 16-byte tag prepended to the ciphertext.

Every DNSCrypt key derivation following the X-Wing operation uses HKDF-SHA256 {{!RFC5869}}.

Labels such as `[name: N bytes]` refer to the values in {{pq-generated-values}}.

## Parameters

The vectors use the wire identifiers defined in {{pq}} and the reference ticket construction in {{pq-ticket-issuance}}.

| Item                       | Value                                  |
| -------------------------- | -------------------------------------- |
| `<es-version>` (X-Wing)    | `0x00 0x03`                            |
| `<resume-magic>`           | `50 51 52 65 73 75 6d 65` ("PQResume") |
| `<kdf-id>`                 | `0x01` (HKDF-SHA256)                   |
| `<aead-id>`                | `0x01` (XChaCha20_DJB-Poly1305)        |
| ticket AEAD                | XChaCha20_DJB-Poly1305, 24-byte nonce  |
| `<ticket-key-id>`          | 4 bytes                                |
| `<ticket-nonce>`           | 24 bytes                               |
| `<ticket-expiry>`          | 4-byte Unix timestamp                  |
| `<ticket-lifetime>`        | 4-byte seconds                         |
| `<profile-extension-hash>` | `SHA-256(<extensions>)`, 32 bytes      |

## Pinned Inputs

All randomness is fixed so the vectors are reproducible.

The tables name longer values that appear in {{pq-generated-values}}.

| Input                                  | Length | Value                       |
| -------------------------------------- | ------ | --------------------------- |
| provider Ed25519 signing seed          | 32     | `00 01 02 ... 1f`           |
| provider Ed25519 public key            | 32     | `[provider-pk: 32 bytes]`   |
| resolver X-Wing secret seed            | 32     | `20 21 22 ... 3f`           |
| resolver X-Wing public key             | 1216   | `[resolver-pk: 1216 bytes]` |
| client X-Wing encapsulation seed       | 64     | `40 41 42 ... 7f`           |
| `<es-version>`                         | 2      | `00 03`                     |
| `<protocol-minor-version>`             | 2      | `00 00`                     |
| `<client-magic>`                       | 8      | `a1 b2 c3 d4 e5 f6 07 18`   |
| `<serial>`                             | 4      | `00 00 00 01`               |
| `<ts-start>`                           | 4      | `68 00 00 00`               |
| `<ts-end>`                             | 4      | `68 01 51 80`               |
| query `<client-nonce>`                 | 12     | `b0 b1 b2 ... bb`           |
| response `<resolver-nonce>`            | 12     | `c0 c1 c2 ... cb`           |
| ticket key `TK`                        | 32     | `80 81 82 ... 9f`           |
| `<ticket-key-id>`                      | 4      | `00 00 00 01`               |
| `<ticket-nonce>`                       | 24     | `d0 d1 d2 ... e7`           |
| `<ticket-expiry>`                      | 4      | `68 00 02 58`               |
| `<ticket-lifetime>`                    | 4      | `00 00 01 2c`               |
| resumed `<client-nonce>`               | 12     | `f0 f1 f2 ... fb`           |
| resumed `<resolver-nonce>`             | 12     | `10 11 12 ... 1b`           |
| example DNS query (A? www.example.com) | 33     | `[dns-query: 33 bytes]`     |
| example DNS response                   | var    | `[dns-response]`            |

## Profile Extension and Signature Input

The PQ profile extension is the entire `<extensions>` field in this revision:

~~~
pq-profile-ext =
    "PQD"             50 51 44
    ext-version       01
    es-version        00 03
    kdf-id            01            (HKDF-SHA256)
    aead-id           01            (XChaCha20_DJB-Poly1305)
    resolver-pk-len   04 c0         (1216)
    client-kex-len    04 60         (1120)
                                    -> 12 bytes total
~~~

The Ed25519 signature is computed over the existing field set, unchanged:

~~~
sig-input = resolver-pk (1216) || client-magic (8) || serial (4)
            || ts-start (4) || ts-end (4) || extensions (12)
          -> 1248 bytes
signature = Ed25519.Sign(provider-seed, sig-input)
          = [signature: 64 bytes]
~~~

The full certificate (92 fixed bytes + 1216-byte resolver key + 12-byte extensions = 1320 bytes):

| Offset | Field                      | Length | Value                                 |
| ------ | -------------------------- | ------ | ------------------------------------- |
| 0      | `<cert-magic>`             | 4      | `44 4e 53 43`                         |
| 4      | `<es-version>`             | 2      | `00 03`                               |
| 6      | `<protocol-minor-version>` | 2      | `00 00`                               |
| 8      | `<signature>`              | 64     | `[signature: 64 bytes]`               |
| 72     | `<resolver-pk>`            | 1216   | `[resolver-pk: 1216 bytes]`           |
| 1288   | `<client-magic>`           | 8      | `a1 b2 c3 d4 e5 f6 07 18`             |
| 1296   | `<serial>`                 | 4      | `00 00 00 01`                         |
| 1300   | `<ts-start>`               | 4      | `68 00 00 00`                         |
| 1304   | `<ts-end>`                 | 4      | `68 01 51 80`                         |
| 1308   | `<extensions>`             | 12     | `50 51 44 01 00 03 01 01 04 c0 04 60` |

## Full X-Wing Query

The deterministic functions are those of {{!I-D.connolly-cfrg-xwing-kem}}.

`resolver-seed` is the 32-byte resolver seed above, and `eseed` is the 64-byte client encapsulation seed.

~~~
(resolver-sk, resolver-pk) =
    X-Wing.GenerateKeyPairDerand(resolver-seed)
(kem-ss, ct) = X-Wing.EncapsulateDerand(resolver-pk, eseed)
    ct      = [ct: 1120 bytes]
    kem-ss  = [kem-ss: 32 bytes]

cert-context = "DNSCrypt-PQ-v1"            (14 bytes)
            || es-version (00 03)
            || protocol-minor-version (00 00)
            || resolver-pk (1216) || client-magic (8)
            || serial (4) || ts-start (4) || ts-end (4)
            || extensions (12)

shared-key = HKDF-SHA256(
                 IKM  = kem-ss,
                 salt = es-version || client-magic
                        (10 bytes: 00 03 a1 b2 c3 d4 e5 f6 07 18),
                 info = cert-context || ct,
                 L    = 32)
           = [shared-key: 32 bytes]

query-nonce = client-nonce || (12 * 00)      (24 bytes)
plaintext   = dns-query (33) || 80 || (30 * 00)
              (padded to 64; ISO/IEC 7816-4)
encrypted-query = tag (16) || ciphertext (64)
                = [enc-query: 80 bytes]
~~~

Query on the wire (1220 bytes):

| Offset | Field                | Length | Value                     |
| ------ | -------------------- | ------ | ------------------------- |
| 0      | `<client-magic>`     | 8      | `a1 b2 c3 d4 e5 f6 07 18` |
| 8      | `<client-pk>` = `ct` | 1120   | `[ct: 1120 bytes]`        |
| 1128   | `<client-nonce>`     | 12     | `b0 b1 ... bb`            |
| 1140   | `<encrypted-query>`  | 80     | `[enc-query: 80 bytes]`   |

## Full Response and Ticket Issuance

For this vector, the ticket is issued at Unix time `0x6800012c`.

Its advertised lifetime is 300 seconds, giving the sealed expiry `0x68000258`.

~~~
resume-secret = HKDF-SHA256(
                    IKM  = shared-key,
                    salt = client-magic || client-nonce,
                    info = "DNSCrypt-PQ-resume-secret-v1",
                    L    = 32)
              = [resume-secret: 32 bytes]

profile-extension-hash = SHA-256(extensions) = [peh: 32 bytes]

ticket-plain = resume-secret (32) || es-version (2)
            || client-magic (8)
            || serial (4) || ts-end (4) || ticket-expiry (4)
            || profile-extension-hash (32)   (86 bytes)

ticket = ticket-key-id (4) || ticket-nonce (24)
      || AE(TK, ticket-nonce, ticket-plain)
         where AE output = tag (16) || ciphertext (86)
      -> 4 + 24 + 102 = 130 bytes            = [ticket: 130 bytes]

control = "PQDR" (50 51 44 52) || control-version (01)
       || ticket-lifetime (00 00 01 2c) || ticket-len (00 82)
       || ticket (130)                       (141 bytes)

pq-response-plain = control-len (00 8d) || control (141)
                  || dns-response || pad-to-64

response-nonce = client-nonce || resolver-nonce   (24 bytes)
encrypted-response = tag (16) || ciphertext       = [enc-response]
~~~

Response on the wire:

| Field                  | Length | Value                                 |
| ---------------------- | ------ | ------------------------------------- |
| `<resolver-magic>`     | 8      | `72 36 66 6e 76 57 6a 38`             |
| `<nonce>`              | 24     | `b0..bb` (client) `c0..cb` (resolver) |
| `<encrypted-response>` | var    | `[enc-response]`                      |

## Resumed Query and Response

~~~
resumed shared-key = HKDF-SHA256(
                         IKM  = resume-secret,
                         salt = client-magic
                                || resumed-client-nonce
                                (20 bytes),
                         info = "DNSCrypt-PQ-resumed-query-v1"
                                || SHA-256(ticket),
                         L    = 32)
                  = [resumed-shared-key: 32 bytes]

query-nonce = resumed-client-nonce || (12 * 00)   (24 bytes)
plaintext   = dns-query || 80 || pad
              (padded to 256 for this vector)
encrypted-query = tag (16) || ciphertext (256)
                = [enc-query: 272 bytes]
~~~

Resumed query on the wire (424 bytes):

| Offset | Field               | Length | Value                     |
| ------ | ------------------- | ------ | ------------------------- |
| 0      | `<resume-magic>`    | 8      | `50 51 52 65 73 75 6d 65` |
| 8      | `<ticket-len>`      | 2      | `00 82` (130)             |
| 10     | `<ticket>`          | 130    | `[ticket: 130 bytes]`     |
| 140    | `<client-nonce>`    | 12     | `f0 f1 ... fb`            |
| 152    | `<encrypted-query>` | 272    | `[enc-query: 272 bytes]`  |

The resumed response reuses `resumed shared-key` with nonce `resumed-client-nonce || resumed-resolver-nonce`.

If the resolver issues no new ticket, the control block is empty (`control-len = 00 00`).

## Negative Cases

The following cases exercise certificate validation and packet rejection.

1. Bad profile-extension length: `resolver-pk-len` or `client-kex-len` in the extension disagrees with the actual field length, or `pq-profile-ext` is not 12 bytes. The client MUST reject the certificate.

2. `<es-version>` mismatch: the on-the-wire `<es-version>` differs from the copy inside the signed extension. The client MUST reject the certificate.

3. Corrupted ticket AEAD: one byte of the sealed region of `<ticket>` in a resumed query is flipped. AEAD opening fails, and the resolver MUST silently drop the query.

4. Expired or rotated ticket: `<ticket-expiry>` is in the past, or `<ticket-key-id>` names a `TK` that has been rotated out. The resolver MUST silently drop the query; the client re-handshakes with a query that carries a ciphertext.

5. Ticket context mismatch: any sealed certificate-context field in the ticket (`<es-version>`, `<client-magic>`, `<serial>`, `<ts-end>`, or `<profile-extension-hash>`) does not match the resumption context. The resolver MUST silently drop the query.

6. Tampered KEM ciphertext: change a byte in its ML-KEM component while leaving the encrypted query unchanged.
   ML-KEM implicit rejection changes the X-Wing shared secret, authentication fails, and the resolver MUST silently discard the query.
   Decapsulation and authentication must not reveal secret-dependent information through timing.
7. Repeated nonce: encrypting a new query with a previously used `<client-nonce>` under the same ticket repeats both the derived key and the AEAD nonce, violating {{pq-resumed-query}}.
   A stateless resolver cannot detect this; retransmitting an identical packet is permitted.

8. A resumed UDP query below the 256-byte query-size target remains decryptable.
   Its smaller response budget may require an authenticated response with TC set.
   A relay MUST discard a response that exceeds the inner query size.

## Generated Values {#pq-generated-values}

The values below were produced by a reference generator from the pinned inputs above, and are reproducible by any conformant implementation.

Values up to 141 bytes are given in full; longer artifacts are pinned by their SHA-256 digest.

X-Wing key generation and encapsulation use the deterministic functions in {{!I-D.connolly-cfrg-xwing-kem}}, with the seeds listed above.

~~~
provider-ed25519-pk (32):
  03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8
resolver-pk (1216, SHA-256):
  a1f324bc0701f1234fbba7b11901023b3644f3bb8c6eb4ee4368d7e859eb6228
client-kex / ct (1120, SHA-256):
  f6bf3f238e83f24cd444f2887e8fd32d630e07dbe6ca2f2b403aaf5333030c48
kem-ss (32):
  8dac8602d4ce5e27e81335b54b25fdcaea86e56613214ee0522db4a5e0a38d50
shared-key (32):
  e6d4ab9cffc9b49e2a64d80d7eb2dde280f806b89e834d596ad385b1dd75e9ef
signature (64):
  811bab04e2e70c9d946296a93b4028d7c7bb84f32f597d3cf8aba29edc1b6b97
  4acc99dd00ec62cdcae477433d10bff20e1c432e1011ad8ad5324f68a294750c

dns-query (33):
  12340100000100000000000003777777076578616d706c6503636f6d00000100
  01
dns-response (49):
  12348180000100010000000003777777076578616d706c6503636f6d00000100
  01c00c0001000100000e1000045db8d822
padded query plaintext (64):
  12340100000100000000000003777777076578616d706c6503636f6d00000100
  0180000000000000000000000000000000000000000000000000000000000000
encrypted-query (80):
  c41764468cb42d3a837c51234c08be714af49e1a6830ea6da28178e9e280d76b
  ac1b87fd7f56515f2b2cc3d4715aaa42907c282db1edff0bc3b92cd535a710e2
  64859a5bdaf67c17ffa6e1c6f6e02a50
full query wire (1220, SHA-256):
  65c3421776283f503779916e7b5c32d0d41c885508ad892b349688db6c901233

resume-secret (32):
  df158804e3f8ddf383ff7c9d3128491b29437a894936ec72c68aed8a9553272b
profile-extension-hash = SHA-256(extensions) (32):
  fab3bf4996c5d2fdfc330ec958d0a5b63624bf3fbdc0fedfa9d94b0941a4060c
ticket-plain (86):
  df158804e3f8ddf383ff7c9d3128491b29437a894936ec72c68aed8a9553272b
  0003a1b2c3d4e5f60718000000016801518068000258fab3bf4996c5d2fdfc33
  0ec958d0a5b63624bf3fbdc0fedfa9d94b0941a4060c
ticket (130):
  00000001d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e1d90c86
  474574e0e51e82d8a29938896b0999e827138f8f452f21e044d9809f65a013cf
  ad8981be94c1354178b3e03dd518c28bcbaab962aa45246e446de7763288aa4a
  01e207725a0ae7bc95452fef3743f6083deb10cd23e2881e8d9307fc2f43bce1
  a97e
control (141):
  50514452010000012c008200000001d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0
  e1e2e3e4e5e6e7e1d90c86474574e0e51e82d8a29938896b0999e827138f8f45
  2f21e044d9809f65a013cfad8981be94c1354178b3e03dd518c28bcbaab962aa
  45246e446de7763288aa4a01e207725a0ae7bc95452fef3743f6083deb10cd23
  e2881e8d9307fc2f43bce1a97e
response plaintext, padded to 256 (256, SHA-256):
  a215df14b59d272b506224ed1f6ab5956be2bf189f847dfac4f8649c5f94d99e
full response wire (304, SHA-256):
  33c081503d5ead4061a30d3f095fc9f226b8c01c3bbffa8fc6f4d9b15087de5c

sha256(ticket) (32):
  fb196d81022c6b480f1340c80987088a85145194c18441928a4ae8e5a153536c
resumed shared-key (32):
  e61f03acb2ee2ef01b952a0c312c60653267d47a2766fcfd804747fdf2fe789f
resumed encrypted-query (272, SHA-256):
  60323805036492350ee442ee4dcb097597fb586e3f2c8a1f26feb9cdd0409b29
resume query wire (424, SHA-256):
  34be2e331b4d7c7e808e968c5efc9f25675a9de9064cb33f7c66950e0e4e6db7
resume response wire, no new ticket (112, SHA-256):
  2bf202dd3f33d38854450e70a02bd1a317a23bf6d79c5dae406787c9c5f34f52
~~~
