"""Unauthenticated certificate retrieval and its anti-amplification rule."""

from __future__ import annotations

from typing import Sequence

from constants import (
    CERTIFICATE_RECORD_TTL,
    DNS_CLASS_IN,
    DNS_HEADER_SIZE,
    DNS_TYPE_OPT,
    DNS_TYPE_TXT,
    EDNS_PADDING_OPTION_CODE,
    EDNS_UDP_PAYLOAD_SIZE,
)
from errors import AmplificationError


def _dns_name(name: str) -> bytes:
    """Encode a domain name as a sequence of length-prefixed labels."""

    wire = b""
    for label in name.rstrip(".").split("."):
        encoded = label.encode("ascii")
        if not 1 <= len(encoded) <= 63:
            raise ValueError("each DNS label must be 1 to 63 bytes")
        wire += bytes([len(encoded)]) + encoded
    return wire + b"\x00"


def _edns_padding(padding_len: int) -> bytes:
    """Build an EDNS(0) OPT record carrying a padding option (RFC 7830)."""

    option = (
        EDNS_PADDING_OPTION_CODE.to_bytes(2, "big")
        + padding_len.to_bytes(2, "big")
        + b"\x00" * padding_len
    )
    return (
        b"\x00"  # root owner name
        + DNS_TYPE_OPT.to_bytes(2, "big")
        + EDNS_UDP_PAYLOAD_SIZE.to_bytes(2, "big")
        + b"\x00\x00\x00\x00"  # extended rcode, version, flags
        + len(option).to_bytes(2, "big")
        + option
    )


def _question_end(packet: bytes) -> int:
    """Return the offset just past the single question of a DNS message."""

    if len(packet) < DNS_HEADER_SIZE:
        raise ValueError("DNS message is shorter than its header")
    if packet[4:6] != b"\x00\x01":
        raise ValueError("a certificate query carries exactly one question")
    offset = DNS_HEADER_SIZE
    while True:
        if offset >= len(packet):
            raise ValueError("DNS question name is truncated")
        label_len = packet[offset]
        if label_len & 0xC0:
            raise ValueError("unexpected compression pointer in question name")
        offset += 1 + label_len
        if label_len == 0:
            break
    if offset + 4 > len(packet):
        raise ValueError("DNS question is missing its type and class")
    return offset + 4


def _txt_rdata(certificate: bytes) -> bytes:
    """Split a certificate into TXT character-strings of at most 255 bytes."""

    chunks = [certificate[i : i + 255] for i in range(0, len(certificate), 255)]
    return b"".join(bytes([len(chunk)]) + chunk for chunk in chunks)


def _txt_answer(certificate: bytes, ttl: int) -> bytes:
    """Encode one certificate as a TXT answer record."""

    rdata = _txt_rdata(certificate)
    return (
        b"\xc0\x0c"  # owner name: compression pointer to the question
        + DNS_TYPE_TXT.to_bytes(2, "big")
        + DNS_CLASS_IN.to_bytes(2, "big")
        + ttl.to_bytes(4, "big")
        + len(rdata).to_bytes(2, "big")
        + rdata
    )


def certificate_query(
    provider_name: str,
    query_id: bytes = b"\x00\x00",
    padded_length: int = 0,
) -> bytes:
    """Build an unencrypted TXT certificate query, optionally EDNS(0)-padded.

    A client that wants the larger PQ certificates over UDP pads the query to at
    least the expected response size, so the response stays within the request and
    passes the anti-amplification check at the resolver and at any relay.
    """

    question = (
        _dns_name(provider_name)
        + DNS_TYPE_TXT.to_bytes(2, "big")
        + DNS_CLASS_IN.to_bytes(2, "big")
    )
    additional = b""
    arcount = b"\x00\x00"
    if padded_length > 0:
        opt_overhead = 15  # OPT record header (11) and padding option header (4)
        padding = max(0, padded_length - DNS_HEADER_SIZE - len(question) - opt_overhead)
        additional = _edns_padding(padding)
        arcount = b"\x00\x01"
    header = (
        query_id
        + b"\x01\x00"  # standard query, recursion desired
        + b"\x00\x01"  # qdcount
        + b"\x00\x00"  # ancount
        + b"\x00\x00"  # nscount
        + arcount
    )
    return header + question + additional


def build_certificate_response(
    request: bytes,
    certificates: Sequence[bytes],
    truncated: bool = False,
    ttl: int = CERTIFICATE_RECORD_TTL,
) -> bytes:
    """Assemble a TXT certificate response that echoes the request's question.

    Each certificate becomes one TXT answer record. The request's OPT record and
    padding are not echoed, exactly as a resolver answers a plain TXT query.
    """

    question = request[DNS_HEADER_SIZE : _question_end(request)]
    answers = b"".join(_txt_answer(certificate, ttl) for certificate in certificates)
    flags = 0x8400  # response, authoritative
    flags |= request[2] & 0x01  # preserve recursion-desired
    flags |= 0x0080  # recursion available
    if truncated:
        flags |= 0x0200  # TC: the full answer did not fit
    header = (
        request[0:2]
        + flags.to_bytes(2, "big")
        + b"\x00\x01"  # qdcount
        + len(certificates).to_bytes(2, "big")  # ancount
        + b"\x00\x00"  # nscount
        + b"\x00\x00"  # arcount
    )
    return header + question + answers


def serve_certificates(
    request: bytes,
    classical_certificates: Sequence[bytes],
    pq_certificates: Sequence[bytes],
    over_udp: bool,
) -> bytes:
    """Answer a certificate query under the anti-amplification rule.

    The classical certificate is always returned for compatibility with deployed
    DNSCrypt v2 clients and resolvers. The large PQ certificates are added over
    UDP only when the complete response still fits within the request that
    triggered it, because otherwise a spoofed query could amplify traffic. When
    the PQ certificates do not fit, the response carries the classical
    certificates with the TC bit set and a PQ-capable client retries over TCP.
    Over TCP the handshake validates the source, so all certificates are always
    included.
    """

    full = build_certificate_response(
        request, [*classical_certificates, *pq_certificates]
    )
    if not over_udp or not pq_certificates or len(full) <= len(request):
        return full
    return build_certificate_response(request, classical_certificates, truncated=True)


def relay_certificate_response(
    forwarded_query: bytes, upstream_response: bytes
) -> bytes:
    """Forward a certificate response only if it respects anti-amplification.

    An Anonymized DNSCrypt relay forwards the certificate query upstream over UDP
    and must never return more bytes to the client than the client sent, so a
    response larger than the forwarded query is rejected.
    """

    if len(upstream_response) > len(forwarded_query):
        raise AmplificationError("certificate response is larger than the query")
    return upstream_response
