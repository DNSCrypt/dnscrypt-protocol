"""TCP framing, packet size bounds, and Anonymized DNSCrypt relaying."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Container

from constants import ANON_MAGIC, MAX_DNSCRYPT_PACKET_SIZE, QUIC_MAGIC
from errors import AmplificationError, RelayError, WireFormatError

__all__ = [
    "AnonymizedDNSCryptQuery",
    "anonymized_dnscrypt_query",
    "check_query_size",
    "check_response_size",
    "parse_anonymized_dnscrypt_query",
    "read_tcp_packet",
    "relay_certificate_response",
    "tcp_packet",
    "validate_relay_query",
]


@dataclass(frozen=True)
class AnonymizedDNSCryptQuery:
    """Parsed Anonymized DNSCrypt forwarding prefix and inner query."""

    server_ip: ipaddress.IPv6Address
    server_port: int
    dnscrypt_query: bytes


def check_query_size(dnscrypt_query: bytes) -> None:
    """Enforce the Transport rule: complete queries stay within 4096 bytes."""

    if len(dnscrypt_query) > MAX_DNSCRYPT_PACKET_SIZE:
        raise ValueError("complete encrypted query exceeds 4096 bytes")


def check_response_size(dnscrypt_response: bytes) -> None:
    """Enforce the Transport rule: complete responses stay below 4096 bytes."""

    if len(dnscrypt_response) >= MAX_DNSCRYPT_PACKET_SIZE:
        raise ValueError("complete encrypted response must be smaller than 4096 bytes")


def tcp_packet(packet: bytes) -> bytes:
    """Prefix a DNSCrypt packet with its two-byte TCP length."""

    if len(packet) > 0xFFFF:
        raise ValueError("TCP-framed packet is too large")
    return len(packet).to_bytes(2, "big") + packet


def read_tcp_packet(stream: bytes) -> bytes:
    """Remove and validate a two-byte TCP length prefix."""

    if len(stream) < 2:
        raise WireFormatError("TCP stream is shorter than the length prefix")
    packet_len = int.from_bytes(stream[:2], "big")
    if len(stream) != 2 + packet_len:
        raise WireFormatError("TCP stream length does not match the prefix")
    return stream[2:]


def anonymized_dnscrypt_query(
    server_ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address,
    server_port: int,
    dnscrypt_query: bytes,
) -> bytes:
    """Prefix a standard DNSCrypt query for Anonymized DNSCrypt."""

    ip = ipaddress.ip_address(server_ip)
    if isinstance(ip, ipaddress.IPv4Address):
        ip = ipaddress.IPv6Address("::ffff:" + str(ip))
    if not 0 <= server_port <= 0xFFFF:
        raise ValueError("server_port must fit in 16 bits")
    return ANON_MAGIC + ip.packed + server_port.to_bytes(2, "big") + dnscrypt_query


def parse_anonymized_dnscrypt_query(packet: bytes) -> AnonymizedDNSCryptQuery:
    """Parse an Anonymized DNSCrypt query prefix."""

    header_len = len(ANON_MAGIC) + 16 + 2
    if len(packet) < header_len:
        raise WireFormatError("Anonymized DNSCrypt query is too short")
    if packet[: len(ANON_MAGIC)] != ANON_MAGIC:
        raise WireFormatError("invalid Anonymized DNSCrypt magic")
    server_ip = ipaddress.IPv6Address(packet[len(ANON_MAGIC) : len(ANON_MAGIC) + 16])
    server_port = int.from_bytes(packet[len(ANON_MAGIC) + 16 : header_len], "big")
    return AnonymizedDNSCryptQuery(server_ip, server_port, packet[header_len:])


def validate_relay_query(
    query: AnonymizedDNSCryptQuery, allowed_ports: Container[int] = (443,)
) -> None:
    """Apply the relay validation rules before forwarding to the target.

    The target must be globally routable, the port must be allowed by local
    policy, and the inner query must be neither another Anonymized DNSCrypt
    query nor a packet that could be confused with QUIC.
    """

    target = query.server_ip.ipv4_mapped or query.server_ip
    if target.is_multicast or not target.is_global:
        raise RelayError("target address is not globally routable")
    if query.server_port not in allowed_ports:
        raise RelayError("target port is not allowed")
    if query.dnscrypt_query.startswith(ANON_MAGIC):
        raise RelayError("nested Anonymized DNSCrypt queries are not relayed")
    if query.dnscrypt_query.startswith(QUIC_MAGIC):
        raise RelayError("inner query could be confused with QUIC")


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
