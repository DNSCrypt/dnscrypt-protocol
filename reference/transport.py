"""TCP framing and Anonymized DNSCrypt helpers."""

from __future__ import annotations

import ipaddress

from .constants import ANON_MAGIC
from .types import AnonymizedDNSCryptQuery


def tcp_packet(packet: bytes) -> bytes:
    """Prefix a DNSCrypt packet with its two-byte TCP length."""

    if len(packet) > 0xFFFF:
        raise ValueError("TCP-framed packet is too large")
    return len(packet).to_bytes(2, "big") + packet


def read_tcp_packet(stream: bytes) -> bytes:
    """Remove and validate a two-byte TCP length prefix."""

    if len(stream) < 2:
        raise ValueError("TCP stream is shorter than the length prefix")
    packet_len = int.from_bytes(stream[:2], "big")
    if len(stream) != 2 + packet_len:
        raise ValueError("TCP stream length does not match the prefix")
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
        raise ValueError("Anonymized DNSCrypt query is too short")
    if packet[: len(ANON_MAGIC)] != ANON_MAGIC:
        raise ValueError("invalid Anonymized DNSCrypt magic")
    server_ip = ipaddress.IPv6Address(packet[len(ANON_MAGIC) : len(ANON_MAGIC) + 16])
    server_port = int.from_bytes(packet[len(ANON_MAGIC) + 16 : header_len], "big")
    return AnonymizedDNSCryptQuery(server_ip, server_port, packet[header_len:])
