import hashlib
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import dnscrypt as d


def iota(start: int, size: int) -> bytes:
    """Byte runs like `20 21 22 ... 3f` from the appendix Pinned Inputs tables."""

    return bytes((start + i) & 0xFF for i in range(size))


DNS_QUERY = bytes.fromhex(
    "12340100000100000000000003777777076578616d706c6503636f6d0000010001"
)
DNS_RESPONSE = bytes.fromhex(
    "12348180000100010000000003777777076578616d706c6503636f6d00000100"
    "01c00c0001000100000e1000045db8d822"
)

PROVIDER_SEED = iota(0x00, 32)
RESOLVER_SECRET = iota(0x20, 32)
CLASSICAL_CLIENT_MAGIC = bytes.fromhex("b1b2b3b4b5b6b7b8")
PQ_CLIENT_MAGIC = bytes.fromhex("a1b2c3d4e5f60718")
TICKET_KEY = d.TicketKey(ticket_key_id=b"\x00\x00\x00\x01", ticket_key=iota(0x80, 32))


def classical_certificate(
    serial=1,
    ts_start=0x68000000,
    ts_end=0x68015180,
    client_magic=CLASSICAL_CLIENT_MAGIC,
):
    """Sign the Appendix B certificate, with overrides for negative cases."""

    return d.DNSCryptCertificate.sign(
        provider_signing_seed=PROVIDER_SEED,
        es_version=d.ES_VERSION_XCHACHA20POLY1305,
        resolver_pk=d.x25519_public_key(RESOLVER_SECRET),
        client_magic=client_magic,
        serial=serial,
        ts_start=ts_start,
        ts_end=ts_end,
    )


def pq_certificate(serial=1, client_magic=PQ_CLIENT_MAGIC):
    """Sign the Appendix C certificate, with overrides for negative cases."""

    return d.DNSCryptCertificate.sign(
        provider_signing_seed=PROVIDER_SEED,
        es_version=d.ES_VERSION_XWING,
        resolver_pk=d.xwing_generate_key_pair_derand(RESOLVER_SECRET).public_key,
        client_magic=client_magic,
        serial=serial,
        ts_start=0x68000000,
        ts_end=0x68015180,
        extensions=d.pq_profile_extension(),
    )


def issue_ticket(certificate, shared_key, client_nonce, ticket_expiry=0x68000258):
    """Issue the Appendix C ticket for the given shared key and nonce."""

    return d.issue_pq_ticket(
        certificate=certificate,
        shared_key=shared_key,
        client_nonce=client_nonce,
        ticket_key=TICKET_KEY,
        ticket_nonce=iota(0xD0, 24),
        ticket_expiry=ticket_expiry,
        ticket_lifetime=0x0000012C,
    )


class DNSCryptReferenceTests(unittest.TestCase):
    """Vector and round-trip tests for the reference implementation."""

    def test_hchacha20_kat(self):
        """Check the HChaCha20 known-answer test from Appendix A."""

        self.assertEqual(
            d.hchacha20(iota(0x00, 32), iota(0x00, 16)).hex(),
            "51e3ff45a895675c4b33b46c64f4a9ace110d34df6a2ceab486372bacbd3eff6",
        )

    def test_chacha20_counter_carry(self):
        """Check low-word counter carry against libsodium's original ChaCha20."""

        key = hashlib.shake_256(b"stream-key").digest(32)
        nonce = hashlib.shake_256(b"stream-nonce").digest(8)
        plaintext = hashlib.shake_256(b"stream-message").digest(129)
        expected = bytes.fromhex(
            "afb968a92a79852966692aef044a5bca96bff9d01a64d2d67d0d6e489fffe3ad2"
            "53b2c51950b5109107d09d1721b0768e2678e0d2e4337f3ec2b1ba5538f130c9"
            "bcd93d69941024eeb101ceeb8ee742dbd288f6fafadcf3877735d0f6af52b5357"
            "29722d54d1ea34fdd11dfe9ba3e83bf678fb17c7d496f3d1cd5d4400e9174c37"
        )
        for size in (0, 1, 63, 64, 65, 129):
            self.assertEqual(
                d.chacha20_djb(key, nonce, plaintext[:size], 0xFFFFFFFF),
                expected[:size],
            )
        for counter in (-1, 1 << 64):
            with self.assertRaises(ValueError):
                d.chacha20_djb(key, nonce, b"", counter)
        with self.assertRaises(ValueError):
            d.chacha20_djb(key, nonce, bytes(65), (1 << 64) - 1)

    def test_classical_appendix_vector(self):
        """Check the complete classical DNSCrypt Appendix B vector."""

        client_sk = iota(0x40, 32)
        client_nonce = iota(0xA0, 12)
        resolver_nonce = iota(0xC0, 12)
        certificate = classical_certificate()

        self.assertEqual(
            d.ed25519_public_key_from_seed(PROVIDER_SEED).hex(),
            "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
        )
        self.assertEqual(
            certificate.signature.hex(),
            "3a570ea17f47b80217977fbb455840bfd50ab32f5fbf2aabc173a6a49b7a49ca"
            "55362a6c5dec47657cf515e9f99382a316dfecd964b94d1c4659cac45961400c",
        )
        self.assertEqual(
            certificate.to_bytes().hex(),
            "444e5343000200003a570ea17f47b80217977fbb455840bfd50ab32f5fbf2aab"
            "c173a6a49b7a49ca55362a6c5dec47657cf515e9f99382a316dfecd964b94d1c"
            "4659cac45961400c358072d6365880d1aeea329adf9121383851ed21a28e3b75"
            "e965d0d2cd166254b1b2b3b4b5b6b7b8000000016800000068015180",
        )

        parsed = d.DNSCryptCertificate.from_bytes(certificate.to_bytes())
        parsed.verify(d.ed25519_public_key_from_seed(PROVIDER_SEED))
        self.assertEqual(parsed, certificate)

        prepared = d.encrypt_dnscrypt_query(
            certificate, client_sk, DNS_QUERY, client_nonce=client_nonce
        )
        self.assertEqual(
            prepared.shared_key.hex(),
            "335d32f2d65e6623cbbd05b6539c9575fee16cb5405fe839ab4bd291fdf13262",
        )
        self.assertEqual(
            prepared.dnscrypt_query.hex(),
            "b1b2b3b4b5b6b7b879a631eede1bf9c98f12032cdeadd0e7a079398fc786b88c"
            "c846ec89af85a51aa0a1a2a3a4a5a6a7a8a9aaab2dae527c26386d5cd4e61152"
            "db6dd1812ff6aaf7644fc122afc70b1b580b18f10fbc26577abc759152cde31c"
            "d0afc5c5f452f8654815469723300819bed5a12015c044b94d63ec1f79e48a23"
            "968e437feb8bb8720cf4e60a0499746190c8b3eb83aeb0d858df77794270b861"
            "f86644502be0d22d6f0b2b132e9ca68538300c8d68b8e3c48190cbbf96d602f3"
            "8dfc3b4d642016ceeaf4bc2c2ded9483b9f9d4eed703a0bebc252add8822d4b9"
            "152e30670bcde9ea75a0e3e67ea576e9b1262bb2b25b4f9432311b75a2238b34"
            "bf4f868da182b85dccb1762a703bba31d04d77b4c57ec9039663959793677588"
            "b3a74ae409b0f16374dd64cbd6d47d801725b014ce9ddaf6f1aa30688c8efcbf"
            "de1d5d1d",
        )

        decrypted = d.decrypt_dnscrypt_query(
            prepared.dnscrypt_query,
            [
                d.ResolverCertificate(
                    certificate=certificate, resolver_sk=RESOLVER_SECRET
                )
            ],
        )
        self.assertEqual(decrypted.client_query, DNS_QUERY)
        self.assertEqual(decrypted.shared_key, prepared.shared_key)

        response = d.encrypt_dnscrypt_response(
            DNS_RESPONSE,
            prepared.shared_key,
            prepared.client_nonce,
            resolver_nonce=resolver_nonce,
        )
        self.assertEqual(
            response.hex(),
            "7236666e76576a38a0a1a2a3a4a5a6a7a8a9aaabc0c1c2c3c4c5c6c7c8c9cacb"
            "f2670995c6d37c2f8d2016029dd5970b893de83c02815ece9b48d9fd0b0dca87"
            "41674142fbd8e12c1120b111f366326aa71c89823a2931ac5c860dad49685ed6"
            "cc22cc13e829d2e51d1c00ea64d1d39d",
        )
        self.assertEqual(
            d.decrypt_dnscrypt_response(response, prepared.shared_key, client_nonce),
            DNS_RESPONSE,
        )

    def test_negative_padding_and_nonce_cases(self):
        """Check representative rejection paths for padding and nonce mismatch."""

        with self.assertRaises(d.PaddingError):
            d.unpad_7816_4(b"plain\x00\x00")

        certificate = classical_certificate(ts_start=1, ts_end=2)
        prepared = d.encrypt_dnscrypt_query(
            certificate, iota(0x40, 32), DNS_QUERY, client_nonce=iota(0xA0, 12)
        )
        response = d.encrypt_dnscrypt_response(
            DNS_RESPONSE,
            prepared.shared_key,
            prepared.client_nonce,
            resolver_nonce=iota(0xC0, 12),
        )
        with self.assertRaises(d.DecryptionError):
            d.decrypt_dnscrypt_response(response, prepared.shared_key, iota(0xB0, 12))

    def test_tcp_and_anonymized_helpers(self):
        """Check TCP framing and Anonymized DNSCrypt prefix helpers."""

        packet = b"abc"
        self.assertEqual(d.read_tcp_packet(d.tcp_packet(packet)), packet)
        anon = d.anonymized_dnscrypt_query("192.0.2.1", 443, packet)
        parsed = d.parse_anonymized_dnscrypt_query(anon)
        self.assertEqual(
            parsed.server_ip.packed, bytes.fromhex("00000000000000000000ffffc0000201")
        )
        self.assertEqual(parsed.server_port, 443)
        self.assertEqual(parsed.dnscrypt_query, packet)

    def test_xwing_keygen_matches_pq_appendix_digest(self):
        """Check deterministic X-Wing key generation against Appendix C."""

        key_pair = d.xwing_generate_key_pair_derand(RESOLVER_SECRET)
        self.assertEqual(len(key_pair.public_key), d.XWING_PUBLIC_KEY_SIZE)
        self.assertEqual(
            hashlib.sha256(key_pair.public_key).hexdigest(),
            "a1f324bc0701f1234fbba7b11901023b3644f3bb8c6eb4ee4368d7e859eb6228",
        )

    def test_pq_appendix_ticket_vector(self):
        """Check deterministic PQ ticket and resumed-query Appendix C values."""

        certificate = pq_certificate()
        shared_key = bytes.fromhex(
            "e6d4ab9cffc9b49e2a64d80d7eb2dde280f806b89e834d596ad385b1dd75e9ef"
        )
        self.assertEqual(
            certificate.signature.hex(),
            "811bab04e2e70c9d946296a93b4028d7c7bb84f32f597d3cf8aba29edc1b6b97"
            "4acc99dd00ec62cdcae477433d10bff20e1c432e1011ad8ad5324f68a294750c",
        )
        issued = issue_ticket(certificate, shared_key, iota(0xB0, 12))
        self.assertEqual(
            issued.resume_secret.hex(),
            "df158804e3f8ddf383ff7c9d3128491b29437a894936ec72c68aed8a9553272b",
        )
        self.assertEqual(
            issued.ticket.hex(),
            "00000001d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e1d90c86"
            "474574e0e51e82d8a29938896b0999e827138f8f452f21e044d9809f65a013cf"
            "ad8981be94c1354178b3e03dd518c28bcbaab962aa45246e446de7763288aa4a"
            "01e207725a0ae7bc95452fef3743f6083deb10cd23e2881e8d9307fc2f43bce1"
            "a97e",
        )
        self.assertEqual(
            issued.control.hex(),
            "50514452010000012c008200000001d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0"
            "e1e2e3e4e5e6e7e1d90c86474574e0e51e82d8a29938896b0999e827138f8f45"
            "2f21e044d9809f65a013cfad8981be94c1354178b3e03dd518c28bcbaab962aa"
            "45246e446de7763288aa4a01e207725a0ae7bc95452fef3743f6083deb10cd23"
            "e2881e8d9307fc2f43bce1a97e",
        )
        response = d.encrypt_pq_dnscrypt_response(
            DNS_RESPONSE,
            shared_key,
            iota(0xB0, 12),
            resolver_nonce=iota(0xC0, 12),
            control=issued.control,
            min_plaintext_len=256,
        )
        self.assertEqual(
            hashlib.sha256(response).hexdigest(),
            "33c081503d5ead4061a30d3f095fc9f226b8c01c3bbffa8fc6f4d9b15087de5c",
        )
        resumed = d.encrypt_pq_resume_query(
            ticket=issued.ticket,
            resume_secret=issued.resume_secret,
            client_magic=certificate.client_magic,
            client_query=DNS_QUERY,
            client_nonce=iota(0xF0, 12),
        )
        self.assertEqual(
            resumed.shared_key.hex(),
            "e61f03acb2ee2ef01b952a0c312c60653267d47a2766fcfd804747fdf2fe789f",
        )
        resumed_encrypted_query = resumed.dnscrypt_query[-(d.TAG_SIZE + 256) :]
        self.assertEqual(
            hashlib.sha256(resumed_encrypted_query).hexdigest(),
            "60323805036492350ee442ee4dcb097597fb586e3f2c8a1f26feb9cdd0409b29",
        )
        self.assertEqual(
            hashlib.sha256(resumed.dnscrypt_query).hexdigest(),
            "34be2e331b4d7c7e808e968c5efc9f25675a9de9064cb33f7c66950e0e4e6db7",
        )
        resumed_response = d.encrypt_pq_dnscrypt_response(
            DNS_RESPONSE,
            resumed.shared_key,
            iota(0xF0, 12),
            resolver_nonce=iota(0x10, 12),
            control=b"",
            min_plaintext_len=64,
        )
        self.assertEqual(
            hashlib.sha256(resumed_response).hexdigest(),
            "2bf202dd3f33d38854450e70a02bd1a317a23bf6d79c5dae406787c9c5f34f52",
        )

    def test_pq_appendix_full_query_vector(self):
        """Decapsulate the independently generated Appendix C ciphertext."""

        ciphertext = bytes.fromhex(
            Path(__file__).with_name("pq-client-kex.hex").read_text()
        )
        self.assertEqual(len(ciphertext), d.XWING_CIPHERTEXT_SIZE)
        self.assertEqual(
            hashlib.sha256(ciphertext).hexdigest(),
            "f6bf3f238e83f24cd444f2887e8fd32d630e07dbe6ca2f2b403aaf5333030c48",
        )
        kem_ss = d.xwing_decapsulate(ciphertext, RESOLVER_SECRET)
        self.assertEqual(
            kem_ss.hex(),
            "8dac8602d4ce5e27e81335b54b25fdcaea86e56613214ee0522db4a5e0a38d50",
        )
        certificate = pq_certificate()
        self.assertEqual(
            d.pq_shared_key(certificate, kem_ss, ciphertext).hex(),
            "e6d4ab9cffc9b49e2a64d80d7eb2dde280f806b89e834d596ad385b1dd75e9ef",
        )
        with patch(
            "pq.xwing_encapsulate",
            return_value=d.XWingEncapsulation(kem_ss, ciphertext),
        ):
            prepared = d.encrypt_pq_dnscrypt_query(
                certificate, DNS_QUERY, client_nonce=iota(0xB0, 12)
            )
        self.assertEqual(len(prepared.dnscrypt_query), 1220)
        self.assertEqual(
            prepared.dnscrypt_query[1140:].hex(),
            "c41764468cb42d3a837c51234c08be714af49e1a6830ea6da28178e9e280d76b"
            "ac1b87fd7f56515f2b2cc3d4715aaa42907c282db1edff0bc3b92cd535a710e2"
            "64859a5bdaf67c17ffa6e1c6f6e02a50",
        )
        self.assertEqual(
            hashlib.sha256(prepared.dnscrypt_query).hexdigest(),
            "65c3421776283f503779916e7b5c32d0d41c885508ad892b349688db6c901233",
        )
        decrypted = d.decrypt_dnscrypt_query(
            prepared.dnscrypt_query,
            [d.ResolverCertificate(certificate, RESOLVER_SECRET)],
        )
        self.assertEqual(decrypted.client_query, DNS_QUERY)
        self.assertEqual(decrypted.shared_key, prepared.shared_key)

    def test_zero_response_nonce(self):
        """A response must not reuse the query's complete AEAD nonce."""

        key = iota(0x40, 32)
        client_nonce = iota(0xA0, 12)
        zero = bytes(d.RESOLVER_NONCE_SIZE)
        with self.assertRaises(ValueError):
            d.encrypt_dnscrypt_response(DNS_RESPONSE, key, client_nonce, zero)
        with patch("packets.os.urandom", side_effect=[zero, iota(0xC0, 12)]):
            response = d.encrypt_dnscrypt_response(DNS_RESPONSE, key, client_nonce)
        self.assertEqual(response[20:32], iota(0xC0, 12))

        nonce = d.query_nonce(client_nonce)
        response = d.RESOLVER_MAGIC + nonce + d.xchacha20_djb_poly1305_seal(
            key, nonce, d.pad_7816_4(DNS_RESPONSE)
        )
        with self.assertRaises(d.DecryptionError):
            d.decrypt_dnscrypt_response(response, key, client_nonce)

    def test_authenticated_padding(self):
        """Check minimal, unaligned, and malformed padding after authentication."""

        certificate = classical_certificate()
        resolver = [d.ResolverCertificate(certificate, RESOLVER_SECRET)]
        prepared = d.encrypt_dnscrypt_query(certificate, iota(0x40, 32), DNS_QUERY)
        for padding in (b"\x80", b"\x80\x00", b"\x80" + bytes(255)):
            query = prepared.dnscrypt_query[:52] + d.xchacha20_djb_poly1305_seal(
                prepared.shared_key,
                d.query_nonce(prepared.client_nonce),
                DNS_QUERY + padding,
            )
            self.assertEqual(d.decrypt_dnscrypt_query(query, resolver).client_query, DNS_QUERY)
            nonce = prepared.client_nonce + iota(0xC0, 12)
            response = d.RESOLVER_MAGIC + nonce + d.xchacha20_djb_poly1305_seal(
                prepared.shared_key, nonce, DNS_RESPONSE + padding
            )
            self.assertEqual(
                d.decrypt_dnscrypt_response(
                    response, prepared.shared_key, prepared.client_nonce
                ),
                DNS_RESPONSE,
            )
        for plaintext in (b"", DNS_QUERY, DNS_QUERY + b"\x80\x01"):
            query = prepared.dnscrypt_query[:52] + d.xchacha20_djb_poly1305_seal(
                prepared.shared_key, d.query_nonce(prepared.client_nonce), plaintext
            )
            with self.assertRaises(d.PaddingError):
                d.decrypt_dnscrypt_query(query, resolver)

    def test_incoming_packet_size_bounds(self):
        """Reject oversized authenticated packets and accept exact allowed bounds."""

        certificate = classical_certificate()
        resolver = [d.ResolverCertificate(certificate, RESOLVER_SECRET)]
        prepared = d.encrypt_dnscrypt_query(certificate, iota(0x40, 32), DNS_QUERY)
        for size in (4096, 4097):
            plaintext = DNS_QUERY + b"\x80" + bytes(size - 68 - len(DNS_QUERY) - 1)
            query = prepared.dnscrypt_query[:52] + d.xchacha20_djb_poly1305_seal(
                prepared.shared_key, d.query_nonce(prepared.client_nonce), plaintext
            )
            self.assertEqual(len(query), size)
            if size == 4096:
                self.assertEqual(
                    d.decrypt_dnscrypt_query(query, resolver).client_query, DNS_QUERY
                )
            else:
                with self.assertRaises(d.DecryptionError):
                    d.decrypt_dnscrypt_query(query, resolver)

        nonce = prepared.client_nonce + iota(0xC0, 12)
        for size in (4095, 4096):
            plaintext = DNS_RESPONSE + b"\x80" + bytes(size - 48 - len(DNS_RESPONSE) - 1)
            response = d.RESOLVER_MAGIC + nonce + d.xchacha20_djb_poly1305_seal(
                prepared.shared_key, nonce, plaintext
            )
            self.assertEqual(len(response), size)
            if size == 4095:
                self.assertEqual(
                    d.decrypt_dnscrypt_response(
                        response, prepared.shared_key, prepared.client_nonce
                    ),
                    DNS_RESPONSE,
                )
            else:
                with self.assertRaises(d.DecryptionError):
                    d.decrypt_dnscrypt_response(
                        response, prepared.shared_key, prepared.client_nonce
                    )

    def test_incoming_pq_packet_size_bounds(self):
        """Apply the same query bound to full and resumed PQ packets."""

        certificate = pq_certificate()
        full = d.encrypt_pq_dnscrypt_query(certificate, DNS_QUERY)
        issued = issue_ticket(certificate, full.shared_key, full.client_nonce)
        resumed = d.encrypt_pq_resume_query(
            issued.ticket, issued.resume_secret, certificate.client_magic, DNS_QUERY
        )
        for prepared, header_size in ((full, 1140), (resumed, 152)):
            def open_query(query):
                if prepared is full:
                    return d.decrypt_dnscrypt_query(
                        query, [d.ResolverCertificate(certificate, RESOLVER_SECRET)]
                    )
                return d.decrypt_pq_resume_query(
                    query, [TICKET_KEY], [certificate], 0x68000100
                )

            for size in (4096, 4097):
                plaintext = DNS_QUERY + b"\x80" + bytes(
                    size - header_size - d.TAG_SIZE - len(DNS_QUERY) - 1
                )
                query = prepared.dnscrypt_query[:header_size] + d.xchacha20_djb_poly1305_seal(
                    prepared.shared_key, d.query_nonce(prepared.client_nonce), plaintext
                )
                self.assertEqual(len(query), size)
                if size == 4096:
                    self.assertEqual(open_query(query).client_query, DNS_QUERY)
                else:
                    with self.assertRaises(d.DecryptionError):
                        open_query(query)

    def test_certificate_retrieval_amplification(self):
        """Check the certificate retrieval anti-amplification size rule."""

        classical = classical_certificate().to_bytes()
        pq = pq_certificate(serial=2).to_bytes()
        provider_name = "2.dnscrypt-cert.example.com"

        # One 1320-byte PQ certificate is about 1338 bytes as a TXT answer record.
        self.assertEqual(len(pq), 1320)
        base_query = d.certificate_query(provider_name)
        self.assertEqual(
            len(d.build_certificate_response(base_query, [pq])) - len(base_query),
            1338,
        )

        # Initial UDP retrieval covers the rollover set, including the relay prefix.
        direct_udp = d.certificate_query_for_transport(
            provider_name, over_tcp=False, via_relay=False
        )
        self.assertEqual(len(direct_udp), 3200)
        relay_udp = d.certificate_query_for_transport(
            provider_name, over_tcp=False, via_relay=True
        )
        self.assertEqual(
            len(d.anonymized_dnscrypt_query("192.0.2.1", 443, relay_udp)), 3200
        )

        # Direct TCP needs no padding. TCP to a relay keeps the inner query large
        # enough for the relay's UDP response budget.
        direct_tcp = d.certificate_query_for_transport(
            provider_name, over_tcp=True, via_relay=False
        )
        self.assertEqual(direct_tcp, base_query)
        relay_tcp = d.certificate_query_for_transport(
            provider_name, over_tcp=True, via_relay=True
        )
        self.assertEqual(len(relay_tcp), 3200)

        # A query padded past the response carries the PQ certificate over UDP.
        padded = d.certificate_query(provider_name, padded_length=1600)
        served = d.serve_certificates(padded, [classical], [pq], over_udp=True)
        self.assertEqual(served[6:8], b"\x00\x02")  # two answers
        self.assertFalse(served[2] & 0x02)  # TC not set
        self.assertLessEqual(len(served), len(padded))
        self.assertEqual(d.relay_certificate_response(padded, served), served)

        # An unpadded query is too small for the PQ certificate: return the
        # classical certificate with TC set, matching deployed resolvers.
        truncated = d.serve_certificates(base_query, [classical], [pq], over_udp=True)
        self.assertEqual(truncated[6:8], b"\x00\x01")  # classical only
        self.assertTrue(truncated[2] & 0x02)  # TC set
        with self.assertRaises(d.AmplificationError):
            d.relay_certificate_response(base_query, served)

        # Over TCP the source is validated, so the PQ certificate is always sent.
        over_tcp = d.serve_certificates(base_query, [classical], [pq], over_udp=False)
        self.assertEqual(over_tcp[6:8], b"\x00\x02")
        self.assertFalse(over_tcp[2] & 0x02)

        # The rollover set of two classical and two PQ certificates needs a larger
        # query, since the response roughly doubles during a key rotation.
        rollover_query = d.certificate_query(provider_name, padded_length=3200)
        rollover = d.serve_certificates(
            rollover_query, [classical, classical], [pq, pq], over_udp=True
        )
        self.assertEqual(rollover[6:8], b"\x00\x04")
        self.assertFalse(rollover[2] & 0x02)
        self.assertLessEqual(len(rollover), len(rollover_query))

        long_name = "2.dnscrypt-cert." + ".".join(["x" * 63] * 3 + ["x" * 45])
        self.assertEqual(len(d.certificate_query(long_name)), 271)
        for over_tcp, via_relay in ((False, False), (False, True), (True, True)):
            query = d.certificate_query_for_transport(
                long_name, over_tcp=over_tcp, via_relay=via_relay
            )
            response = d.serve_certificates(
                query, [classical, classical], [pq, pq], over_udp=True
            )
            self.assertEqual(len(response), 3221)
            self.assertFalse(response[2] & 0x02)
            self.assertLessEqual(len(response), len(query))

    def test_pq_full_and_resumed_round_trip(self):
        """Check randomized full-PQ and resumed-query round trips."""

        certificate = pq_certificate()
        certificate.verify(d.ed25519_public_key_from_seed(PROVIDER_SEED))

        prepared = d.encrypt_pq_dnscrypt_query(
            certificate, DNS_QUERY, client_nonce=iota(0xB0, 12)
        )
        decrypted = d.decrypt_dnscrypt_query(
            prepared.dnscrypt_query,
            [
                d.ResolverCertificate(
                    certificate=certificate, resolver_sk=RESOLVER_SECRET
                )
            ],
        )
        self.assertEqual(decrypted.client_query, DNS_QUERY)
        self.assertEqual(decrypted.shared_key, prepared.shared_key)

        issued = issue_ticket(certificate, prepared.shared_key, prepared.client_nonce)
        response = d.encrypt_pq_dnscrypt_response(
            DNS_RESPONSE,
            prepared.shared_key,
            prepared.client_nonce,
            resolver_nonce=iota(0xC0, 12),
            control=issued.control,
            min_plaintext_len=256,
        )
        opened_response = d.decrypt_pq_dnscrypt_response(
            response, prepared.shared_key, prepared.client_nonce
        )
        self.assertEqual(opened_response.control, issued.control)
        self.assertEqual(opened_response.resolver_response, DNS_RESPONSE)
        self.assertEqual(opened_response.ticket.ticket, issued.ticket)
        self.assertEqual(opened_response.ticket.ticket_lifetime, 300)

        resumed = d.encrypt_pq_resume_query(
            ticket=issued.ticket,
            resume_secret=issued.resume_secret,
            client_magic=certificate.client_magic,
            client_query=DNS_QUERY,
            client_nonce=iota(0xF0, 12),
        )
        opened_resume = d.decrypt_pq_resume_query(
            resumed.dnscrypt_query,
            ticket_keys=[TICKET_KEY],
            certificates=[certificate],
            now=0x68000100,
        )
        self.assertEqual(opened_resume.client_query, DNS_QUERY)
        self.assertEqual(opened_resume.shared_key, resumed.shared_key)

    def test_pq_ticket_renewal(self):
        """Renew a ticket using the answered resumed query's key and nonce."""

        certificate = pq_certificate()
        full = d.encrypt_pq_dnscrypt_query(certificate, DNS_QUERY)
        issued = issue_ticket(certificate, full.shared_key, full.client_nonce)
        resumed = d.encrypt_pq_resume_query(
            issued.ticket, issued.resume_secret, certificate.client_magic, DNS_QUERY
        )
        opened = d.decrypt_pq_resume_query(
            resumed.dnscrypt_query, [TICKET_KEY], [certificate], now=0x68000258
        )
        renewed = d.issue_pq_ticket(
            certificate=opened.certificate,
            shared_key=opened.shared_key,
            client_nonce=opened.client_nonce,
            ticket_key=TICKET_KEY,
            ticket_nonce=iota(0xE0, 24),
            ticket_expiry=0x68000384,
            ticket_lifetime=300,
        )
        response = d.encrypt_pq_dnscrypt_response(
            DNS_RESPONSE, opened.shared_key, opened.client_nonce, control=renewed.control
        )
        received = d.decrypt_pq_dnscrypt_response(
            response, resumed.shared_key, resumed.client_nonce
        )
        resume_secret = d.pq_resume_secret(
            resumed.shared_key, certificate.client_magic, resumed.client_nonce
        )
        self.assertEqual(resume_secret, renewed.resume_secret)
        self.assertNotEqual(resume_secret, issued.resume_secret)
        self.assertEqual(received.resolver_response, DNS_RESPONSE)
        self.assertEqual(received.ticket.ticket, renewed.ticket)

        next_query = d.encrypt_pq_resume_query(
            received.ticket.ticket, resume_secret, certificate.client_magic, DNS_QUERY
        )
        next_opened = d.decrypt_pq_resume_query(
            next_query.dnscrypt_query, [TICKET_KEY], [certificate], now=0x68000259
        )
        self.assertEqual(next_opened.client_query, DNS_QUERY)
        self.assertEqual(next_opened.shared_key, next_query.shared_key)
        self.assertEqual(next_opened.certificate, certificate)
        with self.assertRaises(d.DecryptionError):
            d.decrypt_pq_resume_query(
                resumed.dnscrypt_query, [TICKET_KEY], [certificate], now=0x68000259
            )

    def test_pq_control_validation(self):
        """Ignore unknown controls and reject malformed version 1 tickets."""

        key = iota(0x40, 32)
        nonce = iota(0xA0, 12)
        valid = d.PQ_CONTROL_MAGIC + b"\x01" + (300).to_bytes(4, "big") + b"\x00\x01x"
        self.assertEqual(d.parse_pq_control(valid), d.PQTicketControl(300, b"x"))
        for control in (b"", b"other", d.PQ_CONTROL_MAGIC + b"\x02"):
            response = d.encrypt_pq_dnscrypt_response(
                DNS_RESPONSE, key, nonce, control=control
            )
            opened = d.decrypt_pq_dnscrypt_response(response, key, nonce)
            self.assertEqual(opened.resolver_response, DNS_RESPONSE)
            self.assertIsNone(opened.ticket)
        malformed = (
            d.PQ_CONTROL_MAGIC,
            valid[:5],
            valid[:10],
            valid[:-1],
            valid + b"x",
            valid[:5] + bytes(4) + valid[9:],
            valid[:9] + bytes(2),
        )
        for control in malformed:
            with self.subTest(control=control.hex()):
                response = d.encrypt_pq_dnscrypt_response(
                    DNS_RESPONSE, key, nonce, control=control
                )
                with self.assertRaises(d.DecryptionError):
                    d.decrypt_pq_dnscrypt_response(response, key, nonce)
        for plaintext in (b"", b"\x00", b"\x00\x01"):
            response = d.encrypt_dnscrypt_response(plaintext, key, nonce)
            with self.assertRaises(d.DecryptionError):
                d.decrypt_pq_dnscrypt_response(response, key, nonce)

    def test_certificate_query_and_response_vectors(self):
        """Check the Appendix B certificate retrieval vectors byte for byte."""

        provider_name = "2.dnscrypt-cert.example.com"
        query = d.certificate_query(provider_name, query_id=b"\xab\xcd")
        self.assertEqual(
            query.hex(),
            "abcd0100000100000000000001320d646e7363727970742d6365727407657861"
            "6d706c6503636f6d0000100001",
        )

        certificate = classical_certificate()
        response = d.build_certificate_response(query, [certificate.to_bytes()])
        self.assertEqual(
            response.hex(),
            "abcd8180000100010000000001320d646e7363727970742d6365727407657861"
            "6d706c6503636f6d0000100001c00c0010000100015180007d7c444e53430002"
            "00003a570ea17f47b80217977fbb455840bfd50ab32f5fbf2aabc173a6a49b7a"
            "49ca55362a6c5dec47657cf515e9f99382a316dfecd964b94d1c4659cac45961"
            "400c358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd"
            "166254b1b2b3b4b5b6b7b8000000016800000068015180",
        )

        padded = d.certificate_query(
            provider_name, query_id=b"\xab\xcd", padded_length=512
        )
        self.assertEqual(len(padded), 512)
        self.assertEqual(
            padded[45:].hex(),
            "00002910000000000001c8000c01c4" + "00" * 452,
        )

    def test_choose_certificate_skips_invalid_certificates(self):
        """One bad record must not prevent selection of a valid certificate."""

        provider_pk = d.ed25519_public_key_from_seed(PROVIDER_SEED)
        good = classical_certificate(serial=3)
        bad_signature = d.DNSCryptCertificate.from_bytes(
            classical_certificate(serial=9).to_bytes()[:-1] + b"\xff"
        )
        expired = classical_certificate(serial=8, ts_start=1, ts_end=2)
        chosen = d.choose_certificate(
            [bad_signature, expired, good], provider_pk, now=0x68000100
        )
        self.assertEqual(chosen, good)
        with self.assertRaises(d.CertificateError):
            d.choose_certificate([bad_signature, expired], provider_pk, now=0x68000100)

        # A blob with an unknown es-version is ignored as a whole at parse
        # time; its resolver-pk length cannot be guessed.
        with self.assertRaises(d.CertificateError):
            d.DNSCryptCertificate.from_bytes(
                good.to_bytes()[:4] + b"\x00\x63" + good.to_bytes()[6:]
            )

    def test_client_magic_signing_constraints(self):
        """Reject reserved client-magic values at signing time."""

        for client_magic in (b"\x00" * 7 + b"\x01", b"\xff" * 8, d.RESUME_MAGIC):
            with self.assertRaises(d.CertificateError):
                classical_certificate(client_magic=client_magic)
            certificate = replace(classical_certificate(), client_magic=client_magic)
            certificate = replace(
                certificate,
                signature=d.ed25519_sign(PROVIDER_SEED, certificate.signed_data()),
            )
            with self.assertRaises(d.CertificateError):
                certificate.verify(d.ed25519_public_key_from_seed(PROVIDER_SEED))

    def test_certificate_txt_character_strings(self):
        """Reassemble both certificate sizes and reject truncated TXT strings."""

        for certificate in (classical_certificate(), pq_certificate()):
            raw = certificate.to_bytes()
            rdata = b"".join(
                bytes([len(raw[i : i + 255])]) + raw[i : i + 255]
                for i in range(0, len(raw), 255)
            )
            self.assertEqual(d.DNSCryptCertificate.from_txt_rdata(rdata), certificate)
            with self.assertRaises(d.CertificateError):
                d.DNSCryptCertificate.from_txt_rdata(rdata[:-1])
        with self.assertRaises(d.CertificateError):
            d.DNSCryptCertificate.from_txt_rdata(b"")

    def test_certificate_query_arguments(self):
        """Reject caller inputs that cannot form a valid DNS question."""

        for query_id in (b"", b"a", b"abc"):
            with self.assertRaises(ValueError):
                d.certificate_query("2.dnscrypt-cert.example.com", query_id)
        with self.assertRaises(ValueError):
            d.certificate_query(".".join(["x" * 63] * 4))

    def test_classical_negative_cases(self):
        """Check Appendix B negative cases 1, 3, and 5."""

        certificate = classical_certificate(ts_start=1, ts_end=2)
        resolver = [
            d.ResolverCertificate(certificate=certificate, resolver_sk=RESOLVER_SECRET)
        ]
        prepared = d.encrypt_dnscrypt_query(
            certificate, iota(0x40, 32), DNS_QUERY, client_nonce=iota(0xA0, 12)
        )

        # Case 1: any flipped ciphertext byte fails authentication.
        tampered = bytearray(prepared.dnscrypt_query)
        tampered[-1] ^= 0x01
        with self.assertRaises(d.DecryptionError):
            d.decrypt_dnscrypt_query(bytes(tampered), resolver)

        # Case 3: an unknown client-magic is not a query for this resolver.
        with self.assertRaises(d.DecryptionError):
            d.decrypt_dnscrypt_query(b"\xee" * 8 + prepared.dnscrypt_query[8:], resolver)

        # Case 5: a low-order client public key yields an all-zero shared point.
        low_order = bytearray(prepared.dnscrypt_query)
        low_order[8 : 8 + 32] = b"\x00" * 32
        with self.assertRaises(d.DecryptionError):
            d.decrypt_dnscrypt_query(bytes(low_order), resolver)

    def test_pq_negative_cases(self):
        """Check Appendix C negative cases for tickets and KEM ciphertexts."""

        certificate = pq_certificate()
        resolver = [
            d.ResolverCertificate(certificate=certificate, resolver_sk=RESOLVER_SECRET)
        ]

        # Case 6: a tampered KEM ciphertext fails exactly like any bad query,
        # including a low-order X25519 component (implicit rejection).
        prepared = d.encrypt_pq_dnscrypt_query(
            certificate, DNS_QUERY, client_nonce=iota(0xB0, 12)
        )
        tampered = bytearray(prepared.dnscrypt_query)
        tampered[8] ^= 0x01
        with self.assertRaises(d.DecryptionError):
            d.decrypt_dnscrypt_query(bytes(tampered), resolver)
        low_order_ct_x = bytearray(prepared.dnscrypt_query)
        low_order_ct_x[
            8 + d.XWING_MLKEM_CIPHERTEXT_SIZE : 8 + d.XWING_CIPHERTEXT_SIZE
        ] = b"\x00" * 32
        with self.assertRaises(d.DecryptionError):
            d.decrypt_dnscrypt_query(bytes(low_order_ct_x), resolver)

        issued = issue_ticket(certificate, prepared.shared_key, prepared.client_nonce)
        resumed = d.encrypt_pq_resume_query(
            ticket=issued.ticket,
            resume_secret=issued.resume_secret,
            client_magic=certificate.client_magic,
            client_query=DNS_QUERY,
            client_nonce=iota(0xF0, 12),
        )

        def open_resumed(query, ticket_keys=(TICKET_KEY,), now=0x68000100):
            return d.decrypt_pq_resume_query(
                query, ticket_keys=ticket_keys, certificates=[certificate], now=now
            )

        self.assertEqual(open_resumed(resumed.dnscrypt_query).client_query, DNS_QUERY)

        # Case 3: a corrupted ticket byte makes the ticket AEAD fail.
        corrupted = bytearray(resumed.dnscrypt_query)
        corrupted[10 + d.TICKET_KEY_ID_SIZE + d.TICKET_NONCE_SIZE] ^= 0x01
        with self.assertRaises(d.DecryptionError):
            open_resumed(bytes(corrupted))

        # Case 4: an expired ticket or a rotated-out ticket key is rejected.
        with self.assertRaises(d.DecryptionError):
            open_resumed(resumed.dnscrypt_query, now=0x68000259)
        rotated = d.TicketKey(
            ticket_key_id=b"\x00\x00\x00\x02", ticket_key=iota(0x80, 32)
        )
        with self.assertRaises(d.DecryptionError):
            open_resumed(resumed.dnscrypt_query, ticket_keys=(rotated,))

        # Case 5: a ticket context that matches no current certificate is rejected.
        other = pq_certificate(serial=2, client_magic=bytes.fromhex("a1b2c3d4e5f60719"))
        with self.assertRaises(d.DecryptionError):
            d.decrypt_pq_resume_query(
                resumed.dnscrypt_query,
                ticket_keys=[TICKET_KEY],
                certificates=[other],
                now=0x68000100,
            )

        # A ticket must not outlive its certificate.
        with self.assertRaises(ValueError):
            issue_ticket(
                certificate,
                prepared.shared_key,
                prepared.client_nonce,
                ticket_expiry=certificate.ts_end + 1,
            )

    def test_pq_profile_extension_negative_cases(self):
        """Check Appendix C negative cases 1 and 2 for the profile extension."""

        # A PQ certificate without the required extension cannot be used to
        # encrypt, even if the caller never ran verify().
        missing_extension = d.DNSCryptCertificate.sign(
            provider_signing_seed=PROVIDER_SEED,
            es_version=d.ES_VERSION_XWING,
            resolver_pk=d.xwing_generate_key_pair_derand(RESOLVER_SECRET).public_key,
            client_magic=PQ_CLIENT_MAGIC,
            serial=1,
            ts_start=0x68000000,
            ts_end=0x68015180,
        )
        with self.assertRaises(d.CertificateError):
            d.encrypt_pq_dnscrypt_query(missing_extension, DNS_QUERY)

        with self.assertRaises(d.CertificateError):
            d.parse_pq_profile_extension(d.pq_profile_extension() + b"\x00")
        with self.assertRaises(d.CertificateError):
            d.parse_pq_profile_extension(d.pq_profile_extension(es_version=b"\x00\x02"))
        with self.assertRaises(d.CertificateError):
            d.parse_pq_profile_extension(d.pq_profile_extension(resolver_pk_len=1217))
        with self.assertRaises(d.CertificateError):
            d.parse_pq_profile_extension(d.pq_profile_extension(client_kex_len=1121))
        for offset in (0, 3, 6, 7):
            extension = bytearray(d.pq_profile_extension())
            extension[offset] ^= 1
            with self.assertRaises(d.CertificateError):
                d.parse_pq_profile_extension(bytes(extension))

    def test_relay_validation(self):
        """Check the Anonymized DNSCrypt relay validation rules."""

        inner = CLASSICAL_CLIENT_MAGIC + b"\x00" * 60
        valid = d.parse_anonymized_dnscrypt_query(
            d.anonymized_dnscrypt_query("93.184.216.34", 443, inner)
        )
        d.validate_relay_query(valid)

        bad_targets = ("127.0.0.1", "10.0.0.1", "169.254.1.1", "192.0.2.1", "ff0e::1")
        for bad_target in bad_targets:
            with self.assertRaises(d.RelayError):
                d.validate_relay_query(
                    d.parse_anonymized_dnscrypt_query(
                        d.anonymized_dnscrypt_query(bad_target, 443, inner)
                    )
                )
        with self.assertRaises(d.RelayError):
            d.validate_relay_query(
                d.parse_anonymized_dnscrypt_query(
                    d.anonymized_dnscrypt_query("93.184.216.34", 53, inner)
                )
            )
        nested = d.anonymized_dnscrypt_query("93.184.216.34", 443, inner)
        with self.assertRaises(d.RelayError):
            d.validate_relay_query(
                d.parse_anonymized_dnscrypt_query(
                    d.anonymized_dnscrypt_query("93.184.216.34", 443, nested)
                )
            )
        quic = d.QUIC_MAGIC + inner[8:]
        with self.assertRaises(d.RelayError):
            d.validate_relay_query(
                d.parse_anonymized_dnscrypt_query(
                    d.anonymized_dnscrypt_query("93.184.216.34", 443, quic)
                )
            )

    def test_packet_size_bounds(self):
        """Complete queries stay within 4096 bytes, responses below it."""

        certificate = classical_certificate()
        with self.assertRaises(ValueError):
            d.encrypt_dnscrypt_query(
                certificate, iota(0x40, 32), DNS_QUERY, min_plaintext_len=4096
            )
        prepared = d.encrypt_dnscrypt_query(certificate, iota(0x40, 32), DNS_QUERY)
        with self.assertRaises(ValueError):
            d.encrypt_dnscrypt_response(
                DNS_RESPONSE,
                prepared.shared_key,
                prepared.client_nonce,
                min_plaintext_len=4096,
            )

    def test_wire_format_errors(self):
        """Wire-level parse failures raise WireFormatError, not ValueError."""

        with self.assertRaises(d.WireFormatError):
            d.read_tcp_packet(b"\x00")
        with self.assertRaises(d.WireFormatError):
            d.read_tcp_packet(b"\x00\x05abc")
        with self.assertRaises(d.WireFormatError):
            d.parse_anonymized_dnscrypt_query(b"\xff" * 8)
        with self.assertRaises(d.WireFormatError):
            d.build_certificate_response(b"\x00" * 4, [])


if __name__ == "__main__":
    unittest.main()
