import hashlib
import unittest

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
    """Sign the Appendix 2 certificate, with overrides for negative cases."""

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
    """Sign the Appendix 3 certificate, with overrides for negative cases."""

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
    """Issue the Appendix 3 ticket for the given shared key and nonce."""

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
        """Check the HChaCha20 known-answer test from Appendix 1."""

        self.assertEqual(
            d.hchacha20(iota(0x00, 32), iota(0x00, 16)).hex(),
            "51e3ff45a895675c4b33b46c64f4a9ace110d34df6a2ceab486372bacbd3eff6",
        )

    def test_classical_appendix_vector(self):
        """Check the complete classical DNSCrypt Appendix 2 vector."""

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
        """Check deterministic X-Wing key generation against Appendix 3."""

        key_pair = d.xwing_generate_key_pair_derand(RESOLVER_SECRET)
        self.assertEqual(len(key_pair.public_key), d.XWING_PUBLIC_KEY_SIZE)
        self.assertEqual(
            hashlib.sha256(key_pair.public_key).hexdigest(),
            "a1f324bc0701f1234fbba7b11901023b3644f3bb8c6eb4ee4368d7e859eb6228",
        )

    def test_pq_appendix_ticket_vector(self):
        """Check deterministic PQ ticket and resumed-query Appendix 3 values."""

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

    def test_certificate_query_and_response_vectors(self):
        """Check the Appendix 2 certificate retrieval vectors byte for byte."""

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

        for client_magic in (b"\x00" * 7 + b"\x01", d.RESUME_MAGIC):
            with self.assertRaises(d.CertificateError):
                classical_certificate(client_magic=client_magic)

    def test_classical_negative_cases(self):
        """Check Appendix 2 negative cases 1, 3, and 5."""

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
        """Check Appendix 3 negative cases for tickets and KEM ciphertexts."""

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
        """Check Appendix 3 negative cases 1 and 2 for the profile extension."""

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
