"""Exception types used by the DNSCrypt reference implementation.

Failures a peer can trigger with wire data raise a `DNSCryptError` subclass;
`ValueError` is reserved for caller misuse, such as passing a wrong-size key.
"""


class DNSCryptError(Exception):
    """Base class for reference implementation errors."""


class CertificateError(DNSCryptError):
    """A certificate is malformed, unsupported, or invalid."""


class DecryptionError(DNSCryptError):
    """A DNSCrypt packet failed authentication or validation."""


class PaddingError(DNSCryptError):
    """ISO/IEC 7816-4 padding is malformed."""


class WireFormatError(DNSCryptError):
    """A packet or DNS message is malformed at the wire-format level."""


class RelayError(DNSCryptError):
    """An Anonymized DNSCrypt query fails the relay's validation rules."""


class AmplificationError(DNSCryptError):
    """A response would exceed its request and is dropped to avoid amplification."""

