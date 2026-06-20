"""Exception types used by the DNSCrypt reference implementation."""


class DNSCryptError(Exception):
    """Base class for reference implementation errors."""


class CertificateError(DNSCryptError):
    """A certificate is malformed, unsupported, or invalid."""


class DecryptionError(DNSCryptError):
    """A DNSCrypt packet failed authentication or validation."""


class PaddingError(DNSCryptError):
    """ISO/IEC 7816-4 padding is malformed."""


class AmplificationError(DNSCryptError):
    """A response would exceed its request and is dropped to avoid amplification."""

