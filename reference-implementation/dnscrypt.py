"""Readable reference implementation for DNSCrypt v2 and PQDNSCrypt.

This module is a compatibility facade. The implementation is split by topic in
the neighboring modules, but importing `dnscrypt` exposes the same simple API
used by the tests and examples.
"""

from certificates import *
from constants import *
from crypto import *
from errors import *
from packets import *
from pq import *
from transport import *
from protocol_types import *

