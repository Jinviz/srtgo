"""
DynaPath Mobile SDK token generator (v2, Korail+ 7.0.10 / DynaPath SDK 2.0.1).

Generates ``x-dynapath-m-token`` header values required by macro-protected
Korail API endpoints.

History
-------
* Up to Korail Talk 7.0.8 the app sent a "v1" token (``bEeEP…`` prefix, custom
  base-30 encoding). Since 2026-10-21 the server rejects v1 tokens on protected
  endpoints with ``-8204`` ("최신 버전으로 업데이트해 주세요").
* Korail+ 7.0.10 generates the token in a native library
  (``libdp_ffi_android.so``). The token is a "declaration token": a plaintext
  envelope of device facts, XOR-ed with a SHA-256 counter keystream, tagged with a
  3-byte MAC, and encoded with a custom base62 alphabet, prefixed with ``201``.

Algorithm (as documented by the pykorail project's reverse engineering of the
7.0.10 APK, re-implemented here from that description):

    plaintext = "!v=2&es=<op>&ts=<ms>&st=Android&sv=2.0.1&ai=korailplus&os=..&dm=..
                 &iid=..&mf=..&bd=..&sl=<sdk>&sb=<strongbox>&kl=<kl>&ec=<ec>"
    keystream = SHA256(SECRET || LE32(nonce) || BE32(block)) for block = 0, 1, ...
    eor       = plaintext XOR keystream
    mac3      = SHA256(SECRET || LE32(nonce) || eor)[:3]
    buffer    = LE32(nonce) || mac3 || eor
    token     = "201" + base62(buffer, 4-byte words -> 6 chars, last 1..3 bytes -> 2..5 chars)
"""

import base64
import hashlib
import math
import secrets
import struct
import time


TOKEN_PREFIX = "201"
DYNAPATH_SDK_VERSION = "2.0.1"
DYNAPATH_APP_ID = "korailplus"

# Build-embedded secret (64 ASCII hex characters, used as raw ASCII bytes).
_SECRET = b"9a330fd663b62c5f888a7ce76ac7202d93f646b4e0bd605cd4183278ca4ca888"
# Custom base62 alphabet used by the native encoder (not the standard one).
_ALPHABET = "TeFOuQBxj1qRUHwKkymSY8l3psvCzAL5tofNcihg9WDG072EZ4bVad6rJnPXIM"

# Software declaration op id (same for every endpoint) and the attestation
# derived values that accompany it. Accepted by the live server as of 2026-10-28.
_DEFAULT_OP_ID = 288904575606514493
_DEFAULT_KL = "990094375841594426"
_DEFAULT_EC = "978212327729758430"

_DEFAULT_MANUFACTURER = "samsung"
_DEFAULT_BOARD = "kalama"
_DEFAULT_STRONGBOX = 1
_SDK_BY_ANDROID = {"10": 29, "11": 30, "12": 31, "13": 33, "14": 34, "15": 35, "16": 36}

MACRO_PROTECTED_URLS = [
    "/classes/com.korail.mobile.certification.TicketReservation",
    "/classes/com.korail.mobile.nonMember.NonMemTicket",
    "/classes/com.korail.mobile.seatMovie.ScheduleView",
    "/classes/com.korail.mobile.seatMovie.ScheduleViewSpecial",
    "/classes/com.korail.mobile.trn.prcFare.do",
    "/classes/com.korail.mobile.login.Login",
]


def _b64url(raw: bytes) -> str:
    """Android ``Base64.URL_SAFE | NO_PADDING | NO_WRAP``."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _sdk_int(android_release: str) -> int:
    if android_release in _SDK_BY_ANDROID:
        return _SDK_BY_ANDROID[android_release]
    if android_release.isdigit() and int(android_release) >= 13:
        return int(android_release) + 20
    return 35


def _keystream(nbytes: int, nonce: int) -> bytes:
    nonce_le = struct.pack("<I", nonce)
    blocks = math.ceil(nbytes / 32)
    out = b"".join(
        hashlib.sha256(_SECRET + nonce_le + struct.pack(">I", i)).digest()
        for i in range(blocks)
    )
    return out[:nbytes]


def _b62_width(nbytes: int) -> int:
    """Fixed base62 digit count for an ``nbytes``-byte word (4 -> 6, 1 -> 2)."""
    return math.ceil(nbytes * 8 / math.log2(62))


def _b62_word(value: int, width: int) -> str:
    digits = [_ALPHABET[0]] * width
    for i in range(width - 1, -1, -1):
        digits[i] = _ALPHABET[value % 62]
        value //= 62
    return "".join(digits)


def _encode_body(buffer: bytes) -> str:
    parts = []
    for i in range(0, len(buffer), 4):
        word = buffer[i : i + 4]
        parts.append(_b62_word(int.from_bytes(word, "big"), _b62_width(len(word))))
    return "".join(parts)


class DynaPathToken:
    """Generates DynaPath v2 declaration tokens for Korail API requests."""

    def __init__(
        self,
        app_id: str = DYNAPATH_APP_ID,
        device_id: str = None,
        os_version: str = "15",
        device_model: str = "SM-S911N",
        manufacturer: str = _DEFAULT_MANUFACTURER,
        board: str = _DEFAULT_BOARD,
        strongbox: int = _DEFAULT_STRONGBOX,
        op_id: int = _DEFAULT_OP_ID,
        kl: str = _DEFAULT_KL,
        ec: str = _DEFAULT_EC,
    ):
        self._app_id = app_id
        # ``iid`` carries the android_id *string* (16 hex chars) as UTF-8 bytes.
        self._device_id = device_id or self._random_device_id()
        self._os_version = os_version
        self._device_model = device_model
        self._manufacturer = manufacturer
        self._board = board
        self._strongbox = strongbox
        self._op_id = op_id
        self._kl = kl
        self._ec = ec
        self._timestamp = None

    @staticmethod
    def _random_device_id() -> str:
        return secrets.token_hex(8)

    @property
    def device_id(self) -> str:
        return self._device_id

    @property
    def timestamp(self) -> int:
        """Millisecond timestamp used by the most recent token."""
        return self._timestamp

    def _plaintext(self, ts_ms: int) -> bytes:
        envelope = (
            f"!v=2&es={self._op_id}&ts={ts_ms}&st=Android&sv={DYNAPATH_SDK_VERSION}"
            f"&ai={self._app_id}"
            f"&os={_b64url(self._os_version.encode('utf-8'))}"
            f"&dm={_b64url(self._device_model.encode('utf-8'))}"
            f"&iid={_b64url(self._device_id.encode('ascii'))}"
            f"&mf={_b64url(self._manufacturer.encode('utf-8'))}"
            f"&bd={_b64url(self._board.encode('utf-8'))}"
            f"&sl={_sdk_int(self._os_version)}&sb={self._strongbox}"
            f"&kl={self._kl}&ec={self._ec}"
        )
        return envelope.encode("latin1")

    def build(self, ts_ms: int, nonce: int) -> str:
        """Build a token for an explicit timestamp and nonce (deterministic)."""
        if not 0 <= nonce < 2**32:
            raise ValueError("nonce must fit in 32 bits")
        plaintext = self._plaintext(ts_ms)
        keystream = _keystream(len(plaintext), nonce)
        eor = bytes(p ^ k for p, k in zip(plaintext, keystream))
        nonce_le = struct.pack("<I", nonce)
        mac3 = hashlib.sha256(_SECRET + nonce_le + eor).digest()[:3]
        return TOKEN_PREFIX + _encode_body(nonce_le + mac3 + eor)

    def generate(self) -> str:
        """Generate a fresh token for the x-dynapath-m-token header."""
        self._timestamp = int(time.time() * 1000)
        return self.build(self._timestamp, secrets.randbits(32))

    @staticmethod
    def is_macro_url(url: str) -> bool:
        """Check if a URL requires a DynaPath token."""
        return any(protected in url for protected in MACRO_PROTECTED_URLS)
