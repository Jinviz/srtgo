"""
DynaPath Mobile SDK token generator.

Reverse-engineered from the Korail Talk APK (v6.4.4).
Generates x-dynapath-m-token header values required by macro-protected API endpoints.
"""

import math
import random
import string
import time
from collections import OrderedDict
from functools import lru_cache
from urllib.parse import quote


CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
APP_SIGNATURE_HASH = "38ff229cb34c7dda8e28220a2d750cce"

MACRO_PROTECTED_URLS = [
    "/classes/com.korail.mobile.certification.TicketReservation",
    "/classes/com.korail.mobile.nonMember.NonMemTicket",
    "/classes/com.korail.mobile.seatMovie.ScheduleView",
    "/classes/com.korail.mobile.seatMovie.ScheduleViewSpecial",
    "/classes/com.korail.mobile.trn.prcFare.do",
    "/classes/com.korail.mobile.login.Login",
]


@lru_cache(maxsize=128)
def _generate_primes(n: int) -> tuple:
    """Generate first n primes starting from 3 (excludes 2)."""
    primes = [2]
    candidate = 3
    while len(primes) < n + 1:
        sqrt_c = int(math.sqrt(candidate))
        is_prime = True
        for p in primes:
            if p > sqrt_c:
                break
            if candidate % p == 0:
                is_prime = False
                break
        if is_prime:
            primes.append(candidate)
        candidate += 1
    return tuple(primes[1:])


def _primes_list() -> tuple:
    return _generate_primes(100)


def _largest_prime_le(n: int) -> int:
    """Find the largest prime in the cached list that is <= n."""
    result = 1
    for p in _primes_list():
        if p > n:
            break
        result = p
    return result


def _char_permute(s: str, a: int, b: int) -> str:
    """Permute characters of s using modular arithmetic with parameters a and b."""
    length = len(s)
    prime_size = _largest_prime_le(length)

    visit_count = [0] * prime_size
    result_chars = ['\0'] * prime_size

    multiplier = 1
    for i in range(prime_size):
        idx = (multiplier % prime_size) * b % prime_size
        visit_count[idx] += 1
        if visit_count[idx] == 1:
            result_chars[i] = s[idx]
        multiplier *= a

    placed = []
    unplaced = []

    for i in range(prime_size):
        if result_chars[i] == '\0':
            for j in range(prime_size):
                if visit_count[j] == 0:
                    result_chars[i] = s[j]
                    unplaced.append(s[j])
                    visit_count[j] = 1
                    break
        else:
            placed.append(result_chars[i])

    for i in range(prime_size, length):
        unplaced.append(s[i])

    if len(unplaced) < _primes_list()[0]:
        return "".join(placed) + "".join(unplaced)

    return "".join(placed) + _char_permute("".join(unplaced), a, b)


@lru_cache(maxsize=1024)
def _get_order_table(num: int) -> str:
    """Get character permutation table for given index."""
    primes = _primes_list()
    idx = num % 29
    idx2 = (num // 29) % 29
    return _char_permute(CHARSET, primes[idx], primes[idx2])


def _string_to_xa1s(s: str) -> list:
    """Convert string to custom byte encoding (similar to UTF-8 but with different ranges)."""
    result = []
    for ch in s:
        cp = ord(ch)
        if cp < 128:
            result.append(cp)
        elif cp < 2048:
            result.append(128 | ((cp >> 7) & 15))
            result.append(cp & 127)
        elif cp >= 262144:
            result.append(160)
            result.append((cp >> 14) & 127)
            result.append((cp >> 7) & 127)
            result.append(cp & 127)
        elif (63488 & cp) != 55296:
            result.append(((cp >> 14) & 15) | 144)
            result.append((cp >> 7) & 127)
            result.append(cp & 127)
    return result


def _encode_normal_be(data: str, table: str, decode: int, encode: int, block: int) -> str:
    """Custom base encoding: converts from base 'decode' to base 'encode'."""
    xa1s = _string_to_xa1s(data)
    result = []
    buf = [0] * (block + 1)
    remainder = len(xa1s) % block
    full_part = len(xa1s) - remainder

    idx = 0
    while idx < full_part:
        value = 0
        for _ in range(block):
            value = value * decode + xa1s[idx]
            idx += 1
        for k in range(block + 1):
            buf[k] = int(value % encode)
            value //= encode
        for k in range(block, -1, -1):
            result.append(table[buf[k]])

    if remainder > 0:
        value = 0
        for _ in range(remainder):
            value = value * decode + xa1s[idx]
            idx += 1
        for k in range(remainder + 1):
            buf[k] = int(value % encode)
            value //= encode
        for k in range(remainder, -1, -1):
            result.append(table[buf[k]])

    return "".join(result)


def _make_key(key_str: str) -> int:
    """Convert a string to a large integer via bit-shift accumulation."""
    result = 0
    for ch in key_str:
        cp = ord(ch)
        shift = 32768
        for _ in range(16):
            if (shift & cp) != 0:
                break
            shift >>= 1
        result = result * (shift << 1) + cp
    return result


def _pick_unused_char(source: str, big_int_val: int, count: int, already_used: str) -> str:
    """Pick the nth unused character from source (where n = big_int_val)."""
    skipped = 0
    for i in range(count):
        if source[i] not in already_used:
            if big_int_val == skipped:
                return source[i]
            skipped += 1
    return " "


def _make_encode_table(num: int, size: int, order_table: str) -> str:
    """Create a dynamic encoding table from a key number and order table."""
    result = []
    for i in range(size):
        remaining = size - i
        remainder = num % remaining
        ch = _pick_unused_char(order_table, remainder, size, "".join(result))
        result.append(ch)
        num //= remaining
    return "".join(result)


def _prime_encode(data: str, key: str) -> str:
    """Main encoding function: encodes data with the given key."""
    decode_base = 161
    encode_base = 30
    block_size = 2

    is_string = True
    i9 = (1 if is_string else 0) % 26
    order_table = _get_order_table(i9)

    prefix = (
        chr(i9 + 97)
        + order_table[decode_base // 62]
        + order_table[decode_base % 62]
        + order_table[block_size]
        + order_table[encode_base - 1]
    )

    encoded_key = _encode_normal_be(key, order_table, decode_base, encode_base, block_size)

    big_key = _make_key(key)
    custom_table = _make_encode_table(big_key, encode_base, order_table)
    encoded_data = _encode_normal_be(data, custom_table, decode_base, encode_base, block_size)

    return prefix + order_table[len(encoded_key)] + encoded_key + encoded_data


class DynaPathToken:
    """Generates DynaPath Mobile SDK tokens for Korail API requests."""

    def __init__(
        self,
        app_id: str = "com.korail.talk",
        device_id: str = None,
        app_signature: str = None,
        os_version: str = "15",
        device_model: str = "SM-S926N",
    ):
        self._app_id = app_id
        self._device_id = device_id or self._random_device_id()
        self._app_signature = app_signature or f"[{APP_SIGNATURE_HASH}]"
        self._os_version = os_version
        self._device_model = device_model
        self._init_timestamp = int(time.time() * 1000)
        self._timestamp = None
        self._recent_timestamps = []

    @staticmethod
    def _random_device_id() -> str:
        return "".join(random.choices("0123456789abcdef", k=16))

    @staticmethod
    def _random_alpha_numeric(length: int) -> str:
        chars = string.ascii_letters + string.digits
        return "".join(random.choices(chars, k=length))

    def _action(self):
        """Update timestamps (called before each token generation)."""
        now = int(time.time() * 1000)
        self._timestamp = now
        if len(self._recent_timestamps) < 5:
            self._recent_timestamps.append(now)
        else:
            self._recent_timestamps = self._recent_timestamps[1:] + [now]

    def _to_map(self) -> OrderedDict:
        """Build parameter map matching the exact keys from the decompiled APK."""
        m = OrderedDict()
        if self._app_id is not None:
            m["ai"] = [self._app_id]
        if self._device_id is not None:
            m["di"] = [self._device_id]
        if self._app_signature is not None:
            m["as"] = [self._app_signature]
        m["su"] = ["false"]
        m["dbg"] = ["false"]
        m["emu"] = ["false"]
        m["hk"] = ["false"]
        if self._init_timestamp is not None:
            m["it"] = [str(self._init_timestamp)]
        if self._timestamp is not None:
            m["ts"] = [str(self._timestamp)]
        if self._recent_timestamps:
            m["rt"] = [str(ts) for ts in self._recent_timestamps]
        if self._os_version is not None:
            m["os"] = [self._os_version]
        if self._device_model is not None:
            m["dm"] = [self._device_model]
        m["st"] = ["Android"]
        m["sv"] = ["v1"]
        return m

    @staticmethod
    def _query_string(param_map: OrderedDict) -> str:
        """URL-encode the parameter map into a query string."""
        parts = []
        for key, values in param_map.items():
            encoded_key = quote(key, safe="")
            for val in values:
                parts.append(f"{encoded_key}={quote(val, safe='')}")
        return "&".join(parts)

    def generate(self) -> str:
        """Generate a DynaPath token for the x-dynapath-m-token header."""
        self._action()
        query = self._query_string(self._to_map())
        rand_chars = self._random_alpha_numeric(4)
        key = f"v1+{rand_chars}+{self._timestamp}"
        return _prime_encode(query, key)

    @staticmethod
    def is_macro_url(url: str) -> bool:
        """Check if a URL requires a DynaPath token."""
        return any(protected in url for protected in MACRO_PROTECTED_URLS)
