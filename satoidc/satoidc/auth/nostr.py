"""Nostr authentication helpers (BIP-340 Schnorr and NIP-98 events).

The server never receives or generates private keys. A client signs an HTTP
authentication event (NIP-98, kind 27235) that binds a one-time challenge and
the verification URL, and the server only checks that signature.
"""

import hashlib
import json
import time
from typing import Any, Optional

# secp256k1 domain parameters (the curve used by Nostr keys).
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    55066263022277343669578718895168534326250603453777594175500187360389116729240,
    32670510020758816978083085130507043184471273380659243275938904335757337482424,
)

AUTH_KIND = 27235  # NIP-98: HTTP authentication.
MAX_CLOCK_SKEW_SECONDS = 60
HEX_CHARS = frozenset("0123456789abcdef")
FIELD_BYTES = 32
SIGNATURE_BYTES = 64
ID_HEX_LENGTH = 64
SIGNATURE_HEX_LENGTH = 128

Point = Optional[tuple[int, int]]


class NostrEventError(ValueError):
    """Invalid authentication event. The message is safe to show."""


def _inverse(value: int) -> int:
    return pow(value, P - 2, P)


def _point_add(point_a: Point, point_b: Point) -> Point:
    if point_a is None:
        return point_b
    if point_b is None:
        return point_a

    x1, y1 = point_a
    x2, y2 = point_b

    if x1 == x2 and (y1 + y2) % P == 0:
        return None

    if point_a == point_b:
        slope = (3 * x1 * x1) * _inverse(2 * y1 % P) % P
    else:
        slope = (y2 - y1) * _inverse((x2 - x1) % P) % P

    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    return x3, y3


def point_mul(scalar: int, point: tuple[int, int] = G) -> Point:
    result: Point = None
    addend: Point = point

    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1

    return result


def _lift_x(x: int) -> Point:
    """Return the curve point with an even y for an x-only public key."""
    if x >= P:
        return None
    y_squared = (pow(x, 3, P) + 7) % P
    y = pow(y_squared, (P + 1) // 4, P)
    if pow(y, 2, P) != y_squared:
        return None
    return x, y if y % 2 == 0 else P - y


def tagged_hash(tag: str, message: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + message).digest()


def schnorr_verify(
    message: bytes, public_key: bytes, signature: bytes
) -> bool:
    """Verify a BIP-340 Schnorr signature (x-only 32-byte public key)."""
    if (
        len(message) != FIELD_BYTES
        or len(public_key) != FIELD_BYTES
        or len(signature) != SIGNATURE_BYTES
    ):
        return False

    point = _lift_x(int.from_bytes(public_key, "big"))
    r = int.from_bytes(signature[:FIELD_BYTES], "big")
    s = int.from_bytes(signature[FIELD_BYTES:], "big")
    if point is None or r >= P or s >= N:
        return False

    challenge = tagged_hash(
        "BIP0340/challenge", signature[:FIELD_BYTES] + public_key + message
    )
    e = int.from_bytes(challenge, "big") % N
    result = _point_add(point_mul(s), point_mul(N - e, point))
    return result is not None and result[1] % 2 == 0 and result[0] == r


def _is_hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and set(value) <= HEX_CHARS
    )


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _has_valid_shape(event: Any) -> bool:
    return (
        isinstance(event, dict)
        and _is_hex(event.get("id"), ID_HEX_LENGTH)
        and _is_hex(event.get("pubkey"), ID_HEX_LENGTH)
        and _is_hex(event.get("sig"), SIGNATURE_HEX_LENGTH)
        and _is_int(event.get("created_at"))
        and _is_int(event.get("kind"))
        and isinstance(event.get("content"), str)
        and isinstance(event.get("tags"), list)
        and all(
            isinstance(tag, list) and all(isinstance(i, str) for i in tag)
            for tag in event["tags"]
        )
    )


def event_id(event: dict) -> str:
    """NIP-01 event id: sha256 of the canonical serialization."""
    serialized = json.dumps(
        [
            0,
            event["pubkey"],
            event["created_at"],
            event["kind"],
            event["tags"],
            event["content"],
        ],
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(serialized.encode()).hexdigest()


def check_auth_event(event: Any, *, url: str, challenge: str) -> str:
    """Validate a signed NIP-98 event for ``challenge`` and return its pubkey.

    The event must be a kind 27235 event with empty content and the tags
    ``["u", url]``, ``["method", "POST"]`` and ``["challenge", challenge]``,
    created within ``MAX_CLOCK_SKEW_SECONDS`` of now, with a valid id and a
    valid BIP-340 signature. Raises ``NostrEventError`` otherwise.
    """
    if not _has_valid_shape(event):
        raise NostrEventError("Invalid event")
    if event["kind"] != AUTH_KIND or event["content"]:
        raise NostrEventError("Event is not an authentication request")

    tags = event["tags"]
    if ["u", url] not in tags or ["method", "POST"] not in tags:
        raise NostrEventError("Event was signed for another URL")
    if ["challenge", challenge] not in tags:
        raise NostrEventError("Event was signed for another challenge")

    if abs(time.time() - event["created_at"]) > MAX_CLOCK_SKEW_SECONDS:
        raise NostrEventError("Event is too old or too far in the future")
    if event_id(event) != event["id"]:
        raise NostrEventError("Event id does not match its content")
    if not schnorr_verify(
        bytes.fromhex(event["id"]),
        bytes.fromhex(event["pubkey"]),
        bytes.fromhex(event["sig"]),
    ):
        raise NostrEventError("Invalid signature")
    return event["pubkey"]
