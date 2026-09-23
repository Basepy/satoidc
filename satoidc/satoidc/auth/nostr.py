from __future__ import annotations

from dataclasses import dataclass
from secrets import randbelow

from bech32 import bech32_decode, bech32_encode, convertbits

# secp256k1 parameters used by Nostr keys.
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    55066263022277343669578718895168534326250603453777594175500187360389116729240,
    32670510020758816978083085130507043184471273380659243275938904335757337482424,
)


class NostrKeyError(ValueError):
    pass


@dataclass(frozen=True)
class NostrKeys:
    private_key_hex: str
    public_key_hex: str
    nsec: str
    npub: str


def _inverse(value: int) -> int:
    return pow(value, P - 2, P)


def _point_add(
    point_a: tuple[int, int] | None,
    point_b: tuple[int, int] | None,
) -> tuple[int, int] | None:
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


def _point_mul(
    scalar: int,
    point: tuple[int, int] = G,
) -> tuple[int, int] | None:
    if scalar % N == 0:
        return None

    result = None
    addend = point

    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1

    return result


def _bech32_to_bytes(value: str, expected_hrp: str) -> bytes:
    hrp, data = bech32_decode(value)
    if hrp != expected_hrp or data is None:
        raise NostrKeyError(f"Invalid {expected_hrp} key.")
    decoded = convertbits(data, 5, 8, False)
    if decoded is None:
        raise NostrKeyError(f"Invalid {expected_hrp} payload.")
    return bytes(decoded)


def _bytes_to_bech32(hrp: str, value: bytes) -> str:
    data = convertbits(value, 8, 5, True)
    if data is None:
        raise NostrKeyError("Could not encode Nostr key.")
    encoded = bech32_encode(hrp, data)
    if not encoded:
        raise NostrKeyError("Could not encode Nostr key.")
    return encoded


def parse_private_key(value: str) -> int:
    raw = (value or "").strip()
    if not raw:
        raise NostrKeyError("Nostr private key is required.")

    if raw.startswith("nsec1"):
        key_bytes = _bech32_to_bytes(raw, "nsec")
        if len(key_bytes) != 32:
            raise NostrKeyError("Nostr private key must have 32 bytes.")
        private_key = int.from_bytes(key_bytes, "big")
    else:
        normalized = raw.removeprefix("0x")
        if len(normalized) != 64:
            raise NostrKeyError(
                "Use a nsec key or a 64-character hex private key."
            )
        try:
            private_key = int(normalized, 16)
        except ValueError as exc:
            raise NostrKeyError("Invalid hex private key.") from exc

    if not 1 <= private_key < N:
        raise NostrKeyError("Nostr private key is outside the secp256k1 range.")

    return private_key


def private_key_to_public_key(private_key: int) -> str:
    point = _point_mul(private_key)
    if point is None:
        raise NostrKeyError("Could not derive Nostr public key.")
    return f"{point[0]:064x}"


def normalize_public_key(value: str) -> str:
    raw = (value or "").strip()
    if raw.startswith("npub1"):
        key_bytes = _bech32_to_bytes(raw, "npub")
        if len(key_bytes) != 32:
            raise NostrKeyError("Nostr public key must have 32 bytes.")
        return key_bytes.hex()

    normalized = raw.removeprefix("0x")
    if len(normalized) != 64:
        raise NostrKeyError(
            "Use a npub key or a 64-character hex public key."
        )
    try:
        int(normalized, 16)
    except ValueError as exc:
        raise NostrKeyError("Invalid hex public key.") from exc
    return normalized.lower()


def npub_from_public_key(public_key_hex: str) -> str:
    public_key = normalize_public_key(public_key_hex)
    return _bytes_to_bech32("npub", bytes.fromhex(public_key))


def nsec_from_private_key(private_key: int) -> str:
    return _bytes_to_bech32("nsec", private_key.to_bytes(32, "big"))


def keys_from_private_key(value: str) -> NostrKeys:
    private_key = parse_private_key(value)
    private_key_hex = f"{private_key:064x}"
    public_key_hex = private_key_to_public_key(private_key)
    return NostrKeys(
        private_key_hex=private_key_hex,
        public_key_hex=public_key_hex,
        nsec=nsec_from_private_key(private_key),
        npub=npub_from_public_key(public_key_hex),
    )


def generate_keys() -> NostrKeys:
    private_key = randbelow(N - 1) + 1
    return keys_from_private_key(f"{private_key:064x}")
