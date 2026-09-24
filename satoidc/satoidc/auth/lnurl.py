import ecdsa
from bech32 import bech32_encode, convertbits


def url_encode(url: str) -> str:
    """
    Encode a URL without validating it first and return a bech32 LNURL string.
    """
    bech32_data = convertbits(url.encode("utf-8"), 8, 5, True)
    assert bech32_data
    return bech32_encode("lnurl", bech32_data).upper()


def verify(k1: str, key: str, sig: str) -> bool:
    """
    Verifica a assinatura do k1 feita pela linkingKey da carteira (LUD-04).

    A assinatura normalmente vem em DER, mas algumas carteiras enviam o
    formato compacto (r||s, 64 bytes); aceitamos os dois.
    """
    try:
        k1_bytes = bytes.fromhex(k1)
        key_bytes = bytes.fromhex(key)
        sig_bytes = bytes.fromhex(sig)
        vk = ecdsa.VerifyingKey.from_string(key_bytes, curve=ecdsa.SECP256k1)
    except (ValueError, ecdsa.errors.MalformedPointError):
        return False

    for decode in (ecdsa.util.sigdecode_der, ecdsa.util.sigdecode_string):
        try:
            if vk.verify_digest(sig_bytes, k1_bytes, sigdecode=decode):
                return True
        except (
            ecdsa.keys.BadSignatureError,
            ecdsa.keys.BadDigestError,
            ecdsa.der.UnexpectedDER,
            ValueError,
        ):
            continue
    return False
