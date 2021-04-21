from typing import *


# upymod/modtrezorcrypto/modtrezorcrypto-ecash.h
def sign_schnorr(
    secret_key: bytes,
    digest: bytes,
) -> bytes:
    """
    Uses secret key to produce the Schnorr signature (XEC variant) of the
    digest.
    """


# upymod/modtrezorcrypto/modtrezorcrypto-ecash.h
def verify_schnorr(public_key: bytes, signature: bytes, digest: bytes) -> bool:
    """
    Uses public key to verify the Schnorr signature (XEC variant) of the
    digest.
    Returns True on success.
    """
