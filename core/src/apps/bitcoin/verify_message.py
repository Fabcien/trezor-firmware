from trezor import wire
from trezor.crypto.curve import secp256k1
from trezor.crypto.hashlib import sha256
from trezor.messages.InputScriptType import SPENDADDRESS, SPENDP2SHWITNESS, SPENDWITNESS
from trezor.messages.SigningAlgo import ECDSA, SCHNORRBCH
from trezor.messages.Success import Success

from apps.common import coins
from apps.common.coininfo import CoinInfo
from apps.common.confirm import require_confirm
from apps.common.signverify import (
    message_digest,
    require_confirm_verify_message,
    require_confirm_verify_message_pubkey,
)

from .addresses import (
    address_p2wpkh,
    address_p2wpkh_in_p2sh,
    address_pkh,
    address_short,
    address_to_cashaddr,
)

if False:
    from trezor.messages.VerifyMessage import VerifyMessage
    from trezor.messages.TxInputType import EnumTypeInputScriptType

async def verify_message_ecdsa(ctx: wire.Context, message: bytes, address: str, signature: bytes, coin: CoinInfo) -> bool:
    digest = message_digest(coin, message)

    recid = signature[0]
    if (recid >= 27 and recid <= 34):
        # p2pkh
        script_type: EnumTypeInputScriptType = SPENDADDRESS
    elif recid >= 35 and recid <= 38:
        # segwit-in-p2sh
        script_type = SPENDP2SHWITNESS
        signature = bytes([signature[0] - 4]) + signature[1:]
    elif recid >= 39 and recid <= 42:
        # native segwit
        script_type = SPENDWITNESS
        signature = bytes([signature[0] - 8]) + signature[1:]
    else:
        return False

    pubkey = secp256k1.verify_recover(signature, digest)

    if not pubkey:
        return False

    if script_type == SPENDADDRESS:
        addr = address_pkh(pubkey, coin)
        if coin.cashaddr_prefix is not None:
            addr = address_to_cashaddr(addr, coin)
    elif script_type == SPENDP2SHWITNESS:
        addr = address_p2wpkh_in_p2sh(pubkey, coin)
    elif script_type == SPENDWITNESS:
        addr = address_p2wpkh(pubkey, coin)
    else:
        return False

    if addr != address:
        return False

    await require_confirm_verify_message(
        ctx, address_short(coin, address), coin.coin_shortcut, message
    )

    return True

async def verify_message_schnorr(ctx: wire.Context, message: bytes, pubkey: bytes, signature: bytes, coin: CoinInfo) -> bool:
    def sha(b):
        return sha256(b).digest()
    digest = sha(sha(message))

    if not secp256k1.verify_schnorr(pubkey, signature, digest):
        return False

    await require_confirm_verify_message_pubkey(
        ctx, pubkey, coin.coin_shortcut, message
    )

    return True

async def verify_message(ctx: wire.Context, msg: VerifyMessage) -> Success:
    message = msg.message
    address = msg.address
    signature = msg.signature
    coin_name = msg.coin_name or "Bitcoin"
    signing_algo = msg.signing_algo or ECDSA
    pubkey = msg.pubkey or None
    coin = coins.by_name(coin_name)

    if signing_algo == ECDSA:
        signature_valid = await verify_message_ecdsa(ctx, message, address, signature, coin)
    elif signing_algo == SCHNORRBCH:
        if pubkey is None:
            raise wire.ProcessError("Verifying messages signed with Schnorr require supplying the public key")
        signature_valid = await verify_message_schnorr(ctx, message, pubkey, signature, coin)
    else:
        raise wire.ProcessError("Unsupported signing algorithm")

    if not signature_valid:
        raise wire.ProcessError("Invalid signature")

    return Success(message="Message verified")
