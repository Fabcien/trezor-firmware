from trezor.crypto import ecash
from trezor.crypto.hashlib import sha256
from trezor.messages import EcashSignStake, EcashStakeSignature
from trezor.utils import HashWriter

from apps.common.coininfo import by_name

# from apps.bitcoin.keychain import validate_path_against_script_type
from apps.common.keychain import Keychain, auto_keychain
from apps.common.paths import validate_path
from apps.ecash.layout import require_confirm_sign_stake
from apps.ecash.writers import write_stake


@auto_keychain(__name__)
async def sign_stake(
    msg: EcashSignStake,
    keychain: Keychain,
) -> EcashStakeSignature:
    coin = by_name("Ecash")
    address_n = msg.address_n

    await validate_path(keychain, address_n)
    await require_confirm_sign_stake(msg, coin)

    node = keychain.derive(address_n)
    pubkey = node.public_key()

    w = HashWriter(sha256())
    write_stake(w, msg, pubkey)
    digest = sha256(w.get_digest()).digest()

    signature = ecash.sign_schnorr(node.private_key(), digest)

    return EcashStakeSignature(pubkey=pubkey, signature=signature)
