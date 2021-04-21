from ubinascii import hexlify

from trezor import TR
from trezor.enums import AmountUnit, ButtonRequestType
from trezor.messages import EcashSignStake
from trezor.ui.layouts import confirm_properties

from apps.bitcoin.sign_tx.layout import format_coin_amount
from apps.common.coininfo import CoinInfo


async def require_confirm_sign_stake(msg: EcashSignStake, coin: CoinInfo) -> None:
    await confirm_properties(
        "confirm_ecash_stake",
        TR.ecash__confirm_sign_stake,
        (
            (TR.ecash__transaction_id, hexlify(msg.txid).decode()),
            (TR.ecash__output_index, str(msg.index)),
            (
                TR.words__amount,
                format_coin_amount(msg.amount, coin, AmountUnit.BITCOIN),
            ),
            (TR.ecash__block_height, str(msg.height)),
            (TR.ecash__is_coinbase, "Yes" if msg.is_coinbase else "No"),
            (TR.ecash__expiration_time, str(msg.expiration_time)),
            (TR.ecash__master_pubkey, hexlify(msg.master_pubkey).decode()),
        ),
        hold=True,
        br_code=ButtonRequestType.Other,
    )
