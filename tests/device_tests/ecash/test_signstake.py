# This file is part of the Trezor project.
#
# Copyright (C) 2025 SatoshiLabs and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.


import pytest

from trezorlib import ecash
from trezorlib.tools import parse_path

SCHNORR_SIGNATURE_LENGTH = 64


def case(id, *args):
    return pytest.param(*args, id=id, marks=pytest.mark.altcoin)


VECTORS = (  # case name, address, txid, index, amount, height, is_coinbase, expiration_time, master_pubkey, pubkey, signature
    case(
        # Extracted from an avalanche proof generated with Electrum ABC
        "eCash Testnet",
        "44h/1h/0h/0/0",
        "117a38af059b3e1548786b5bd8241cdaaf44d5c6bd52469a2f0c4c191965921e",
        0,
        10000000000,
        1644744,
        False,
        1832058488,
        "0219f01868c0bf83ac03987092ed568c1f13fee30e2b907de244a2c84c9438d617",
        "03ea05da8b9ed8d02830340caad68c412e83b8c6d52fd6d7bb1cc57664f1c522f6",
        "3efa7a6bd81cd399dbc8ef9187b73ff78d5643f86ef22939e4089115de40eafdb41c24f0b91874f624a896b1ff6ef4cbc3dbc01a469aad928a47332d27a8bd5e",
    ),
)


@pytest.mark.skip_t1
@pytest.mark.parametrize(
    "coin_name, path, txid, index, amount, height, is_coinbase, expiration_time, master_pubkey, pubkey, signature",
    VECTORS,
)
def test_signstake(
    client,
    path,
    txid,
    index,
    amount,
    height,
    is_coinbase,
    expiration_time,
    master_pubkey,
    pubkey,
    signature,
):
    res = ecash.sign_stake(
        client,
        address_n=parse_path(path),
        txid=bytes.fromhex(txid),
        index=index,
        amount=amount,
        height=height,
        is_coinbase=is_coinbase,
        expiration_time=expiration_time,
        master_pubkey=bytes.fromhex(master_pubkey),
    )

    assert res.pubkey.hex() == pubkey
    assert len(res.signature) == SCHNORR_SIGNATURE_LENGTH
    assert res.signature.hex() == signature
