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

import base64
from typing import TYPE_CHECKING

import click

from .. import ecash, tools
from . import with_client

if TYPE_CHECKING:
    from ..client import TrezorClient


@click.group(name="ecash")
def cli() -> None:
    """eCash commands."""


@cli.command()
@click.option("-n", "--address", required=True, help="BIP-32 path")
@click.argument("txid", type=str)
@click.argument("index", type=int)
@click.argument("amount", type=int)
@click.argument("height", type=int)
@click.argument("is_coinbase", type=bool)
@click.argument("expiration_time", type=int)
@click.argument("master_pubkey", type=str)
@with_client
def sign_stake(
    client: "TrezorClient",
    address: str,
    txid: str,
    index: int,
    amount: int,
    height: int,
    is_coinbase: bool,
    expiration_time: int,
    master_pubkey: str,
):
    """Sign an avalanche stake."""

    msg = ecash.sign_stake(
        client,
        tools.parse_path(address),
        bytes.fromhex(txid),
        index,
        amount,
        height,
        is_coinbase,
        expiration_time,
        bytes.fromhex(master_pubkey),
    )

    return {
        "pubkey": msg.pubkey.hex(),
        "signature": base64.b64encode(msg.signature).decode(),
    }
