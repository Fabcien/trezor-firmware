from typing import TYPE_CHECKING

from trezor.crypto.hashlib import sha256
from trezor.utils import HashWriter

from apps.bitcoin.writers import TX_HASH_SIZE, write_bytes_prefixed
from apps.common.writers import (  # noqa: F401
    write_bytes_fixed,
    write_bytes_reversed,
    write_bytes_unchecked,
    write_uint16_le,
    write_uint32_le,
    write_uint64_le,
)

if TYPE_CHECKING:
    from trezor.messages import EcashSignStake

    from apps.common.writers import Writer

write_uint16 = write_uint16_le
write_uint32 = write_uint32_le
write_uint64 = write_uint64_le


def write_stake(w: Writer, s: EcashSignStake, pubkey: bytes) -> None:
    stake_commitment_writer = HashWriter(sha256())
    write_uint64_le(stake_commitment_writer, s.expiration_time)
    write_bytes_prefixed(stake_commitment_writer, s.master_pubkey)
    stake_commitment = sha256(stake_commitment_writer.get_digest()).digest()

    write_bytes_fixed(w, stake_commitment, 32)
    write_bytes_reversed(w, s.txid, TX_HASH_SIZE)
    write_uint32_le(w, s.index)
    write_uint64_le(w, s.amount)
    height_coinbase = s.height << 1 | int(s.is_coinbase)
    write_uint32_le(w, height_coinbase)
    write_bytes_prefixed(w, pubkey)
