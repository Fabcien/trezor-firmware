from trezor.utils import BufferReader


def read_bitcoin_varint(r: BufferReader) -> int:
    prefix = r.get()
    if prefix < 253:
        n = prefix
    elif prefix == 253:
        n = r.get()
        n += r.get() << 8
    elif prefix == 254:
        n = r.get()
        n += r.get() << 8
        n += r.get() << 16
        n += r.get() << 24
    else:
        raise ValueError
    return n


def read_uint64_le(r: BufferReader) -> int:
    n = 0
    for i in range(0, 64, 8):
        n += r.get() << i
    return n
