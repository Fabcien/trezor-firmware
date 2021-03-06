# Automatically generated by pb2py
# fmt: off
# isort:skip_file
from .. import protobuf as p

if __debug__:
    try:
        from typing import Dict, List, Optional  # noqa: F401
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        pass


class EthereumTxRequest(p.MessageType):
    MESSAGE_WIRE_TYPE = 59

    def __init__(
        self,
        *,
        data_length: Optional[int] = None,
        signature_v: Optional[int] = None,
        signature_r: Optional[bytes] = None,
        signature_s: Optional[bytes] = None,
    ) -> None:
        self.data_length = data_length
        self.signature_v = signature_v
        self.signature_r = signature_r
        self.signature_s = signature_s

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('data_length', p.UVarintType, None),
            2: ('signature_v', p.UVarintType, None),
            3: ('signature_r', p.BytesType, None),
            4: ('signature_s', p.BytesType, None),
        }
