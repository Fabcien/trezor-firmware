# Automatically generated by pb2py
# fmt: off
# isort:skip_file
import protobuf as p

if __debug__:
    try:
        from typing import Dict, List, Optional  # noqa: F401
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        pass


class StellarManageDataOp(p.MessageType):
    MESSAGE_WIRE_TYPE = 220

    def __init__(
        self,
        *,
        source_account: Optional[str] = None,
        key: Optional[str] = None,
        value: Optional[bytes] = None,
    ) -> None:
        self.source_account = source_account
        self.key = key
        self.value = value

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('source_account', p.UnicodeType, None),
            2: ('key', p.UnicodeType, None),
            3: ('value', p.BytesType, None),
        }
