from __future__ import annotations
from rlp import Serializable, encode, decode
from rlp.sedes import Binary, binary, big_endian_int

class RPC(Serializable):
    fields = [

    ]

    def __init__(self):
        pass

    @classmethod
    def empty(self) -> RPC:
        pass

    def serialize(self) -> bytes:
        return encode(self)
    
    @classmethod
    def deserialize(cls, payload) -> RPC:
        return decode(payload, RPC)

    def size(self) -> int:
        return len(self.serialize())