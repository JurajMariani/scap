from __future__ import annotations
from rlp import Serializable, encode, decode
from rlp.sedes import Binary, binary, big_endian_int, CountableList
from node.peer import fit_X, to_int

class Param(Serializable):
    fields = [
        ('name', binary),
        ('type', Binary.fixed_length(1)),
        ('value', binary)
    ]

class RPC(Serializable):
    fields = [
        ('phase', Binary.fixed_length(1)),
        ('layer', Binary.fixed_length(1)),
        ('procedure', binary),
        ('params', CountableList(Param))
    ]

    @classmethod
    def fromDict(cls) -> RPC:
        pass


    def toDict(self) -> dict:
        paramList = []
        for p in self.params:
            paramList.append({
                'name': p.name.decode('ascii'),
                'type': to_int(p.type),
                'value': self.value
            })
        return {
            'phase': to_int(self.phase),
            'layer': to_int(self.layer),
            'procedure': self.procedure.decode('ascii'),
            'params': paramList
        }

    def __init__(self):
        self.pphase = ''
        self.llayer = ''
        self.proc = b''
        self.paramList = []

    def export(self) -> RPC:
        return RPC(
            self.pphase,
            self.llayer,
            self.proc,
            self.paramList
        )

    @classmethod
    def empty(self) -> RPC:
        return RPC(
            b'\x00',
            b'\x00',
            b'',
            []
        )

    def serialize(self) -> bytes:
        return encode(self)
    
    @classmethod
    def deserialize(cls, payload) -> RPC:
        return decode(payload, RPC)

    def size(self) -> int:
        return len(self.serialize())