"""
middleware/rpc.py

This module defines an interface of a Remote Procedure Call message passed between the blockchain and node processes.

Example:
    You can use this as a module:
        from middleware.rpc import RPC, Param

    Parameter value types:
        0. int
        1. str
        2. float
        3. bytes
        4. BlockSerializable
        5. TxSerializable
        6. TxMeta
        7. Attestation

Author: XXXXXXXXXX
Date: 19/05/2025
"""

from __future__ import annotations
from rlp import Serializable, encode, decode
from rlp.sedes import Binary, binary, big_endian_int, CountableList
from network.peer import fit_X, to_int, Peer

class Param(Serializable):
    """
    Serializable parameter class

    Used in the RPC class
    """
    fields = [
        ('name', binary),
        ('type', Binary.fixed_length(1)),
        ('value', binary)
    ]

    @classmethod
    def fromDict(cls, ddict):
        return Param(
            ddict.get('name').encode('ascii'),
            fit_X(ddict.get('type'), 1),
            ddict.get('value')
        )
    
    @classmethod
    def constructParam(cls, name: str, type: int, value: bytes) -> Param:
        Param(name.encode('ascii'), fit_X(type, 1), value)
        return Param(name.encode('ascii'), fit_X(type, 1), value)

class RPC(Serializable):
    """
    Message passing class between the network layer and the blockchain layer.

    NOTE:
    The fields 'phase' and 'layer' are currently unused.
    """
    fields = [
        ('phase', Binary.fixed_length(1)),
        ('layer', Binary.fixed_length(1)),
        ('procedure', binary),
        ('params', CountableList(Param))
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.senderId: str = ''
        self.xclusive: bool = False

    @classmethod
    def fromDict(cls, ddict: dict) -> RPC:
        return RPC(
            fit_X(ddict.get('phase'), 1),
            fit_X(ddict.get('layer'), 1),
            ddict.get('procedure').encode('ascii'),
            ddict.get('params')
        )
    
    @classmethod
    def constructRPC(cls, func: str, params: list[Param]) -> RPC:
        return RPC.fromDict({'layer': 0, 'phase': 0, 'procedure': func, 'params': params})

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

    @classmethod
    def empty(self) -> RPC:
        return RPC(
            b'\x00',
            b'\x00',
            b'',
            []
        )

    def sserialize(self) -> bytes:
        return encode(self)
    
    @classmethod
    def ddeserialize(cls, payload) -> RPC:
        return decode(payload, RPC)

    def size(self) -> int:
        return len(self.sserialize())