"""
network/peer.py

This module stores and simplifies manipulation with peers

Example:
    You can use this as a module:
        from network.peer import Peer, fit_X, to_int

Author: XXXXXXXXXX
Date: 19/05/2025
"""

from __future__ import annotations
from asyncio import StreamReader, StreamWriter
from rlp import Serializable, encode
from rlp.sedes import Binary

PEER_SIZE = 36
MESSAGE_HEADER_SIZE = PEER_SIZE + 10

class Peer(Serializable):
    """
    Construct storing serializable peer data.
    """
    # Port is expected in range <2^0;2^15)
    fields = [
        ('id', Binary.fixed_length(16)),
        ('host', Binary.fixed_length(16)),
        ('port', Binary.fixed_length(4))
    ]

    def __init__(self, *args, **kwargs):
        """
        Peer objects contain unserializable reader, writer pair.
        """
        super().__init__(*args, **kwargs)
        self.reader: StreamReader | None = None
        self.writer: StreamWriter | None = None

    def __hash__(self):
        return hash(self.id.decode('ascii'))
    
    def __eq__(self, other):
        return isinstance(other, Peer) and self.id == other.id

    def getId(self) -> str:
        return self.id.decode('ascii')
    
    @classmethod
    def create(cls, id: str, host: str, port: int) -> Peer:
        return Peer(
            fit_X(id),
            fit_X(host),
            port.to_bytes(4, 'big')
        )
        
    def getHost(self) -> str:
        return self.host.decode('ascii').rstrip('\x00').strip()
    
    def getPort(self) -> int:
        return int.from_bytes(self.port, byteorder='big')

    @classmethod
    def empty(cls) -> Peer:
        return Peer(
            b'\x00' * 16,
            b'\x00' * 16,
            b'\x00' * 4
        )
    
    @classmethod
    def getSize(cls) -> int:
        return len(encode(cls.empty()))

    def toTuple(self) -> tuple[str, str, int]:
        return (self.id.decode('ascii'), self.host.decode('ascii'), int.from_bytes(self.port, byteorder='big'))
    
    @classmethod
    def fromTuple(cls, ttuple: tuple[str, str, int]) -> Peer:
        return Peer(
            fit_X(ttuple[0]),
            fit_X(ttuple[1]),
            ttuple[2].to_bytes(4, 'big')
        )
    

def fit_X(val: str | bytes | int | None, x: int = 16) -> bytes:
    """
    Returns value in a binary form, extended/truncated to x bytes
    """
    if val is None:
        return b'\x00' * x
    if isinstance(val, str):
        val = val.encode('ascii')
    if isinstance(val, int):
        return val.to_bytes(x,'big')
    return val[:x].ljust(x, b'\x00')

def to_int(val: bytes | None) -> int:
    """
    Conversion from bytes to an integer.
    """
    if val is None:
        return 0
    return int.from_bytes(val, byteorder='big')
