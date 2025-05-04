from __future__ import annotations
from uuid import uuid4
from middleware.rpc import RPC
from asyncio import StreamReader, StreamWriter
from rlp import Serializable, encode, decode
from rlp.sedes import Binary, binary, big_endian_int

PEER_SIZE = 36
MESSAGE_HEADER_SIZE = PEER_SIZE + 10

class Peer(Serializable):
    # Port is expected in range <2^0;2^15)
    fields = [
        ('id', Binary.fixed_length(16)),
        ('host', Binary.fixed_length(16)),
        ('port', Binary.fixed_length(4))
    ]

    def __init__(self):
        # Runtime-only data (won't get serialized)
        self.reader: StreamReader | None = None
        self.writer: StreamWriter | None = None

    def getId(self) -> str:
        return self.id.decode()
    
    @classmethod
    def create(cls, id: str, host: str, port: int) -> Peer:
        return Peer(
            fit_X(id),
            fit_X(host),
            port.to_bytes(4, 'big')
        )
        
    def getHost(self) -> str:
        return self.host.decode()
    
    def getPort(self) -> int:
        return self.port

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
    

def fit_X(val: str | bytes | None, x: int = 16) -> bytes:
    if val is None:
        return b'\x00' * x
    if isinstance(val, str):
        val = val.encode('ascii')
    return val[:x].ljust(x, b'\x00')

def to_int(val: bytes | None) -> int:
    if val is None:
        return 0
    return int.from_bytes(val, byteorder='big')
    

class MessageHeader(Serializable):
    fields = [
        ('id', Binary.fixed_length(16)),
        ('type', Binary.fixed_length(16)),
        ('subtype', Binary.fixed_length(16)),
        ('sender', Peer),
        # To be able to have up to 1,048,575B of payload
        # this integer should be 5 bytes
        ('payload_length', Binary.fixed_length(5))
    ]

    @classmethod
    def getSize(cls) -> int:
        return len(encode(cls.empty()))

    @classmethod
    def fromDict(cls, ddict: dict) -> MessageHeader:
        return MessageHeader(
            fit_X(ddict.get('id')),
            fit_X(ddict.get('type')),
            fit_X(ddict.get('subtype')),
            ddict.get('sender'),
            ddict.get('payload_length').to_bytes(5, byteorder='big') if ddict.get('payloal_length') != None else ddict.get('payload').size().to_bytes(5, byteorder='big')
        )
    
    def getId(self) -> str:
        return self.id.decode()
    
    def getPL(self) -> int:
        return int.from_bytes(self.payload_length, byteorder='big')

    def toDict(self) -> dict:
        return {
            'id': self.id.decode(),
            'type': self.type.decode(),
            'subtype': self.subtype.decode(),
            'sender': self.sender,
            'payload_length': int.from_bytes(self.payload_length, byteorder='big')
        }

    @classmethod
    def empty(cls) -> MessageHeader:
        return MessageHeader(
            b'\x00' * 16,
            b'\x00' * 16,
            b'\x00' * 16,
            Peer().empty(),
            b'\x00' * 5
        )
    
    def serialize(self) -> bytes:
        return encode(self)

class Message(Serializable):
    fields = [
        ('header', MessageHeader),
        ('payload', RPC)
    ]

    @classmethod
    def fromDict(cls, ddict: dict) -> Message:
        return Message(
            MessageHeader.fromDict(ddict),
            ddict.get('payload')
        )
    
    def getId(self) -> str:
        return self.id.decode()

    def toDict(self) -> dict:
        return {
            'header': self.header.toDict(),
            'payload': self.payload,
        }

    @classmethod
    def empty(cls) -> Message:
        return Message(
            MessageHeader.empty(),
            RPC().empty()
        )
    
    def serialize(self) -> bytes:
        return encode(self)