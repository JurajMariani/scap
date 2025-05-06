from __future__ import annotations
from rlp import Serializable, encode, decode
from rlp.sedes import Binary
from middleware.rpc import RPC
from node.peer import Peer, fit_X

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
            ddict.get('payload_length').to_bytes(5, byteorder='big')# if ddict.get('payloal_length') is not None else ddict.get('payload').size().to_bytes(5, byteorder='big')
        )
    
    def getId(self) -> str:
        return self.id.decode('ascii')
    
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
    
    def sserialize(self) -> bytes:
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
        return self.header.getId()#.decode()

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
    
    def sserialize(self) -> bytes:
        return encode(self)
    
    @classmethod
    def deserialize(cls, msg: bytes) -> Message:
        return decode(msg, Message)