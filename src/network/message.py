"""
network/message.py

This module defines a class for storage and easier manipulation with the serializable network message.

Example:
    You can use this as a module:
        from network.message import Message (, MessageHreader) 

    MSG format:
    {
        id:             str(nodeID),                        <
        type:           str(messageType),                   |
        subtype:        str(messageSubType),                | MessageHeader
        sender:         tuple[nodeID, nodeIp, nodePort],    |
        payload_length  int,                                <
        payload:        dict(RPC)                           < Payload
    }

Author: Bc. Juraj Marini, <xmaria03@stud.fit.vutbr.cz>
Date: 19/05/2025
"""

from __future__ import annotations
from rlp import Serializable, encode, decode
from rlp.sedes import Binary
from middleware.rpc import RPC
from network.peer import Peer, fit_X

class MessageHeader(Serializable):
    """
    Network message header.
    Contains message metadata.
    """
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
            'id': self.id.decode('ascii'),
            'type': self.type.rstrip(b"\x00").decode('ascii'),
            'subtype': self.subtype.rstrip(b"\x00").decode('ascii'),
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
    """
    Network message serializable class.

    Payload contains the Remote Procedure Class passed to the Blockchain layer.
    """
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
    def ddeserialize(cls, msg: bytes) -> Message:
        return decode(msg, Message)