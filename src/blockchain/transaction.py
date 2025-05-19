# Format of a transaction
"""
blockchain/transaction.py

This module defines serializable classes for transactions, allowing simple signing and modification.

Example:
    You can use this as a module:
        from blockchain.transaction import TxSerializable, TxMeta (, *)

Author: Bc. Juraj Marini, <xmaria03@stud.fit.vutbr.cz>
Date: 19/05/2025
"""

from __future__ import annotations
from rlp import Serializable, encode, decode
from rlp.sedes import big_endian_int, Binary, binary, CountableList
from eth_keys import keys
from eth_utils import keccak


class TxSerializableNoSig(Serializable):
    """
    Serializable representation of a Transaction, without a sig.
    """
    fields = [
        ('nonce', big_endian_int),
        ('type', big_endian_int),
        ('fee', big_endian_int),
        #('gas_limit', big_endian_int),
        ('sender', Binary.fixed_length(20, allow_empty=False)),
        ('to', Binary.fixed_length(20, allow_empty=True)),
        ('value', big_endian_int),
        ('timestamp', big_endian_int),
        ('data', binary)
    ]

    def hash(self) -> bytes:
        """
        Calculate a keccak hash of the bytes representation.
        """
        return keccak(encode(self))
    
    def sign(self, privK: bytes) -> TxSerializable:
        """
        Sign the Tx and thus return the TxSerializable instance.
        """
        sk = keys.PrivateKey(privK)
        sig = sk.sign_msg_hash(self.hash())
        return TxSerializable(
            self.nonce,
            self.type,
            self.fee,
            self.sender,
            self.to,
            self.value,
            self.timestamp,
            self.data,
            sig.v,
            sig.r,
            sig.s
        )

class TxMetaNoSig(Serializable):
    """
    A meta transaction representation.

    Forwarder is a nonce-like value used for Meta Txn.
    """
    fields = [
        ('forwarder', big_endian_int),
        ('sender', Binary.fixed_length(20, allow_empty=False)),
        ('to', Binary.fixed_length(20, allow_empty=False)),
        ('timestamp', big_endian_int),
        ('sc', big_endian_int)
    ]

    def hash(self) -> bytes:
        return keccak(encode(self))
    
    def sign(self, privK: bytes) -> TxMeta:
        sk = keys.PrivateKey(privK)
        sig = sk.sign_msg_hash(self.hash())
        return TxMeta(
            self.forwarder,
            self.sender,
            self.to,
            self.timestamp,
            self.sc,
            sig.v,
            sig.r,
            sig.s
        )

class TxMeta(Serializable):
    """
    Meta transaction.
    """
    fields = [
        ('forwarder', big_endian_int),
        ('sender', Binary.fixed_length(20, allow_empty=False)),
        ('to', Binary.fixed_length(20, allow_empty=False)),
        ('timestamp', big_endian_int),
        ('sc', big_endian_int),
        ('v', big_endian_int),
        ('r', big_endian_int),
        ('s', big_endian_int)
    ]

    def hash(self):
        txmetans = TxMetaNoSig(
            self.forwarder,
            self.sender,
            self.to,
            self.timestamp,
            self.sc
        )
        return txmetans.hash()
    
    def recoverAddress(self):
        signature = keys.Signature(vrs=(self.v, self.r, self.s))
        pk = signature.recover_public_key_from_msg_hash(self.hash())
        return pk.to_canonical_address()
    
    def verifySig(self) -> bool:
        """
        Returns TRUE if the sender is the signer.
        """
        return self.recoverAddress() == self.sender
    
    def sserialize(self) -> bytes:
        return encode(self)
    
    @classmethod
    def ddeserialize(cls, txm) -> TxMeta:
        return decode(txm, TxMeta)

class TxSerializable(Serializable):
    """
    Transaction representation.

    NOTE:
    Tx types are:
    0 -> Normal transfer
    1 -> Reassignment of social capital
    2 -> Registration of identity (can award SC)
    3 -> Registration of social media (can receive SC and produce blocks)
    4 -> Replacement TX (untested)
    """
    fields = [
        ('nonce', big_endian_int),
        # 0 -> normal
        # 1 -> scap assignment
        # 2 -> registration
        # 3 -> soc media registration
        # 4 -> replacement (upon recv, node changes type based on orig tx)
        ('type', big_endian_int),
        ('fee', big_endian_int),
        #('gas_limit', big_endian_int),
        ('sender', Binary.fixed_length(20, allow_empty=False)),
        ('to', Binary.fixed_length(20, allow_empty=True)),
        ('value', big_endian_int),
        ('timestamp', big_endian_int),
        ('data', binary),
        ('v', big_endian_int),
        ('r', big_endian_int),
        ('s', big_endian_int)
    ]

    def hash(self):
        txns = TxSerializableNoSig(
            self.nonce,
            self.type,
            self.fee,
            self.sender,
            self.to,
            self.value,
            self.timestamp,
            self.data
        )
        return txns.hash()
    
    def sign(self, privK: bytes) -> TxSerializable:
        sk = keys.PrivateKey(privK)
        sig = sk.sign_msg_hash(self.hash())
        return TxSerializable(
            self.nonce,
            self.type,
            self.fee,
            self.sender,
            self.to,
            self.value,
            self.timestamp,
            self.data,
            sig.v,
            sig.r,
            sig.s
        )
    
    def recoverAddress(self):
        signature = keys.Signature(vrs=(self.v, self.r, self.s))
        pk = signature.recover_public_key_from_msg_hash(self.hash())
        return pk.to_canonical_address()
    
    def verifySig(self) -> bool:
        return self.recoverAddress() == self.sender
    
    def getFeasibilityMetric(self) -> float:
        """
        Return Tx's feasibility metric.

        The metric is fee/B.
        """
        txBytes = len(encode(self))
        return self.fee / txBytes
    
    def update(
        self, nonce: bool = False, type: int | None = None,
        fee: int | None = None, sender: bytes | None = None,
        to: bytes | None = None, value : int | None = None,
        timestamp: int | None = None, data: bytes | None = None,
        v: int | None = None, r: int | None = None, s: int | None = None 
    ) -> TxSerializable:
        """
        A monolith used to update a Transaction.

        Implemented for ease of use.
        
        NOTE:
        This method returns a new instance of 'TxSerializable' as any 'rlp.Serializable' class is immutable.
        """
        return TxSerializable(
            self.nonce + 1 if nonce else self.nonce,
            type if not None else self.type,
            fee if not None else self.fee,
            sender if not None else self.sender,
            to if not None else self.to,
            value if not None else self.value,
            timestamp if not None else self.timestamp,
            data if not None else self.data,
            v if not None else self.v,
            r if not None else self.r,
            s if not None else self.s
        )
    
    def sserialize(self) -> bytes:
        return encode(self)
    
    @classmethod
    def ddeserialize(cls, tx: bytes) -> TxSerializable:
        return decode(tx, TxSerializable)
    
    def eq(self, b: TxSerializable) -> bool:
        """
        Returns TRUE if a Tx 'b' is equal to this one.
        """
        return (
            self.nonce == b.nonce and
            self.type == b.type and
            self.fee == b.fee and
            self.sender == b.sender and
            self.to == b.to and 
            self.value == b.value and
            self.timestamp == b.timestamp and
            self.data == b.data and
            self.v == b.v and
            self.r == b.r and
            self.s == b.s
        )
