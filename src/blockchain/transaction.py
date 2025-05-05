# Format of a transaction
from __future__ import annotations
from rlp import Serializable, encode, decode
from rlp.sedes import big_endian_int, Binary, binary, CountableList
from eth_keys import keys
from eth_utils import keccak


class TxSerializableNoSig(Serializable):
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
        return keccak(encode(self))
    
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


class FnCallArg(Serializable):
    fields = [
        ('type', big_endian_int),
        ('value', binary)
    ]

class TxMetaNoSig(Serializable):
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
        return TxSerializable(
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
        return self.recoverAddress() == self.sender
    
    def serialize(self) -> bytes:
        return encode(self)
    
    @classmethod
    def deserialize(cls, txm) -> TxMeta:
        return decode(txm, TxMeta)

class TxSerializable(Serializable):
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
        txBytes = len(encode(self))
        return self.fee / txBytes
    
    def update(
        self, nonce: bool = False, type: int | None = None,
        fee: int | None = None, sender: bytes | None = None,
        to: bytes | None = None, value : int | None = None,
        timestamp: int | None = None, data: bytes | None = None,
        v: int | None = None, r: int | None = None, s: int | None = None 
    ) -> TxSerializable:
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
    
    def serialize(self) -> bytes:
        return encode(self)
    
    @classmethod
    def deserialize(cls, tx) -> TxSerializable:
        return decode(tx, TxSerializable)

class Transaction():
    def __init__(self, sender: bytes, to: bytes, value: int, type: int, gas_limit: int, gas_price: int, data = b''):
        self.sender = sender
        self.to = to
        self.value = value
        self.type = type 
        self.gas_limit = gas_limit
        self.gas_price = gas_price
        self.data = data
        self.r = 0
        self.v = 0
        self.s = 0
        self.hash = 0
        self.signature = None  # (v, r, s)
    
    def serializeNoSig(self):
        return encode(TxSerializableNoSig(self.type, self.gas_price, self.gas_limit, self.sender, self.to, self.value, self.data))
        #return (to_bytes(self.nonce) + to_bytes(self.gas_price) + to_bytes(self.gas_limit) + self.to + to_bytes(self.value) + self.data)

    def serialize(self):
        return encode(TxSerializable(self.type, self.gas_price, self.gas_limit, self.sender, self.to, self.value, self.data, self.v, self.r, self.s))

    def hashTx(self):
        tx = self.serializeNoSig()
        self.hash = keccak(tx)
    
    def sign(self, private_key: str, chain_id=1):
        self.v = chain_id
        if not self.hash:
            self.hashTx()

        pk = keys.PrivateKey(bytes.fromhex(private_key))
        self.signature = pk.sign_msg_hash(self.hash)
        self.v = self.signature.v + (chain_id * 2 + 35)
        self.r = self.signature.r
        self.s = self.signature.s

    def gossip(self):
        pass

def to_bytes(val: int) -> bytes:
    if val == 0:
        return b''
    return val.to_bytes((val.bit_length() + 7) // 8, byteorder='big')