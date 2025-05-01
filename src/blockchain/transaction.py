# Format of a transaction
import rlp
from rlp.sedes import big_endian_int, Binary, binary, CountableList
from eth_keys import keys
from eth_utils import keccak

class TxSerializableNoSig(rlp.Serializable):
    fields = [
        ('type', big_endian_int),
        ('fee', big_endian_int),
        #('gas_limit', big_endian_int),
        ('sender', Binary.fixed_length(20, allow_empty=False))
        ('to', Binary.fixed_length(20, allow_empty=True)),
        ('value', big_endian_int),
        ('timestamp', big_endian_int),
        ('data', binary)
    ]

class FnCallArg(rlp.Serializable):
    fields = [
        ('type', big_endian_int),
        ('value', binary)
    ]

class TxMetaNoSig(rlp.Serializable):
    fields = [
        ('forwarder', big_endian_int),
        ('sender', Binary.fixed_length(20, allow_empty=False)),
        ('to', Binary.fixed_length(20, allow_empty=False)),
        ('timestamp', big_endian_int),
        ('sc', big_endian_int)
    ]

class TxMeta(rlp.Serializable):
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

class TxSerializable(rlp.Serializable):
    fields = [
        ('type', big_endian_int),
        ('fee', big_endian_int),
        #('gas_limit', big_endian_int),
        ('sender', Binary.fixed_length(20, allow_empty=False))
        ('to', Binary.fixed_length(20, allow_empty=True)),
        ('value', big_endian_int),
        ('timestamp', big_endian_int),
        ('data', binary),
        ('v', big_endian_int),
        ('r', big_endian_int),
        ('s', big_endian_int)
    ]

class Transaction():
    def __init__(self, sender: bytes, to: bytes, value: int, type: int, gas_limit: int, gas_price: int, data = b''):
        self.sender = sender
        self.to = to
        self.value = value
        self.type = type # 0 -> normal, 1 -> scap assignment, 2 -> registration
        self.gas_limit = gas_limit
        self.gas_price = gas_price
        self.data = data
        self.r = 0
        self.v = 0
        self.s = 0
        self.hash = 0
        self.signature = None  # (v, r, s)
    
    def serializeNoSig(self):
        return rlp.encode(TxSerializableNoSig(self.type, self.gas_price, self.gas_limit, self.sender, self.to, self.value, self.data))
        #return (to_bytes(self.nonce) + to_bytes(self.gas_price) + to_bytes(self.gas_limit) + self.to + to_bytes(self.value) + self.data)

    def serialize(self):
        return rlp.encode(TxSerializable(self.type, self.gas_price, self.gas_limit, self.sender, self.to, self.value, self.data, self.v, self.r, self.s))

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