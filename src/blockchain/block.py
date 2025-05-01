import rlp
from rlp.sedes import big_endian_int, Binary, binary, CountableList
from eth_keys import keys
from eth_utils import keccak

from transaction import Transaction, TxSerializable

class BlockFull(rlp.Serializable):
    fields = [
        ('parent_hash', Binary.fixed_length(32, allow_empty=False)),
        ('state_root', Binary.fixed_length(32, allow_empty=False)),
        ('transactions_root', Binary.fixed_length(32, allow_empty=False)),
        ('receipts_root', Binary.fixed_length(32, allow_empty=False)),
        ('block_number', big_endian_int),
        ('beneficiary', Binary.fixed_length(20, allow_empty=False)),
        ('timestamp', big_endian_int),
        ('signature', Binary.fixed_length(65, allow_empty=False)),
        ('data', Binary.fixed_length(32, allow_empty=True)),
        ('transactions', CountableList(TxSerializable))
    ]

class BlockNoSig(rlp.Serializable):
    fields = [
        ('parent_hash', Binary.fixed_length(32, allow_empty=False)),
        ('state_root', Binary.fixed_length(32, allow_empty=False)),
        ('transactions_root', Binary.fixed_length(32, allow_empty=False)),
        ('receipts_root', Binary.fixed_length(32, allow_empty=False)),
        ('block_number', big_endian_int),
        ('beneficiary', Binary.fixed_length(20, allow_empty=False)),
        ('timestamp', big_endian_int),
        #('signature', Binary.fixed_length(65, allow_empty=False)),
        ('data', Binary.fixed_length(32, allow_empty=True)),
        #('transactions', CountableList(Transaction))
    ]

class BlockSig(rlp.Serializable):
    fields = [
        ('parent_hash', Binary.fixed_length(32, allow_empty=False)),
        ('state_root', Binary.fixed_length(32, allow_empty=False)),
        ('transactions_root', Binary.fixed_length(32, allow_empty=False)),
        ('receipts_root', Binary.fixed_length(32, allow_empty=False)),
        ('block_number', big_endian_int),
        ('beneficiary', Binary.fixed_length(20, allow_empty=False)),
        ('timestamp', big_endian_int),
        ('signature', Binary.fixed_length(65, allow_empty=False)),
        ('data', Binary.fixed_length(32, allow_empty=True)),
        #('transactions', CountableList(Transaction))
    ]

class Block():
    def __init__(self, parent_hash: bytes, state_root: bytes, receipts_root: bytes, benef: bytes, block_num: int, timestamp: int, data = b''):
        self.parent_hash = parent_hash
        self.state_root = state_root
        self.receipts_root = receipts_root
        self.transactions_root = b''
        self.beneficiary = benef
        self.block_number = block_num
        #self.gas_limit = ""
        self.timestamp = timestamp
        self.signature = b''
        self.data = data
        self.transactions = []

    def addTransaction(self, tx: Transaction):
        self.transactions.append(tx)

    def serializeNoSig(self):
        return rlp.encode(BlockNoSig(self.parent_hash, self.state_root, self.transactions_root, self.receipts_root, self.block_number, self.beneficiary, self.timestamp, self.data))

    def serializeSig(self):
        return rlp.encode(BlockSig(self.parent_hash, self.state_root, self.transactions_root, self.receipts_root, self.block_number, self.beneficiary, self.timestamp, self.signature.to_bytes(), self.data))

    def serialize(self):
        print(self.signature.to_bytes().hex())
        return rlp.encode(BlockFull(self.parent_hash, self.state_root, self.transactions_root, self.receipts_root, self.block_number, self.beneficiary, self.timestamp, self.signature.to_bytes(), self.data, []))
    
    def calculateTxHash(self):
        hashlist = []
        for tx in self.transactions:
            if not tx.hash:
                tx.hashTx()
            hashlist.append(tx.hash)
        i = 0
        while (i < len(hashlist)):
            if (i + 1 >= len(hashlist)):
                self.transactions_root = hashlist[-1]
                return 0
            nhash = hashlist[i] + hashlist[i + 1]
            hashlist.append(keccak(nhash))
            i += 2
        return -1
    
    def serializeTxs(self):
        txs = []
        for tx in self.transactions:
            txs.append(tx.serialize())
        return txs

    def sign(self, pub_key: str):
        self.calculateTxHash()
        b = self.serializeNoSig()
        hash = keccak(b)

        pk = keys.PrivateKey(bytes.fromhex(pub_key))
        self.signature = pk.sign_msg_hash(hash)

    def gossip():
        pass