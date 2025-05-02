from rlp import Serializable, encode, decode
from rlp.sedes import big_endian_int, Binary, binary, CountableList
from eth_keys import keys
from eth_utils import keccak
from trie import HexaryTrie
from copy import deepcopy

from transaction import Transaction, TxSerializable
from state import StateTrie
import json
import blst

class BlockSerializable(Serializable):
    fields = [
        ('parent_hash', Binary.fixed_length(32, allow_empty=False)),
        ('state_root', Binary.fixed_length(32, allow_empty=False)),
        ('transactions_root', Binary.fixed_length(32, allow_empty=False)),
        ('receipts_root', Binary.fixed_length(32, allow_empty=False)),
        ('epoch_number', big_endian_int),
        ('block_number', big_endian_int),
        # BLS signed (epoch_no + domain_randao)
        # We ignore epoch_no to simplify implementation
        # therefore, sign keccak(block_no + domain_randao)
        ('randao_reveal', Binary.fixed_length(96, allow_empty=False)),
        ('beneficiary', Binary.fixed_length(20, allow_empty=False)),
        ('timestamp', big_endian_int),
        ('sig_v', big_endian_int),
        ('sig_r', big_endian_int),
        ('sig_s', big_endian_int),
        ('data', binary),
        ('transactions', CountableList(TxSerializable))
    ]

    def recoverAddress(self):
        signature = keys.Signature(vrs=(self.sig_v, self.sig_r, self.sig_s))
        pk = signature.recover_public_key_from_msg_hash(self.rebuildHash())
        return pk.to_canonical_address()
    
    def rebuildHash(self):
        blockns = BlockNoSig(
            self.parent_hash,
            self.state_root,
            self.transasction_root,
            self.receipts_root,
            self.epoch_nuber,
            self.block_number,
            self.randao_reveal,
            self.beneficiary,
            self.timestamp,
            self.data
        )
        return keccak(encode(blockns))
    
    def calculateTxHash(self) -> bytes:
        hashlist = []
        for tx in self.transactions:
            hashlist.append(tx.hash())
        i = 0
        while (i < len(hashlist)):
            if (i + 1 >= len(hashlist)):
                return hashlist[-1]
            nhash = hashlist[i] + hashlist[i + 1]
            hashlist.append(keccak(nhash))
            i += 2
        return b''
    
    def int_to_minimal_bytes(n: int) -> bytes:
        if n == 0:
            return b'\x00'
        length = (n.bit_length() + 7) // 8
        return n.to_bytes(length, byteorder='big')
    
    def verifyRandao(self, benefBLS: bytes) -> bool:
        randao_constant = 0
        with open('../config/config.json') as f:
            config = json.load(f)
            randao_constant = config['sc_constrants']['domain_randao']
        # Verify file works
        if (randao_constant == 0):
            return False
        # Construct message
        message = self.int_to_minimal_bytes(randao_constant) + self.int_to_minimal_bytes(self.block_number)
        message = keccak(message)
        # Verify signature
        return blst.verify(benefBLS, message, self.randao_reveal)
    
    def verifyBlock(self, state: StateTrie, parentH: bytes, parentBlockNo: int) -> tuple[StateTrie, bool]:
        # Verify block signature
        if (not self.verifySig(self.beneficiary)):
            return (state, False)
        # Get beneficiary Account from state
        benef = state.getAccount(self.beneficiary)
        # Verify Beneficiary's existance
        if (not benef):
            return (state, False)
        # Only a creator can be a consensus node, therefore, they must exist
        if (not benef.isConsensusNode()):
            return (state, False)
        # Only validators can be leaders
        if (not benef.validator_pub_key):
            return (state, False)
        # Verify assigned epoch
        # TODO
        # Verify randao_reveal
        if (not self.verifyRandao(benef.validator_pub_key)):
            return (state, False)
        # Verify TX root
        if (self.transactions_root != self.calculateTxHash()):
            return (state, False)
        # Verify Transactions
        if (not self.verifyTXs(state)):
            return (state, False)
        # Verify parent hash
        if (not self.parent_hash != parentH):
            return (state, False)
        # Verify block number
        if (not self.block_number != parentBlockNo + 1):
            return (state, False)
        # Verify state root validity
        return self.verifyStateAfterExecution(state)


    def verifySig(self, acc: bytes) -> bool:
        return (self.recoverAddress() == acc)
    
    def verifyTXs(self, state: StateTrie) -> bool:
        for tx in self.transactions:
            if (not state.transaction(tx, True, False)):
                return False
        return True
    
    def verifyStateAfterExecution(self, state: StateTrie) -> tuple[StateTrie, bool]:
        '''
        Returns the correct state of the blockchain.
        The validity of the block can be inferred from the boolean value.
        '''
        # 1. deepcopy state to a tmp variable
        tmp = StateTrie()
        tmp.db = deepcopy(state.db)
        tmp.iddb = deepcopy(state.iddb)
        tmp.state_trie = HexaryTrie(tmp.db, root_hash=state.getRootHash())
        tmp.id_trie = HexaryTrie(tmp.iddb, root_hash=state.id_trie.root_hash)
        # 2. On the tmp state, noverify, execute all txs
        for tx in self.transactions:
            tmp.transaction(tx, False, True)
        # 3. Verify state roothash
        if (self.state_root != tmp.getRootHash()):
            # 4. IF NONMATCHING ROOTHASH
            #   5. Discard Changes (new final state is orig)
            return (state, False)
        # 4. IF MATCHING ROOTHASH
        #   5. Apply Changes (new final state is tmp)
        return (tmp, True)

class BlockNoSig(Serializable):
    fields = [
        ('parent_hash', Binary.fixed_length(32, allow_empty=False)),
        ('state_root', Binary.fixed_length(32, allow_empty=False)),
        ('transactions_root', Binary.fixed_length(32, allow_empty=False)),
        ('receipts_root', Binary.fixed_length(32, allow_empty=False)),
        ('epoch_number', big_endian_int),
        ('block_number', big_endian_int),
        ('randao_reveal', Binary.fixed_length(96, allow_empty=False)),
        ('beneficiary', Binary.fixed_length(20, allow_empty=False)),
        ('timestamp', big_endian_int),
        #('signature', Binary.fixed_length(65, allow_empty=False)),
        ('data', binary),
        #('transactions', CountableList(Transaction))
    ]

class BlockSig(Serializable):
    fields = [
        ('parent_hash', Binary.fixed_length(32, allow_empty=False)),
        ('state_root', Binary.fixed_length(32, allow_empty=False)),
        ('transactions_root', Binary.fixed_length(32, allow_empty=False)),
        ('receipts_root', Binary.fixed_length(32, allow_empty=False)),
        ('epoch_number', big_endian_int),
        ('block_number', big_endian_int),
        ('randao_reveal', Binary.fixed_length(96, allow_empty=False)),
        ('beneficiary', Binary.fixed_length(20, allow_empty=False)),
        ('timestamp', big_endian_int),
        ('sig_v', big_endian_int),
        ('sig_r', big_endian_int),
        ('sig_s', big_endian_int),
        ('data', binary),
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
        return encode(BlockNoSig(self.parent_hash, self.state_root, self.transactions_root, self.receipts_root, self.block_number, self.beneficiary, self.timestamp, self.data))

    def serializeSig(self):
        return encode(BlockSig(self.parent_hash, self.state_root, self.transactions_root, self.receipts_root, self.block_number, self.beneficiary, self.timestamp, self.signature.to_bytes(), self.data))

    def serialize(self):
        print(self.signature.to_bytes().hex())
        return encode(BlockSerializable(self.parent_hash, self.state_root, self.transactions_root, self.receipts_root, self.block_number, self.beneficiary, self.timestamp, self.signature.to_bytes(), self.data, []))
    
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