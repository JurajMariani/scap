from __future__ import annotations
from rlp import Serializable, encode, decode
from rlp.sedes import big_endian_int, Binary, binary, CountableList
from eth_keys import keys
from eth_utils import keccak
from trie import HexaryTrie
from copy import deepcopy

from blockchain.transaction import Transaction, TxSerializable
from blockchain.state import StateTrie
import json

class AttestationNoSig(Serializable):
    fields = [
        ('sender', Binary.fixed_length(20, allow_empty=False)),
        ('block_hash', Binary.fixed_length(32, allow_empty=False)),
        ('verdict', Binary.fixed_length(1, allow_empty=False))
    ]

    def hash(self) -> bytes:
        return keccak(encode(self))
    
    def sign(self, privK: bytes) -> Attestation:
        sk = keys.PrivateKey(privK)
        sig = sk.sign_msg_hash(self.hash())
        return Attestation(
            self.sender,
            self.block_hash,
            self.verdict,
            sig.v,
            sig.r,
            sig.s
        )

class Attestation(Serializable):
    fields = [
        ('sender', Binary.fixed_length(20, allow_empty=False)),
        ('block_hash', Binary.fixed_length(32, allow_empty=False)),
        ('verdict', Binary.fixed_length(1, allow_empty=False)),
        ('v', big_endian_int),
        ('r', big_endian_int),
        ('s', big_endian_int)
    ]

    def hash(self) -> bytes:
        atns = AttestationNoSig(
            self.sender,
            self.block_hash,
            self.verdict
        )
        return atns.hash()

    def recoverAddress(self) -> bytes:
        signature = keys.Signature(vrs=(self.v, self.r, self.s))
        pk = signature.recover_public_key_from_msg_hash(self.hash())
        return pk.to_canonical_address()
    
    def verifySig(self) -> bool:
        return self.recoverAddress() == self.sender
    
    def sserialize(self) -> bytes:
        return encode(self)
    
    def getVerdict(self) -> bool:
        return self.verdict == b'\x01'

    @classmethod
    def ddeserialize(cls, att) -> Attestation:
        return decode(att, Attestation)
    

class BlockNoSig(Serializable):
    fields = [
        ('parent_hash', Binary.fixed_length(32, allow_empty=False)),
        ('state_root', Binary.fixed_length(32, allow_empty=False)),
        ('transactions_root', Binary.fixed_length(32, allow_empty=False)),
        ('attestations_root', Binary.fixed_length(32, allow_empty=False)),
        ('receipts_root', Binary.fixed_length(32, allow_empty=False)),
        ('epoch_number', big_endian_int),
        ('block_number', big_endian_int),
        ('randao_reveal', Binary.fixed_length(65, allow_empty=False)),
        ('randao_seed', binary),#Binary.fixed_length(65, allow_empty=False)),
        ('beneficiary', Binary.fixed_length(20, allow_empty=False)),
        ('timestamp', big_endian_int),
        ('data', binary)
    ]

    def hash(self) -> bytes:
        return keccak(encode(self))
    
    def sign(self, privK: bytes) -> BlockSig:
        try:
            sk = keys.PrivateKey(privK)
            sig = sk.sign_msg_hash(self.hash())
            return BlockSig(
                self.parent_hash,
                self.state_root,
                self.transactions_root,
                self.attestations_root,
                self.receipts_root,
                self.epoch_number,
                self.block_number,
                self.randao_reveal,
                self.randao_seed,
                self.beneficiary,
                self.timestamp,
                sig.v,
                sig.r,
                sig.s,
                self.data
            )
        except Exception as e:
            print("Exception", e)
        return None

class BlockSig(Serializable):
    fields = [
        ('parent_hash', Binary.fixed_length(32, allow_empty=False)),
        ('state_root', Binary.fixed_length(32, allow_empty=False)),
        ('transactions_root', Binary.fixed_length(32, allow_empty=False)),
        ('attestations_root', Binary.fixed_length(32, allow_empty=False)),
        ('receipts_root', Binary.fixed_length(32, allow_empty=False)),
        ('epoch_number', big_endian_int),
        ('block_number', big_endian_int),
        ('randao_reveal', Binary.fixed_length(65, allow_empty=False)),
        ('randao_seed', binary),#Binary.fixed_length(65, allow_empty=False)),
        ('beneficiary', Binary.fixed_length(20, allow_empty=False)),
        ('timestamp', big_endian_int),
        ('sig_v', big_endian_int),
        ('sig_r', big_endian_int),
        ('sig_s', big_endian_int),
        ('data', binary)
    ]

    def getNoSig(self) -> BlockNoSig:
        return BlockNoSig(
            self.parent_hash,
            self.state_root,
            self.transactions_root,
            self.attestations_root,
            self.receipts_root,
            self.epoch_number,
            self.block_number,
            self.randao_reveal,
            self.randao_seed,
            self.beneficiary,
            self.timestamp,
            self.data
        )

    def hash(self) -> bytes:
        return self.getNoSig().hash()

    def recoverAddress(self):
        signature = keys.Signature(vrs=(self.sig_v, self.sig_r, self.sig_s))
        pk = signature.recover_public_key_from_msg_hash(self.hash())
        return pk.to_canonical_address()

    def verifySig(self) -> bool:
        return self.recoverAddress() == self.beneficiary
    
    def addTXandAttLists(self, txs: list[TxSerializable], atts: list[Attestation]) -> BlockSerializable:
        return BlockSerializable(
            self.parent_hash,
            self.state_root,
            self.transactions_root,
            self.attestations_root,
            self.receipts_root,
            self.epoch_number,
            self.block_number,
            self.randao_reveal,
            self.randao_seed,
            self.beneficiary,
            self.timestamp,
            self.sig_v,
            self.sig_r,
            self.sig_s,
            self.data,
            txs,
            atts
        )
    

class BlockSerializable(Serializable):
    fields = [
        ('parent_hash', Binary.fixed_length(32, allow_empty=False)),
        ('state_root', Binary.fixed_length(32, allow_empty=False)),
        ('transactions_root', Binary.fixed_length(32, allow_empty=False)),
        ('attestations_root', Binary.fixed_length(32, allow_empty=False)),
        ('receipts_root', Binary.fixed_length(32, allow_empty=False)),
        ('epoch_number', big_endian_int),
        ('block_number', big_endian_int),
        # BLS signed (epoch_no + domain_randao)
        # We ignore epoch_no to simplify implementation
        # therefore, sign keccak(block_no + domain_randao)
        ('randao_reveal', Binary.fixed_length(65, allow_empty=False)),
        ('randao_seed', binary),#Binary.fixed_length(65, allow_empty=False)),
        ('beneficiary', Binary.fixed_length(20, allow_empty=False)),
        ('timestamp', big_endian_int),
        ('sig_v', big_endian_int),
        ('sig_r', big_endian_int),
        ('sig_s', big_endian_int),
        ('data', binary),
        ('transactions', CountableList(TxSerializable)),
        ('attestations', CountableList(Attestation))
    ]

    def recoverAddress(self):
        signature = keys.Signature(vrs=(self.sig_v, self.sig_r, self.sig_s))
        pk = signature.recover_public_key_from_msg_hash(self.rebuildHash())
        return pk.to_canonical_address()
    
    def getBlockSig(self) -> BlockSig:
        return BlockSig(
            self.parent_hash,
            self.state_root,
            self.transactions_root,
            self.attestations_root,
            self.receipts_root,
            self.epoch_number,
            self.block_number,
            self.randao_reveal,
            self.randao_seed,
            self.beneficiary,
            self.timestamp,
            self.sig_v,
            self.sig_r,
            self.sig_s,
            self.data
        )

    def rebuildHash(self):
        return self.getBlockSig().getNoSig().hash()
    
    @classmethod
    def calculateListHash(cls, llist: list) -> bytes:
        hashlist = []
        for tx in llist:
            hashlist.append(tx.hash())
        i = 0
        while (i < len(hashlist)):
            if (i + 1 >= len(hashlist)):
                return hashlist[-1]
            nhash = hashlist[i] + hashlist[i + 1]
            hashlist.append(keccak(nhash))
            i += 2
        return keccak(b'')
    
    @classmethod
    def int_to_minimal_bytes(cls, n: int) -> bytes:
        if n == 0:
            return b'\x00'
        length = (n.bit_length() + 7) // 8
        return n.to_bytes(length, byteorder='big')
    
    def verifyRandao(self, benefBLS: bytes) -> bool:
        randao_constant = 0
        with open('config/config.json') as f:
            config = json.load(f)
            randao_constant = config['sc_constants']['domain_randao']
        # Verify file works
        if (randao_constant == 0):
            return False
        # Construct message
        message = bytes.fromhex(randao_constant) + self.int_to_minimal_bytes(self.block_number)
        message = keccak(message)
        signature = keys.Signature(self.randao_reveal)
        pk = keys.PublicKey(benefBLS)
        # Verify signature
        return signature.verify_msg_hash(message, pk)
    
    def verifyBlock(self, state: StateTrie, parentH: bytes, parentBlockNo: int, currReward: int, rSeed: bytes) -> tuple[StateTrie, bool]:
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
        # Verify randao randomness seed
        if (rSeed != self.randao_seed):
            return (state, False)
        # Verify randao_reveal
        if (not self.verifyRandao(benef.validator_pub_key)):
            return (state, False)
        # Verify TX root
        if (self.transactions_root != self.calculateListHash(self.transactions)):
            return (state, False)
        # Verify Transactions
        if (not self.verifyTXs(state)):
            return (state, False)
        # Verify parent hash
        if self.parent_hash != parentH:
            return (state, False)
        # Verify block number
        if self.block_number != parentBlockNo + 1:
            return (state, False)
        # Verify prev. block attestations
        if not self.verifyAttestations(state):
            return (state, False)
        # Verify attestation root hash
        if (self.attestations_root != self.calculateListHash(self.attestations)):
            return (state, False)
        # Verify state root validity
        return self.verifyStateAfterExecution(state, currReward)


    def verifySig(self, acc: bytes) -> bool:
        return (self.recoverAddress() == acc)
    
    def verifyTXs(self, state: StateTrie) -> bool:
        for tx in self.transactions:
            if (not state.transaction(tx, True, False)):
                return False
        return True
    
    @classmethod
    def getStateAfterExec(cls, state: StateTrie, txs: list[TxSerializable], benef: bytes, currReward: int) -> tuple[StateTrie, bool]:
        # 1. deepcopy state to a tmp variable
        tmp = StateTrie()
        tmp.db = deepcopy(state.db)
        tmp.iddb = deepcopy(state.iddb)
        tmp.valAddrList = deepcopy(state.valAddrList)
        tmp.state_trie = HexaryTrie(tmp.db, root_hash=state.getRootHash())
        tmp.id_trie = HexaryTrie(tmp.iddb, root_hash=state.id_trie.root_hash)
        # 2. On the tmp state, no-verify, execute all txs
        for tx in txs:
            if not tmp.transaction(tx, False,  True):
                return (state, False)
        # 3. Calculate beneficiary enrichment
        enrichment = 0
        for tx in txs:
            enrichment += tx.fee
        enrichment += currReward
        enrichment = int(enrichment)
        # 4. Enrich beneficiary (reward + fees)
        if not tmp.coinbase(benef, enrichment):
            # print("ERROR")
            return (state, False)
        return (tmp, True)
    
    def getStateAfterExecution(self, state: StateTrie, currReward: int) -> tuple[StateTrie, bool]:
        return BlockSerializable.getStateAfterExec(state, self.transactions, self.beneficiary, currReward)
        
    
    def verifyStateAfterExecution(self, state: StateTrie, currReward: int) -> tuple[StateTrie, bool]:
        '''
        Returns the correct state of the blockchain.
        The validity of the block can be inferred from the boolean value.
        '''
        # 1. - 4. Execute TXs
        try:
            res = self.getStateAfterExecution(state, currReward)
        except Exception as e:
            print(e)
        # In case of incorrect TXs
        if not res[1]:
            return (state, False)
        # 5. Verify state roothash
        # A scenario, in which all TXs are correct and executable,
        #   but root hashes are different
        #   (Leader could have increased their balance)
        if (self.state_root != res[0].getRootHash()):
            #print("States do not equal")
            # 6. IF NONMATCHING ROOTHASH
            #   7. Discard Changes (new final state is orig)
            return (state, False)
        # print("State match")
        # 6. IF MATCHING ROOTHASH
        #   7. Apply Changes (new final state is tmp)
        return (res[0], True)
    
    def verifyAttestations(self, state: StateTrie) -> bool:
        # Verify a supermajority attested
        if (len(self.attestations) < state.getValidatorSupermajorityLen()):
            return False
        positiveVerdicts = 0
        for att in self.attestations:
            # -- Verify attestation validity --
            # Verify sender is in validator list
            if not state.getValidator(att.sender):
                return False
            # Verify block_hash == parent_hash
            if att.block_hash != self.parent_hash:
                return False
            # Count positive verdicts
            if att.getVerdict():
                positiveVerdicts += 1
            # Verify verifier signature
            attns = AttestationNoSig(att.sender, att.block_hash, att.verdict)
            sig = keys.Signature(vrs=(att.v, att.r, att.s))
            pk = sig.recover_public_key_from_msg_hash(attns.hash())
            if pk.to_canonical_address() != att.sender:
                return False
        # Verify positive attestation count
        if positiveVerdicts < state.getValidatorSupermajorityLen():
            return False
        return True
    
    def sserialize(self) -> bytes:
        return encode(self)
    
    @classmethod
    def ddeserialize(cls, bl: bytes) -> BlockSerializable:
        return decode(bl, BlockSerializable)


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

    def sserialize(self):
        return encode(BlockSerializable(self.parent_hash, self.state_root, self.transactions_root, self.receipts_root, self.block_number, self.beneficiary, self.timestamp, self.signature.to_bytes(), self.data, []))
    
    def serializeTxs(self):
        txs = []
        for tx in self.transactions:
            txs.append(tx.sserialize())
        return txs

    def sign(self, pub_key: str):
        self.calculateTxHash()
        b = self.serializeNoSig()
        hash = keccak(b)

        pk = keys.PrivateKey(bytes.fromhex(pub_key))
        self.signature = pk.sign_msg_hash(hash)

    def gossip():
        pass