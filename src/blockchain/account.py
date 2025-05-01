from trie import HexaryTrie
from eth_keys import keys
from eth_utils import keccak
from rlp import encode, decode, Serializable
from rlp.sedes import big_endian_int, Binary, binary, CountableList
import json
import time

from transaction import TxSerializable, TxSerializableNoSig, TxMetaNoSig, TxMeta

class AffilateMedia(Serializable):
    fields = [
        ('add_flag', Binary.fixed_length(1, allow_empty=False)),
        ('media', binary),
        ('zkp_ownership', Binary.fixed_length(288, allow_empty=False))
    ]

class Endorsement(Serializable):
    fields = [
        ('address', Binary.fixed_length(20, allow_empty=False)),
        ('value', big_endian_int)
    ]

class RegisterData(Serializable):
    fields = [
        ('id_hash', Binary.fixed_length(32, allow_empty=True)),
        ('vc_zkp', Binary.fixed_length(288, allow_empty=True))
    ]

class AccSerializable(Serializable):
    fields = [
        ('nonce', big_endian_int), # no of txs sent
        ('forwarder', big_endian_int),
        ('balance', big_endian_int),
        ('id_hash', Binary.fixed_length(32, allow_empty=True)),
        ('vc_zkp', Binary.fixed_length(288, allow_empty=True)),
        ('passive_sc', big_endian_int),
        ('active_sc', big_endian_int),
        ('effective_sc', big_endian_int),
        ('endorsed', CountableList(Endorsement)),
        ('endorsed_by', CountableList(Endorsement)),
        ('soc_media', CountableList(AffilateMedia))
    ]


class Account():
    def __init__(self, non, bal):
        self.nonce = non
        self.forwarder = 0 # nonce for metaTX
        self.balance = bal
        self.id_hash = b''
        self.vc_zkp = b''
        self.passive_sc = 0
        self.active_sc = 0
        self.effective_sc = 0
        self.endorsed = []
        self.affiliateMedia = {}
    
    def register(self, id, zkp):
        pass
    
    def endorse(self, benef: bytes, amount: int):
        if (not self.id_hash):
            raise ValueError('Can\'t endorse without a valid identity.')
    
        if (self.passive_sc < amount):
            raise ValueError('Can\'t endorse, not enough social capital.')
    
        self.passive_sc -= amount
        self.endorsed.append((benef, amount))


    def serialize(self):
        return encode(AccSerializable(self.nonce, self.balance, self.id_hash, self.vc_zkp, self.passive_sc, self.active_sc, self.effective_sc))
    

class StateTrie:
    def __init__(self):
        self.db = {}
        self.state_trie = HexaryTrie(self.db)
        self.iddb = {}
        self.id_trie = HexaryTrie(self.iddb)

    def transaction(self, tx: TxSerializable) -> bool:
        type = tx.type
        if type == 0:
            # Normal transaction
            return self.transfer(tx)
        elif type == 1:
            # SCap reassignment
            return self.reassign(tx)
        elif type == 2:
            # Registration
            return self.register(tx)
        else:
            print('Wrong transaction type.')
            return False

    def addAccount(self, acc: Account, address: bytes):
        acc_serialized = encode(acc)
        key = keccak(address)
        self.state_trie[key] = acc_serialized

    def getAccount(self, address: bytes):
        key = keccak(address)
        return decode(self.state_trie[key], AccSerializable)

    def updateAccount(self, address: bytes, acc: AccSerializable):
        key = keccak(address)
        self.state_trie[key] = encode(acc)

    def accountExists(self, acc: bytes) -> bool:
        key = keccak(acc)
        return key in self.state_trie

    def removeAccount(self, address: bytes):
        key = keccak(address)
        del self.state_trie[key]

    def getRootHash(self):
        return self.state_trie.root_hash
    
    def recoverAddress(self, hash, v, r, s) -> bool:
        signature = keys.Signature(vrs=(v, r, s))
        pk = signature.recover_public_key_from_msg_hash(hash)
        return pk.to_canonical_address()
    
    def rebuildHash(tx: TxSerializable):
        txns = TxSerializableNoSig(
            tx.type,
            tx.fee,
            tx.sender,
            tx.to,
            tx.value,
            tx.timestamp,
            tx.data
        )
        return keccak(encode(txns))
    
    def verifyTX(self, tx: TxSerializable, accSender) -> bool:
        # Verify TX signature
        h = self.rebuildHash(tx)
        if (self.recoverAddress(h, tx.v, tx.r, tx.s) != tx.sender):
            return False
        # Check account existance
        if (tx.type == 0):
            if (not self.accountExists(tx.sender) or not self.accountExists(tx.to)):
                return False
        else:
            if (not self.accountExists(tx.sender)):
                return False
        # Check transaction & user nonces
        if (accSender.nonce != tx.nonce):
            return False
        return True

    
    def transfer(self, tx: TxSerializable) -> bool:
        # Verification (of all txs in a block) should be done before application
        # That would, thus, not require the implementation of operation reverts & tabkeeping
        if (not self.verifyTransfer(tx)):
            return False
        accSender = self.getAccount(tx.sender)
        accBenef = self.getAccount(tx.to)
        # Initiate swap
        updatedSender = AccSerializable(
            accSender.nonce + 1,
            accSender.forwarder,
            accSender.balance - tx.value - tx.fee,
            accSender.id_hash,
            accSender.vc_zkp,
            accSender.passive_sc,
            accSender.active_sc,
            accSender.effective_sc,
            accSender.soc_media
        )
        updatedRec = AccSerializable(
            accBenef.nonce,
            accBenef.forwarder,
            accBenef.balance + tx.value,
            accBenef.id_hash,
            accBenef.vc_zkp,
            accBenef.passive_sc,
            accBenef.active_sc,
            accBenef.effective_sc,
            accBenef.soc_media
        )
        # Record changes
        self.updateAccount(tx.sender, updatedSender)
        self.updateAccount(tx.to, updatedRec)
        return True

    def verifyMetaTX(self, meta: TxMeta) -> bool:
        # Verify signature
        # Rebuild hash
        metxns = TxMetaNoSig(
            meta.forwarder,
            meta.sender,
            meta.to,
            meta.fnCall,
            meta.args
        )
        h = keccak(encode(metxns))
        # Recover sender
        if (self.recoverAddress(h, meta.v, meta.r, meta.s) != meta.sender):
            return False
        # Check sender account existance
        if (not self.accountExists(meta.sender) or not self.accountExists(meta.to)):
            return False
        metaSender = self.getAccount(meta.sender)
        # Verify sender is registered
        if (metaSender.id_hash == b''):
            return False
        # Check timestamp
        if (meta.timestamp > int(time.time)):
            return False
        # Check meta sender forwarder nonce
        if (metaSender.forwarder != meta.forwarder):
            return False
        # Check MetaTX sender sc
        if (metaSender.passive_sc < meta.sc):
            return False
        return True
    
    def verifyTransfer(self, tx: TxSerializable) -> bool:
        accSender = self.getAccount(tx.sender)
        # Verify TX common
        if (not self.verifyTX(tx, accSender)):
            return False
        # Check sender funds
        if (accSender.balance < tx.value + tx.fee):
            return False
        # Check timestamp
        if (tx.timestamp > int(time.time)):
            return False
        return True
    
    def verifyReassign(self, tx: TxSerializable) -> bool:
        accSender = self.getAccount(tx.sender)
        # Verify TX common
        if (not self.verifyTX(tx, accSender)):
            return False
        # Verify base MetaTX
        # Reassign type TXs contain MetaTXs in data field
        metaTx = decode(tx.data, TxMeta)
        if (not self.verifyMetaTX(metaTx)):
            return False
        # If assigning 0 sc, DoS possibility
        if (metaTx.sc == 0):
            False
        # Compare xt and metaTx timestamps
        if (metaTx.timestamp > tx.timestamp):
            return False
        # If sc is negative, check for previous assignment
        if (metaTx.sc < 0):
            for end in accSender.endorsed_by:
                if end.address == metaTx.sender:
                    if (end.value >= metaTx.sc):
                        return True
                    return False
            return False
        return True
    
    def findAddrInEndorsementList(self, elist: list[Endorsement], addr: binary) -> int:
        i = 0
        for e in elist:
            if (e.address == addr):
                return i
            i+=1
        return -1 

    def reassign(self, tx: TxSerializable) -> bool:
        # Verification (of all txs in a block) should be done before application
        # That would, thus, not require the implementation of operation reverts & tabkeeping
        if not self.verifyReassign():
            return False
        scBeneficiary = self.getAccount(tx.sender)
        metaTx = decode(tx.data, TxMeta)
        scSender = self.getAccount(metaTx.sender)
        # --- Initiate changes ---
        # Negative metaTx.sc means withdrawal of SC
        endorsedList = list(scSender.endorsed)
        idx = self.findAddrInEndorsementList(endorsedList, tx.sender)
        if metaTx.sc < 0:
            # if already endorsed, decrease the value associated with that address
            if idx < 0:
                return False
            else:
                item = endorsedList[idx]
                if item.value < abs(metaTx.sc):
                    return False
                else:
                    endorsedList[idx] = Endorsement(item.address, item.value + metaTx.sc)
        elif metaTx.sc > 0:
            # If already endorsed, increase the value associated with that address
            if idx < 0:
                endorsedList = endorsedList + [Endorsement(tx.sender, metaTx.sc)]
            else:
                item = endorsedList[idx]
                endorsedList[idx] = Endorsement(item.address, item.value + metaTx.sc)
        else:
            return
        # Move sc from metaTX sender, register endorsement
        scSenderUpdate = AccSerializable(
            scSender.nonce,
            scSender.forwarder + 1,
            scSender.balance,
            scSender.id_hash,
            scSender.vc_zkp,
            scSender.passive_sc - metaTx.sc,
            scSender.active_sc,
            scSender.effective_sc,
            endorsedList,
            scSender.endorsed_by,
            scSender.soc_media
        )
        # Add sc to receiver, register endorsement
        endorsed_byList = list(scSender.endorsed_by)
        idx = self.findAddrInEndorsementList(endorsed_byList, metaTx.sender)
        if metaTx.sc < 0:
            # if already endorsed, decrease the value associated with that address
            if idx < 0:
                return False
            else:
                item = endorsed_byList[idx]
                if item.value < abs(metaTx.sc):
                    return False
                else:
                    endorsedList[idx] = Endorsement(item.address, item.value + metaTx.sc)
        elif metaTx.sc > 0:
            # If already endorsed, increase the value associated with that address
            if idx < 0:
                endorsed_byList = endorsed_byList + [Endorsement(metaTx.sender, metaTx.sc)]
            else:
                item = endorsed_byList[idx]
                endorsed_byList[idx] = Endorsement(item.address, item.value + metaTx.sc)
        else:
            return
        scBeneficiaryUpdate = AccSerializable(
            scSender.nonce + 1,
            scSender.forwarder,
            scSender.balance,
            scSender.id_hash,
            scSender.vc_zkp,
            scSender.passive_sc,
            scSender.active_sc + metaTx.sc,
            scSender.effective_sc,
            scBeneficiary.endorsed,
            endorsed_byList,
            scSender.soc_media
        )
        # Register changes
        self.updateAccount(metaTx.sender, scSenderUpdate)
        self.updateAccount(tx.sender, scBeneficiaryUpdate)
        return True
    
    def verifyRegister(self, tx:TxSerializable) -> bool:
        # Verify common TX elements
        if (not self.verifyTX(tx)):
            return False
        # Verify data field
        d = decode(tx.data, RegisterData)
        if d.id_hash == b'':
            return False
        if d.vc_zkp == b'':
            return False
        # Verify ZKP
        # TODO
        valid = True
        # TODO
        if (not valid):
            return False
        return True

    def register(self, tx: TxSerializable) -> bool:
        # Verification (of all txs in a block) should be done before application
        # That would, thus, not require the implementation of operation reverts & tabkeeping
        if (not self.verifyRegister(tx)):
            return False
        # Parse Register Data
        regd = decode(tx.data, RegisterData)
        # Load default passive_sc value
        passSc = 0
        with open('../config/config.json') as f:
            config = json.load(f)
            passSc = config['sc_constrants']['def_passive_sc']
        if passSc == 0:
            return False
        # Initiate change
        accSender = self.getAccount(tx.sender)
        accUpdated = AccSerializable(
            accSender.nonce + 1,
            accSender.forwarder,
            accSender.balance,
            regd.id_hash,
            regd.vc_zkp,
            passSc,
            0,
            0,
            [],
            [],
            [],
        )
        self.updateAccount(tx.sender, accUpdated)
        return True
    
    def affiliate(tx: TxSerializable) -> bool:
        return True