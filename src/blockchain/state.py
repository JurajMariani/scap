from __future__ import annotations
from trie import HexaryTrie
from eth_utils import keccak
import asyncio
import json
import time

from rlp import decode
from blockchain.zkp_manager import verify
from blockchain.transaction import TxSerializable, TxMeta
from blockchain.account import AccSerializable, Endorsement, RegisterData, AffiliateMedia, AffiliateMediaList

# TODO
# A method of AccSerializable has been added - `isConsensusNode()` and `isVerified()`
# and may be useful to shorten this code
# TODO
class StateTrie:
    def __init__(self):
        self.db = {}
        self.state_trie = HexaryTrie(self.db)
        self.valAddrList: dict[bytes, int] = {}
        # TODO
        # For the time being, this remains unused
        # Can be used in the future for optimisation
        # TODO
        self.nodeID = ''
        self.iddb = {}
        self.id_trie = HexaryTrie(self.iddb)

    
    def clone(self) -> StateTrie:
        st = StateTrie()
        st.db = self.db.copy()
        st.valAddrList = self.valAddrList.copy()
        st.iddb = self.iddb.copy()
        st.state_trie = HexaryTrie(st.db, self.getRootHash())
        st.id_trie = HexaryTrie(st.iddb, self.id_trie.root_hash)
        st.nodeID = self.nodeID
        return st

    def transaction(self, tx: TxSerializable, verify: bool = True, execute: bool = True) -> bool:
        type = tx.type
        if type == 0:
            # Normal transaction
            return self.transfer(tx, verify, execute)
        elif type == 1:
            # SCap reassignment
            return self.reassign(tx, verify, execute)
        elif type == 2:
            # Registration
            return self.register(tx, verify, execute)
        elif type == 3:
            # Register affiliate social media
            return self.affiliate(tx, verify, execute)
        else:
            print('Wrong transaction type.')
            return False

    def addAccount(self, acc: AccSerializable, address: bytes) -> None:
        key = keccak(address)
        self.state_trie[key] = acc.sserialize()

    def getAccount(self, address: bytes) -> AccSerializable | None:
        key = keccak(address)
        try:
            acc = self.state_trie[key]
            if not acc:
                return None
            return AccSerializable.ddeserialize(acc)
        except Exception as e:
            print(e, "Looking for", address)
            return None

    def updateAccount(self, address: bytes, acc: AccSerializable) -> None:
        key = keccak(address)
        self.state_trie[key] = acc.sserialize()

    def accountExists(self, acc: bytes) -> bool:
        key = keccak(acc)
        return key in self.state_trie

    def removeAccount(self, address: bytes) -> None:
        key = keccak(address)
        del self.state_trie[key]

    def getValidator(self, address: bytes) -> bool:
        if isinstance(address, str):
            raise TypeError("addValidator accepts bytes")
        return address in self.valAddrList.keys()

    def addValidator(self, address: bytes, sc: int) -> None:
        if isinstance(address, str):
            raise TypeError("addValidator accepts bytes")
        self.valAddrList[address] = sc

    def removeValidator(self, address: bytes) -> None:
        del self.valAddrList[address]

    def getValidators(self) -> dict[bytes, int]:
        return self.valAddrList
    
    def getValidatorLen(self) -> int:
        return len(self.valAddrList)
    
    def getValidatorSupermajorityLenFromNum(self, num: int) -> int:
        return ((num // 3) * 2)
    
    def getValidatorSupermajorityLen(self) -> int:
        return (self.getValidatorLen() // 3) * 2
    
    def getValidatorSupermajorityLenInverted(self) -> int:
        return self.getValidatorLen() - self.getValidatorSupermajorityLen()

    def getRootHash(self):
        return self.state_trie.root_hash
    
    def coinbase(self, beneficiary: bytes, value: int) -> bool:
        benef = self.getAccount(beneficiary)
        if not benef:
            return False
        benefEnriched = benef.update(balance=(benef.balance + value))
        self.updateAccount(beneficiary, benefEnriched)
        return True
    
    def verifyTX(self, tx: TxSerializable, accSender, execute: bool) -> bool:
        # Verify TX signature
        if not tx.verifySig():
            return False
        # Check account existance
        if (not tx.type == 2):
            if (not self.accountExists(tx.sender)):
                return False
            # Transfer type TX can create beneficiary account
            if (tx.type == 0):
                if (not self.accountExists(tx.to)):
                    # Create beneficiary account
                    self.addAccount(AccSerializable.blank(), tx.to)
        else:
            # Register type TX can crate SENDER account
            if (not self.getAccount(tx.sender)):
                # Create blank sender
                self.addAccount(AccSerializable.blank(), tx.sender)
        # Check transaction & user nonces
        if not execute:
            if (tx.nonce < accSender.nonce):
                return False
        else:
            if (accSender.nonce != tx.nonce):
                #print("Not EQUAL, should exit")
                return False
        # Check sender has enough funds to send TX (to pay the fee)
        if (accSender.balance < tx.fee):
            return False
        # Check values are not negative
        if (tx.fee < 0 or tx.value < 0):
            return False
        # Check timestamp
        if (tx.timestamp > int(time.time())):
            return False
        return True

    
    def transfer(self, tx: TxSerializable, verify: bool, execute: bool) -> bool:
        # Verification (of all txs in a block) should be done before application
        # That would, thus, not require the implementation of operation reverts & tabkeeping
        if (verify):
            if (not self.verifyTransfer(tx, execute)):
                return False
        if (not execute):
            return True
        accSender = self.getAccount(tx.sender)
        accBenef = self.getAccount(tx.to)
        # Check NONCE
        if accSender.nonce != tx.nonce:
            # print("NONCE DOES NOT MATCH!", accSender.nonce, tx.nonce)
            return False
        # Initiate swap
        updatedSender = accSender.update(nonce=True, balance=(accSender.balance - tx.value - tx.fee))
        updatedRec = accBenef.update(balance=(accBenef.balance + tx.value))
        # Record changes
        self.updateAccount(tx.sender, updatedSender)
        self.updateAccount(tx.to, updatedRec)
        return True

    def verifyMetaTX(self, meta: TxMeta) -> bool:
        # Verify signature
        if not meta.verifySig():
            return False
        # Check sender account existance
        if (not self.accountExists(meta.sender) or not self.accountExists(meta.to)):
            return False
        metaSender = self.getAccount(meta.sender)
        # Verify sender is registered
        if (not metaSender.isVerified()):
            return False
        # Check timestamp
        if (meta.timestamp > int(time.time())):
            return False
        # Check meta sender forwarder nonce
        if (metaSender.forwarder != meta.forwarder):
            return False
        # Check MetaTX sender sc
        if (metaSender.passive_sc < meta.sc):
            return False
        return True
    
    def verifyTransfer(self, tx: TxSerializable, execute: bool) -> bool:
        accSender = self.getAccount(tx.sender)
        # Verify TX common
        if (not self.verifyTX(tx, accSender, execute)):
            return False
        # Check sender funds
        if (accSender.balance < tx.value + tx.fee):
            return False
        return True
    
    def verifyReassign(self, tx: TxSerializable, execute: bool) -> bool:
        accSender = self.getAccount(tx.sender)
        # Verify TX common
        if (not self.verifyTX(tx, accSender, execute)):
            return False
        # Verify base MetaTX
        # Reassign type TXs contain MetaTXs in data field
        metaTx = TxMeta.ddeserialize(tx.data)
        if (not self.verifyMetaTX(metaTx)):
            return False
        # Verify receiver is a verifier
        if (not accSender.isConsensusNode()):
            return False
        # If assigning 0 sc, DoS possibility
        if (metaTx.sc == 0):
            False
        # Compare tx and metaTx timestamps
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
    
    def findAddrInEndorsementList(self, elist: list[Endorsement], addr: bytes) -> int:
        i = 0
        for e in elist:
            if (e.address == addr):
                return i
            i+=1
        return -1

    def reassign(self, tx: TxSerializable, verify, execute) -> bool:
        # Verification (of all txs in a block) should be done before application
        # That would, thus, not require the implementation of operation reverts & tabkeeping
        if verify:
            if not self.verifyReassign(tx, execute):
                return False
        if (not execute):
            return True
        scBeneficiary = self.getAccount(tx.sender)
        # Verify TX nonce
        if scBeneficiary.nonce != tx.nonce:
            return False
        # Extract meta tx
        metaTx = TxMeta.ddeserialize(tx.data)
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
            return False
        # Move sc from metaTX sender, register endorsement
        scSenderUpdate = scSender.update(forwarder=True, passive_sc=(scSender.passive_sc - metaTx.sc), endorsed=endorsedList)
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
            return False
        
        scBeneficiaryUpdate = scBeneficiary.update(nonce=True, active_sc=(scBeneficiary.active_sc + metaTx.sc), endorsed_by=endorsed_byList, balance=(scSender.balance - tx.fee))
        # Register changes
        self.updateAccount(metaTx.sender, scSenderUpdate)
        self.updateAccount(tx.sender, scBeneficiaryUpdate)
        # Add SC to verifier
        # Called add but functions similarly to update
        self.addValidator(tx.sender, scBeneficiaryUpdate.active_sc)
        return True
    
    def verifyRegister(self, tx: TxSerializable, execute: bool) -> bool:
        sender = self.getAccount(tx.sender)
        # Verify common TX elements
        if (not self.verifyTX(tx, sender, execute)):
            return False
        # Verify data field
        d = decode(tx.data, RegisterData)
        if d.id_hash == b'':
            return False
        if d.vc_zkp == b'':
            return False
        # Verify ZKP
        valid = verify(d.vc_zkp, self.nodeID + str(int(time.time())))
        if (not valid):
            # print('INVALID ZKPPPPPPPPPPPPP!', flush=True)
            return False
        return True

    def register(self, tx: TxSerializable, verify, execute) -> bool:
        # Verification (of all txs in a block) should be done before application
        # That would, thus, not require the implementation of operation reverts & tabkeeping
        if verify:
            if (not self.verifyRegister(tx, execute)):
                return False
        if (not execute):
            return True
        # Parse Register Data
        regd = decode(tx.data, RegisterData)
        # Load default passive_sc value
        passSc = 0
        with open('config/config.json') as f:
            config = json.load(f)
            passSc = config['sc_constants']['def_passive_sc']
        if passSc == 0:
            return False
        # Initiate change
        accSender = self.getAccount(tx.sender)
        # Check TX nonce
        if accSender.nonce != tx.nonce:
            return False
        accUpdated = accSender.update(nonce=True, balance=(accSender.balance - tx.fee), id_hash=regd.id_hash, vc_zkp=regd.vc_zkp, passive_sc=passSc)
        self.updateAccount(tx.sender, accUpdated)
        return True
    
    def verifyAffiliate(self, tx: TxSerializable, execute: bool) -> bool:
        acc = self.getAccount(tx.sender)
        # Verify common TX elements
        if (not self.verifyTX(tx, acc, execute)):
            return False
        # Verify data field
        d = decode(tx.data, AffiliateMediaList)
        if not d.media:
            return False
        # Verify validator_pub_key
        # if already present in account
        if (acc.validator_pub_key):
            if (acc.validator_pub_key != d.validator_pub_key):
                if acc.validator_pub_key == b'\x00' * 64:
                    return True
                return False
        return True
    
    def findMediaInAffiliateList(self, alist: list[AffiliateMedia], media: bytes) -> int:
        i = 0
        for item in alist:
            if item.media == media:
                return i
            i+=1
        return -1
    
    def affiliate(self, tx: TxSerializable, verify, execute) -> bool:
        # Verification (of all txs in a block) should be done before application
        # That would, thus, not require the implementation of operation reverts & tabkeeping
        if verify:
            if (not self.verifyAffiliate(tx, execute)):
                return False
        if (not execute):
            return True
        # Recover AffiliateMediaList
        affMediaList = decode(tx.data, AffiliateMediaList)
        affList = list(affMediaList.media)
        accSender = self.getAccount(tx.sender)
        socAccs = list(accSender.soc_media)
        
        # Check TX nonce
        if accSender.nonce != tx.nonce:
            return False
        # Recover SocMedia list from sender
        # For each affiliation
        for aff in affList:
            # Check addition flag
            if (aff.add_flag == b'\x01'):
                # Check for duplicates
                if (self.findMediaInAffiliateList(socAccs, aff.media) >= 0):
                    # Duplicate found
                    return False
                else:
                    # No duplicates
                    # Verify ZKP of ownership
                    # TODO
                    # ZKP Verificatin for soc media ownership is currently unsupported
                    # TODO
                    # ADD
                    socAccs.append(aff)
            else:
                # Remove media
                # Check SM existance
                idx = self.findMediaInAffiliateList(socAccs, aff.media)
                if (idx < 0):
                    # Can't remove nonexistent affiliation
                    return False
                else:
                    del socAccs[idx]
        # Initiate changes
        accSenderUpdated = accSender.update(nonce=True, balance=(accSender.balance - tx.fee), validator_pub_key=affMediaList.validator_pub_key, soc_media=socAccs)
        # Update Account
        self.updateAccount(tx.sender, accSenderUpdated)
        # Register account as a validator
        if (len(socAccs)):
            if (not self.getValidator(tx.sender)):
                self.addValidator(tx.sender, accSender.active_sc)
        else:
            if self.getValidator(tx.sender):
                self.removeValidator(tx.sender)
        return True