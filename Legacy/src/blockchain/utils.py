"""
blockchain/account.py

This module defines utility functions and classes.
It provides a Genesis state creator for initial startup.

Example:
    You can use this as a module:
        from blockchain.utils import chainLog, Genesis

Author: XXXXXXXXXX
Date: 19/05/2025
"""

from blockchain.account import AccSerializable, AffiliateMedia
from blockchain.block import BlockSerializable, BlockNoSig
from blockchain.state import StateTrie
from network.peer import to_int
from eth_utils import keccak
from eth_keys import keys
from os import urandom
from math import log2
import time
import json





def chainLog(logger, nodeId: str, nodeProc: bool | None, fnMethod: str, message: str = ''):
    """
    Logging function.
    """
    if nodeProc is not None:
        np = "NODE" if nodeProc else "BLOCKCHAIN"
    else:
        np = "NONE"
    logger.info(f'[{nodeId}] [{np}] [{fnMethod}]]{": " + message if message else message}')
    #print(f'[{time.time():.7f}] [{nodeId}] [{np}] [{fnMethod}]]{": " + message if message else message}', flush=True)


class Genesis:
    """
    Factory class for the Genesis block and state
    """
    def __init__(self):
        with open('config/config.json') as f:
            self.config = json.load(f)

    def constructGenesisBlock(self) -> BlockSerializable:
        """
        Returns the Genesis block as described in '/src/config/confic.json'
        """
        return BlockSerializable(
            bytes.fromhex(self.config['genesis']['parent_hash']),
            bytes.fromhex(self.config['genesis']['parent_hash']),
            bytes.fromhex(self.config['genesis']['parent_hash']),
            bytes.fromhex(self.config['genesis']['parent_hash']),
            bytes.fromhex(self.config['genesis']['parent_hash']),
            0,
            0,
            b'\x00' * 65,
            bytes.fromhex(self.config['sc_constants']['domain_randao']),
            bytes.fromhex(self.config['genesis']['coinbase']),
            self.config['genesis']['timestamp'],
            0,
            0,
            0,
            b'',
            [],
            []
        )
    
    def getGenesisRandomness(self) -> bytes:
        """
        Returns initial Randao Randomness.
        """
        return bytes.fromhex(self.config['sc_constants']['domain_randao'])

    def getGenesisState(self) -> StateTrie:
        """
        Returns the Genesis state.
        """
        st = StateTrie()
        for a in self.config['genesis']['alloc']:
            st.addAccount(AccSerializable.blank().update(balance=to_int(a['balance'].encode('ascii'))), bytes.fromhex(a['address']))
            acc = st.getAccount(bytes.fromhex(a['address']))
            if a.get('id_hash'):
                acc = acc.update(id_hash=bytes.fromhex(a['id_hash']), vc_zkp=b'\x10'*288)
            if a.get('pub_key'):
                acc = acc.update(validator_pub_key=bytes.fromhex(a['pub_key']))
            if a.get('sc'):
                acc = acc.update(active_sc=a['sc'])
            if a.get('soc_media'):
                acc = acc.update(soc_media=[AffiliateMedia(b'\x01', a['soc_media'].encode('ascii'), b'\x10' * 288)])
                st.addValidator(bytes.fromhex(a['address']), a['sc'])
            st.updateAccount(bytes.fromhex(a['address']), acc)
        return st

    def Eve(self):
        """
        Factory of a default profile.

        DO NOT USE. THIS PROFILE IS NOT IN GENESIS.
        """
        private_key_bytes = keccak('uzumymv'.encode('ascii'))
        sk = keys.PrivateKey(private_key_bytes)
        pk = sk.public_key

        eve = AccSerializable.blank()
        id = keccak('uzumymv'.encode('ascii'))
        eve = eve.update(balance=1000000000000000, id_hash=id, passive_sc=50, active_sc=700, validator_pub_key=pk.to_bytes(), soc_media=[AffiliateMedia(b'\x01', 'Heaven'.encode('ascii'), b'\x00' * 288)])
        eveAddress = pk.to_canonical_address()

        state = StateTrie()
        state.addAccount(eve, eveAddress)
        state.addValidator(eveAddress, 1000)

        return ((sk, pk), eveAddress, eve)

    def rand(self):
        """
        Generate random credentials - (sk, pk).
        """
        private_key_bytes = urandom(32)
        sk = keys.PrivateKey(private_key_bytes)
        pk = sk.public_key
        randAddress = pk.to_canonical_address()

        return ((sk, pk), randAddress)

# PK full: a8465308efd1222a99d2b0e96bfea099f02f7e1000da673b07a5bace76836f071a5418870e184aa7aa7530cc1f2da7c875678c4ac05f1029223b1fddc2793fe0
# Address: 665e032d9166622dd16f4339df9b7a653e57ea9b
# SK: cb3f5373710ac12cf54a3623c98622548246ede6dd4797ab7ee23493c9d7bba9

    def Adam(self):
        """
        Default content creator, required for function.
        """
        private_key_bytes = keccak('hesoyam'.encode('ascii'))
        sk = keys.PrivateKey(private_key_bytes)
        pk = sk.public_key
        

        adam = AccSerializable.blank()
        id = keccak('hesoyam'.encode('ascii'))
        adam = adam.update(balance=1000000000000000, id_hash=id, passive_sc=50, active_sc=1000, validator_pub_key=pk.to_bytes(), soc_media=[AffiliateMedia(b'\x01', 'Life'.encode('ascii'), b'\x00' * 288)])
        adamAddress = pk.to_canonical_address()
        state = StateTrie()
        state.addAccount(adam, adamAddress)
        state.addValidator(adamAddress, 1000)

        with open('config/config.json') as f:
                    config = json.load(f)

        x = config['sc_constants']['domain_randao'].encode('ascii')

        genesis = BlockNoSig(
            keccak('hesoyam'.encode('ascii')),
            state.getRootHash(),
            keccak(b''),
            keccak(b''),
            b'\x00' * 32,
            0,
            0,
            sk.sign_msg_hash(x).to_bytes(),
            urandom(65),
            adamAddress,
            int(time.time()),
            b''
        ).sign(sk.to_bytes()).addTXandAttLists([], [])
        return ((sk, pk), adamAddress, adam, state, genesis)