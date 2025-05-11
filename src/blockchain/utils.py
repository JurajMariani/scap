from blockchain.account import AccSerializable, AffiliateMedia
from blockchain.block import BlockSerializable
from blockchain.state import StateTrie
from node.peer import to_int
from math import log2
import json


class Genesis:

    def __init__(self):
        with open('config/config.json') as f:
            self.config = json.load(f)

    def constructGenesisBlock(self) -> BlockSerializable:
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
        return bytes.fromhex(self.config['sc_constants']['domain_randao'])

    def getGenesisState(self) -> StateTrie:
        st = StateTrie()
        for a in self.config['genesis']['alloc']:
            st.addAccount(AccSerializable.blank().update(balance=to_int(a['balance'].encode('ascii'))), bytes.fromhex(a['address']))
            acc = st.getAccount(bytes.fromhex(a['address']))
            if a.get('id_hash'):
                acc = acc.update(id_hash=bytes.fromhex(a['id_hash']))
            if a.get('pub_key'):
                acc = acc.update(validator_pub_key=bytes.fromhex(a['pub_key']))
            if a.get('sc'):
                acc = acc.update(active_sc=a['sc'])
            if a.get('soc_media'):
                acc = acc.update(soc_media=[AffiliateMedia(b'\x01', a['soc_media'].encode('ascii'), b'\x00' * 288)])
                st.addValidator(bytes.fromhex(a['address']), a['sc'])
            st.updateAccount(bytes.fromhex(a['address']), acc)
        return st
