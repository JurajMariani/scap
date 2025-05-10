from blockchain.account import AccSerializable
from blockchain.block import BlockSerializable
from blockchain.state import StateTrie
from math import log2
import json


class Genesis:

    def __init__(self):
        with open('config/config.json') as f:
            self.config = json.load(f)

    def constructGenesisBlock(self) -> BlockSerializable:
        domain_r: int = self.config['sc_constants']['domain_randao']
        return BlockSerializable(
            self.config['genesis']['parent_hash'],
            self.config['genesis']['parent_hash'],
            self.config['genesis']['parent_hash'],
            self.config['genesis']['parent_hash'],
            self.config['genesis']['parent_hash'],
            0,
            0,
            b'\x00' * 65,
            domain_r.to_bytes(int(log2(domain_r)), byteorder='big'),
            self.config['genesis']['coinbase'],
            self.config['genesis']['timastamp'],
            b'',
            0,
            0,
            0
        )

    def getGenesisState(self) -> StateTrie:
        st = StateTrie()
        for a in self.config['genesis']['alloc']:
            
            st.addAccount(AccSerializable.blank().update(balance=a['balance']), a['account'])