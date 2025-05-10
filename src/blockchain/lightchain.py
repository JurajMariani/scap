from block import BlockSerializable, Attestation, AttestationNoSig
from transaction import TxSerializable
from state import StateTrie
from account import AccSerializable
from consensus import PoSC
import json


class Blockchain:
    def __init__(self):
        self.chain: BlockSerializable = BlockSerializable()
        self.newBlock: BlockSerializable | None = None
        self.headerFile = None
        self.account: AccSerializable | None = None
        self.address: bytes | None = None
        self.secretKey: bytes = b''
        with open('../config/config.json') as f:
            config = json.load(f)
            self.interval = config['currency']['halving_interval']
            self.init_reward = config['currency']['initial_reward']

    def setAccount(self, acc: AccSerializable) -> None:
        self.account = acc

    def getPastBlockHeader(self, idx) -> BlockSerializable | None:
        pass

    def getPastBlockHashList(self) -> list[bytes]:
        # TODO
        return []

    def getReward(self) -> int:
        # Recover block number
        num = self.chain.block_number
        # Calculate epoch
        epoch_no = num // self.interval
        # Calculate reward
        # (+1 to avoid division by zero)
        return self.init_reward // (epoch_no + 1)

    def recvBlock(self, bl: BlockSerializable) -> Attestation | None:
        self.newBlock = bl
        # Validate block on consensus layer
        ret = self.cProt.attest(self.state, self.chain.rebuildHash(), self.chain.block_number, self.getReward(), bl)
        # If this node is not the beneficiary
        if self.address:
            if self.address != bl.beneficiary:
                # If the length of attestationList is smaller than supermajority
                if len(self.attestationList < self.state.getValidatorSupermajorityLen()):
                    # Construct Attestation
                    atns = AttestationNoSig(
                        self.address,
                        bl.rebuildHash(),
                        b'\x01' if ret[1] else b'\x00'
                    )
                    at = atns.sign(self.secretKey)
                    return at
        return None

    def gameplayLoop() -> bool:
        pass