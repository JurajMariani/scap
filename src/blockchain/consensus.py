from rlp.sedes import binary
from math import sqrt, log2, log10, log
import json

from blockchain.state import StateTrie
from blockchain.block import Attestation, AttestationNoSig, BlockSerializable
from blockchain.account import AccSerializable
from blockchain.randao import Randao

class PoSC:
    def __init__(self):
        self.validators: dict[bytes, int] = {}
        self.randao = Randao()
        self.leader: bytes | None = None
        self.attestations: list[Attestation] = []
        self.proposedBlock: BlockSerializable | None = None

    def updateValidatorList(self, state: StateTrie) -> bool:
        scalingFn = ''
        with open('config/config.json') as f:
            config = json.load(f)
            scalingFn = config['sc_constants']['scaling']
        # Chech working file
        if scalingFn == '':
            return False
        # Refresh own validator list
        self.validators = {}
        # Request validator list
        valList = state.getValidators()
        # Set function ptr
        # TODO
        # The scaling should be dynamic to automatically adjust effective social capital
        # to ensure no single account has more than 10% of effective social capital
        # This should be the default operation starting as soon as the 10th nodes stakes
        # its active social capital
        fn = None
        if scalingFn == 'root':
            fn = sqrt
        elif scalingFn == 'log10':
            fn = log10
        elif scalingFn == 'ln':
            fn = log
        else:
            # Default is log2
            fn = log2
        # For each validator
        for addr, sc in valList.items():
            # Calculate effective SC stake
            self.validators[addr] = fn(sc)
        return True

    def selectLeader(self, state: StateTrie) -> bytes | None:
        """Select the next validator based on their stake and Randao randomness."""
        # Refresh current leader
        self.leader = None
        # Get the randomness from Randao
        rngv = self.randao.getValue()
        # Update the list of validators
        if not self.updateValidatorList(state):
            return None
        # Weighted selection based on effective social capital
        total_sc = sum(list(self.validators.values()))
        cumulative_sc = 0
        rngvSewed = rngv * total_sc
        # Shuffle validator list
        shuffledVals = self.randao.shuffleList(list(self.validators.items()))
        for address, sc in shuffledVals:
            cumulative_sc += sc
            if (rngvSewed < cumulative_sc):
                self.leader = address
                return address
        # Obsolete assignment
        # self.leader = None
        return None
    
    def getLeader(self) -> bytes | None:
        return self.leader

    def attest(self, state: StateTrie, parentHash: bytes, parentBNumber: int, cRew: int, bl: BlockSerializable) -> tuple[StateTrie, bool]:
        # Maybe redundant
        self.proposedBlock = bl
        # Beneficiary must match current leader
        if self.getLeader() != bl.beneficiary:
            return (state, False)
        # Validate block
        # print(self.randao.seed)
        return bl.verifyBlock(state, parentHash, parentBNumber, cRew, self.randao.get_seed())
    
    # randao seed 
    # b'\xb3do\x89\x02\xa9=\xae\x9f\x95"\xffo\xfa\x8a\x82\x94+\x89}W\xa6\xec_\xfd\x00A\xe6#\xf3i4'
    # b'\xb3do\x89\x02\xa9=\xae\x9f\x95"\xffo\xfa\x8a\x82\x94+\x89}W\xa6\xec_\xfd\x00A\xe6#\xf3i4'
        