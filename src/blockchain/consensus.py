"""
blockchain/consensus.py

This module defines a class handling leader election and block validation logic.

Example:
    You can use this as a module:
        from blockchain.consensus import PoSC

Author: XXXXXXXXXX
Date: 19/05/2025
"""

from rlp.sedes import binary
from math import sqrt, log2, log10, log
import json

from blockchain.state import StateTrie
from blockchain.block import Attestation, BlockSerializable
from blockchain.randao import Randao

class PoSC:
    """
    Class for leader election and proposed block validation.
    """
    def __init__(self):
        self.validators: dict[bytes, int] = {}
        self.randao = Randao()
        self.leader: bytes | None = None
        self.attestations: list[Attestation] = []
        self.proposedBlock: BlockSerializable | None = None

    def updateValidatorList(self, state: StateTrie) -> bool:
        """
        Based on the STATE, update the list and effective social capital of consensus nodes.
        """
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
        """
        Select the next validator based on their effective social capital (stake) and Randao randomness.
        """
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
        return None
    
    def getLeader(self) -> bytes | None:
        """
        Returns the current leader, if there is one.
        """
        return self.leader

    def attest(self, state: StateTrie, parentHash: bytes, parentBNumber: int, cRew: int, lastValidatLen: int, bl: BlockSerializable) -> tuple[StateTrie, bool]:
        """
        Verify the validity of a proposed block.

        This method is a basis for Attestation issuance.
        """
        # Maybe redundant
        self.proposedBlock = bl
        # Beneficiary must match current leader
        if self.getLeader() != bl.beneficiary:
            return (state, False)
        # Validate block
        return bl.verifyBlock(state, parentHash, parentBNumber, cRew, lastValidatLen, self.randao.get_seed())
    