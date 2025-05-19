"""
blockchain/randao.py

This module defines a Randao-esque mechanism for on-chain randomness.

Example:
    You can use this as a module:
        from blockchain.randao import Randao

Author: Bc. Juraj Marini, <xmaria03@stud.fit.vutbr.cz>
Date: 19/05/2025
"""

from eth_utils import keccak
import random

class Randao:
    """
    Class handling Randao Randomness
    """
    def __init__(self):
        """
        An isolated random instance is used to provide unbiased random resistant to influence.
        """
        self.seed: bytes = b'\x00'
        self.rng = random.Random(self.seed)

    def get_seed(self) -> bytes:
        """
        Returns current seed.
        """
        return self.seed
    
    def reseed(self, seed: bytes) -> None:
        """
        Creates a new seed.

        The 'seed' provided is the 'randao_reveal' value from an accepted block.
        """
        # Process: new_randao_seed = h(prev_seed XOR h(reveal))
        self.seed = keccak(keccak(bytes(a ^ b for a, b in zip(self.seed, keccak(seed)))))
        self.rng.seed(self.seed)

    def getValue(self) -> float:
        """
        Returns a float value from an interval <0;1>
        """
        return self.rng.random()
    
    def getValueInRange(self, low: int, high: int) -> int:
        """
        Returns an integer value from an interval <low;high>
        """
        return self.rng.randint(low, high)
    
    def shuffleList(self, llist: list) -> list:
        """
        Use Randao Randomness to shuffle a list.
        """
        self.rng.shuffle(llist)
        return llist