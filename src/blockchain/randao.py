import random
import time

class Randao:
    def __init__(self):
        self.seed = b'\x00'
        self.rng = random.Random(self.seed)

    def get_seed(self) -> bytes:
        return self.seed
    
    def reseed(self, seed: bytes) -> None:
        self.seed = seed
        self.rng.seed(seed)

    def getValue(self) -> float:
        return self.rng.random()
    
    def getValueInRange(self, low: int, high: int) -> int:
        return self.rng.randint(low, high)
    
    def shuffleList(self, llist: list) -> list:
        self.rng.shuffle(llist)
        return llist