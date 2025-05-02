import random
import time

class Randao:
    def __init__(self):
        self.seed = b'\x00'

    def get_seed(self) -> bytes:
        return self.seed
    
    def reseed(self, seed: bytes) -> None:
        self.seed = seed
        random.seed(seed)

    def getValue() -> float:
        return random.random()
    
    def getValueInRange(low: int, high: int) -> int:
        return random.randint(low, high)