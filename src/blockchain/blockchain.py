from block import Block
from account import StateTrie

class Blockchain:
    def __init__(self):
        self.chain = []
        self.state = StateTrie()

    def add_block(self, block: Block):
        # logic here
        pass