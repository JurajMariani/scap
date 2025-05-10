from multiprocessing import Process, Queue
from blockchain.blockchain import Blockchain
from node.node import Node
from middleware.middleware import Postman
import asyncio
import signal
import atexit
from tests.factory import Adam

class Bootstrapper:
    def __init__(self):
        self.c = Adam()
        self.queue_bc_to_p2p = Queue()
        self.queue_p2p_to_bc = Queue()
        # Bridge the gap
        self.bridge_p2p = Postman(self.queue_bc_to_p2p, self.queue_p2p_to_bc)
        self.bridge_bc = Postman(self.queue_p2p_to_bc, self.queue_bc_to_p2p)
        # Endpoints
        self.node: Node | Node = None
        self.blochchain: Blockchain | None = None
        atexit.register(self.cleanup)

    def cleanup(self):
        print('Called cleanup')
        self.node.shutdown()
        self.blockchain.shutdown()

    def start(self):
        self.node = Node(self.bridge_p2p, '127.0.0.1', 5000, [])
        self.blockchain = Blockchain(self.bridge_bc, self.c[1], self.c[0][1].to_canonical_address(), self.c[0][0].to_bytes(), self.c[4], self.c[3])
        # Launch processes
        p_node = Process(target=self.node.start)
        p_blockchain = Process(target=self.blockchain.start)
        # Add sigINT/TERM protection
        signal.signal(signal.SIGINT, lambda sig, frame: self.cleanup())
        signal.signal(signal.SIGTERM, lambda sig, frame: self.cleanup())
        # Start the show
        p_node.start()
        p_blockchain.start()
        # Wait for the end (ideally never)
        p_node.join()
        p_blockchain.join()


Bootstrapper().start()