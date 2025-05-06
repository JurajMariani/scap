from multiprocessing import Process, Queue
from blockchain.blockchain import Blockchain
from node.node import Node
from middleware.middleware import Postman
import asyncio
import signal
import atexit
from tests.factory import getCreds

class Bootstrapper:
    def __init__(self):
        self.c = getCreds()
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
        self.node.closeConnections()

    def start(self):
        self.bridge_bc.send("AAA")
        self.bridge_p2p.send("XXX")
        #loop = asyncio.get_running_loop()
        self.node = Node(self.bridge_p2p, '127.0.0.1', 5000, [])
        self.blockchain = Blockchain(self.bridge_bc, self.c[1], self.c[0][1].to_canonical_address(), self.c[0][0].to_bytes(), self.c[4], self.c[3])

        # Launch processes
        p_node = Process(target=lambda: self.node.start())
        p_blockchain = Process(target=lambda: self.blockchain.start())
        # Add sigINT/TERM protection
        #loop.add_signal_handler(signal.SIGINT, lambda: asyncio.create_task(self.cleanup()))
        #loop.add_signal_handler(signal.SIGTERM, lambda: asyncio.create_task(self.cleanup()))
        # Start the show
        p_node.start()
        p_blockchain.start()
        # Wait for the end (ideally never)
        p_node.join()
        p_blockchain.join()


Bootstrapper().start()