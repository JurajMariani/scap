from multiprocessing import Process, Queue
from blockchain.blockchain import Blockchain
from node.node import Node
from middleware.middleware import Postman
import asyncio
import signal
import atexit

class Bootstrapper:
    def __init__(self):
        self.queue_bc_to_p2p = Queue()
        self.queue_p2p_to_bc = Queue()
        # Bridge the gap
        self.bridge_p2p = Postman(self.queue_bc_to_p2p, self.queue_p2p_to_bc)
        self.bridge_bc = Postman(self.queue_p2p_to_bc, self.queue_bc_to_p2p)
        # Endpoints
        self.node: Node | Node = None
        self.blochchain: Blockchain | None = None

    @atexit.register
    def cleanup(self):
        self.node.closeConnections()
        pass

    def start(self):
        loop = asyncio.get_running_loop()
        self.node = Node(self.bridge_p2p, '', 0, [])
        self.blockchain = Blockchain(self.bridge_bc)

        # Launch processes
        p_node = Process(target=lambda: self.node.start())
        p_blockchain = Process(target=lambda: self.blochchain.start())
        # Add sigINT/TERM protection
        loop.add_signal_handler(signal.SIGINT, lambda: asyncio.create_task(self.node.closeConnections()))
        loop.add_signal_handler(signal.SIGTERM, lambda: asyncio.create_task(self.node.closeConnections()))
        # Start the show
        p_node.start()
        p_blockchain.start()
        # Wait for the end (ideally never)
        p_node.join()
        p_blockchain.join()