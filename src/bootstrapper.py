from multiprocessing import Process, Queue
from blockchain.blockchain import Blockchain
from node.node import Node, Peer
from middleware.middleware import Postman
import asyncio
import signal
import atexit
import os
from tests.factory import Adam, Eve, rand

class Bootstrapper:
    def __init__(self, ip: str, port: int, adam = True, peerlist: list[Peer] = [], nodeId: str = '', style: int = 0):
        self.c = Adam() if adam else rand()
        # print(self.c[0][0].to_bytes().hex(), self.c[0][1].to_bytes().hex(), self.c[0][1].to_canonical_address().hex())
        # print(self.c[1].id_hash.hex())
        self.queue_bc_to_p2p = Queue()
        self.queue_p2p_to_bc = Queue()
        # Bridge the gap
        self.bridge_p2p = Postman(self.queue_bc_to_p2p, self.queue_p2p_to_bc)
        self.bridge_bc = Postman(self.queue_p2p_to_bc, self.queue_bc_to_p2p)
        # Endpoints
        self.node: Node | Node = None
        self.blochchain: Blockchain | None = None
        self.ip = ip
        self.port = port
        self.peerList = peerlist
        self.nodeId = nodeId
        self.playStyle = style
        atexit.register(self.cleanup)
        self.wipeStorage()


    def wipeStorage(self):
        directory = './storage'
        for filename in os.listdir(directory):
            file_path = os.path.join(directory, filename)
            if os.path.isfile(file_path):
                # print("Removing " + file_path)
                os.remove(file_path)

    def cleanup(self):
        print('Called cleanup')
        self.node.shutdown()
        self.blockchain.shutdown()

    def start(self):
        self.node = Node(self.bridge_p2p, self.ip, self.port, self.peerList, self.nodeId)
        self.blockchain = Blockchain(self.bridge_bc, self.c[1], sk=self.c[0][0].to_bytes(), playStyle=self.playStyle)#, self.c[0][1].to_canonical_address(), self.c[0][0].to_bytes(), self.c[4], self.c[3])
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
        return p_node, p_blockchain


if __name__ == "__main__":
    b = Bootstrapper("127.0.0.1", 5000)
    processes = b.start()
    for p in processes:
        p.join()