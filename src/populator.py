# populator.py
from bootstrapper import Bootstrapper
from node.peer import Peer
from uuid import uuid4
import time

def getPeersFromProcs(procList, strapperList: list[Bootstrapper], bp):
    ret = []
    i = 0
    for x in procList:
        ret.append(Peer.create(strapperList[i].nodeId, "127.0.0.1", bp + i))
        i += 1
    return ret

def populate(n: int, base_port=5000):
    bootstrappers = []
    processes = []

    for i in range(n):
        port = base_port + i
        b = Bootstrapper("127.0.0.1", port, adam=(i == 0), peerlist=getPeersFromProcs(bootstrappers, bootstrappers, base_port), nodeId=str(uuid4()))
        bootstrappers.append(b)
        procs = b.start()
        processes.extend(procs)
        time.sleep(0.5)  # Optional: give some time between startups

    for p in processes:
        p.join()

if __name__ == "__main__":
    populate(2)