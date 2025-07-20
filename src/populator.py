"""
populator.py

This module creates N Bootstrapper processes to simulate a functional network.

Example:
    You can run this module directly:
        $ python populator.py
    To change N, edit the call in main (styles list has to match this value)

Author: XXXXXXXXXX
Date: 19/05/2025
"""

import multiprocessing
from bootstrapper import Bootstrapper
from network.peer import Peer
from chainlogger.logger import loggerListener
from uuid import uuid4
import time

# Style 0 - only send TXs
# Style 1 - Register and Endorse, then switch to 0
# Style 2 - Resgister, Endorse, Become validator, then 0
styles = [0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2]
# Create the log queue
log_queue = multiprocessing.Queue()
listener = multiprocessing.Process(target=loggerListener, args=(log_queue,))

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
    listener.start()

    for i in range(n):
        port = base_port + i
        b = Bootstrapper("127.0.0.1", port, adam=(i == 0), peerlist=getPeersFromProcs(bootstrappers, bootstrappers, base_port), nodeId=str(uuid4()), loggerQueue=log_queue, style=styles[i])
        bootstrappers.append(b)
        procs = b.start()
        processes.extend(procs)
        time.sleep(0.5)

    for p in processes:
        p.join()

    # Send the sentinel value to stop the listener process
    log_queue.put(None)
    listener.join()

if __name__ == "__main__":
    populate(10)