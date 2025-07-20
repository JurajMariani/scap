"""
middleware/middleware.py

This module defines a inter-process communication mechanism between blockchain and node.

Example:
    You can use this as a module:
        from middleware.middleware import Postman

Author: XXXXXXXXXX
Date: 19/05/2025
"""

from multiprocessing import Queue

class Postman:
    """
    Message passing interface
    - Non-blocking  (sender continues instantly, regardless of receiver's withdrawal)
    - Queue-based   (ordered delivery)
    """
    def __init__(self, in_q: Queue, out_q: Queue):
        self.in_q = in_q
        self.out_q = out_q

    def send(self, msg):
        self.out_q.put(msg)

    def recv(self):
        if not self.in_q.empty():
            return self.in_q.get()
        return None
    