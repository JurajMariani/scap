from multiprocessing import Queue
import pickle

class Postman:
    '''
    Message passing interface
    - Non-blocking  (sender continues instantly, regardless of receiver's withdrawal)
    - Queue-based   (ordered delivery)
    '''
    def __init__(self, in_q: Queue, out_q: Queue):
        self.in_q = in_q
        self.out_q = out_q

    def send(self, msg):
        self.out_q.put(msg)

    def recv(self):
        if not self.in_q.empty():
            return self.in_q.get()
        return None
    