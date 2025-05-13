import zkp.zk_handler
import zkp.utils.proof_casting
import os

def generate(filename: str) -> bytes | None:
    pathToZKstorage = './storage/zkp/' + filename + '/'
    os.makedirs(pathToZKstorage, exist_ok=True)
    zkp.zk_handler.createZKP('.' + pathToZKstorage + filename)
    zkp.utils.proof_casting.encodeProof(pathToZKstorage, filename)
    if os.path.isfile(pathToZKstorage + filename + '.json'):
        os.remove(pathToZKstorage + filename + '.json')
    with open(pathToZKstorage + filename + '.bin', 'rb') as f:
        bin = f.read()
    if os.path.isfile(pathToZKstorage + filename + '.bin'):
        os.remove(pathToZKstorage + filename + '.bin')
    return bin

def verify(proof: bytes, filename: str) -> bool:
    pathToZKstorage = './storage/zkp/' + filename + '/'
    os.makedirs(pathToZKstorage, exist_ok=True)
    with open(pathToZKstorage + filename + '.bin', 'wb') as f:
        f.write(proof)
    zkp.utils.proof_casting.decodeProof(pathToZKstorage, filename)
    ret = zkp.zk_handler.verify('.' + pathToZKstorage + filename)
    if os.path.isfile(pathToZKstorage + filename + '.json'):
        os.remove(pathToZKstorage + filename + '.json')
    if os.path.isfile(pathToZKstorage + filename + '.bin'):
        os.remove(pathToZKstorage + filename + '.bin')
    return ret
