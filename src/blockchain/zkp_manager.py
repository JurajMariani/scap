"""
blockchain/zkp_manager.py

This module defines a high-level abstraction of zkp creation and verification.
Employs the low-level 'zkp.zk_handler'

Example:
    You can use this as a module:
        from blockchain.zkp_manager import generate, verify
    Or a test for correct ZoKrates installation and configuration:
        ~/path/to/src$ python3 -m blockchain.zkp_manager

Author: Bc. Juraj Marini, <xmaria03@stud.fit.vutbr.cz>
Date: 19/05/2025
"""

import zkp.zk_handler
import zkp.utils.proof_casting
import os

def generate(filename: str) -> bytes | None:
    """
    Used to generate a ZKP of identity.

    Expects zocrates to be in the $PATH variable and
    the existance of '/src/storage/zkp/'
    """
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
    """
    Used to verify a ZKP of identity.

    Expects zocrates to be in the $PATH variable and
    the existance of '/src/storage/zkp/'
    """
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

if __name__ == "__main__":
    """
    A tester of correctness.

    To test, from the '/src' directory execute
    'python3 -m blockchain.zkp_manager' and wait for the result.
    Correctness is signified by a single 'True' print.
    """
    x = generate('test')
    print(verify(x, 'test'))