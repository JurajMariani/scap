"""
zk_handler.py

This module handles zokrates ZKP generation and verification (low-level handling).

Example:
    You can import this as a module:
        from zk_handler import createZKP, verify

Author: Bc. Juraj Marini, <xmaria03@stud.fit.vutbr.cz>
Date: 19/05/2025
"""

import subprocess
import os

CIRCUIT_FILE = "verifyVC.zok"
OUT_FILE = "out"


def __compile_circuit(create: bool = True):
    if create:
        if os.path.exists('./zkp/out') and os.path.exists('./zkp/proving.key'):
            return
    else:
        if os.path.exists('./zkp/out') and os.path.exists('./zkp/verification.key'):
            return
    """Compile the circuit if 'out' file does not exist."""
    subprocess.run(["zokrates", "compile", "-i", CIRCUIT_FILE], capture_output=True, text=True, cwd='./zkp')
    subprocess.run(["zokrates", "setup"], cwd='./zkp', capture_output=True, text=True)
    return

def __compute_witness(filename = 'proof'):
    H = int.from_bytes(os.urandom(32), 'little')
    VC = []
    for i in range(0, 512):
        VC.append(int.from_bytes(os.urandom(1), 'little'))
    #argsR = [str(coord) for coord in R]
    #argsA = [str(m) for m in issuerPubKey]
    argsVC = [str(v) for v in VC]
    # result = subprocess.run(["zokrates", "compute-witness", "-a"] + argsA + [str(H)] + argsVC + argsR + [str(S)], capture_output=True, text=True)
    result = subprocess.run(["zokrates", "compute-witness", "-a"] + [str(H)] + argsVC, capture_output=True, text=True, cwd='./zkp')
    if "Witness file written to 'witness'" not in result.stdout:
        print(f'Something Happened - {result.stdout}')
    result = subprocess.run(["zokrates", 'generate-proof', '-j', f'{filename}.json'], cwd='./zkp', capture_output=True, text=True)

def __verifyProof(filename: str = 'proof') -> bool:
    result = subprocess.run(["zokrates", "verify", "--proof-path", f'{filename}.json'], cwd='./zkp', capture_output=True, text=True)
    try:
        if 'PASSED' in result.stdout or 'PASSED' in result.stderr:
            return True
        # elif 'FAILED' in result.stdout or 'FAILED' in result.stderr:
        #     return False
        else:
            return False
    except subprocess.CalledProcessError as e:
        print(f"Error while running command: {e.stderr}")
        return False

def createZKP(filename):
    __compile_circuit()
    __compute_witness(filename)

def verify(filename) -> bool:
    __compile_circuit(False)
    return __verifyProof(filename)
