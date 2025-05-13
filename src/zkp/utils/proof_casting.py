import json

def bytes_to_hex(byte_data):
    return "0x" + byte_data.hex()

def hex_to_bytes(hex_str):
    return int(hex_str, 16).to_bytes(32, byteorder='big')

def encodeProof(pathToProof: str, proofname: str):
    with open(pathToProof + proofname + '.json') as f:
        data = json.load(f)

    proof = data["proof"]
    inputs = data["inputs"]

    binary = b""

    # a: [x, y]
    binary += hex_to_bytes(proof["a"][0])
    binary += hex_to_bytes(proof["a"][1])

    # b: [[x1, x2], [y1, y2]]
    binary += hex_to_bytes(proof["b"][0][0])
    binary += hex_to_bytes(proof["b"][0][1])
    binary += hex_to_bytes(proof["b"][1][0])
    binary += hex_to_bytes(proof["b"][1][1])

    # c: [x, y]
    binary += hex_to_bytes(proof["c"][0])
    binary += hex_to_bytes(proof["c"][1])

    # inputs: [input_0, input_1, ...]
    for value in inputs:
        binary += hex_to_bytes(value)

    with open(pathToProof + proofname + '.bin', "wb") as f:
        f.write(binary)

def decodeProof(pathToProof: str, proofname: str):
    with open(pathToProof + proofname + '.bin', "rb") as f:
        binary = f.read()

    proof = {
        "scheme": "g16",
        "curve": "bn128",
        "proof": {
            "a": [
                bytes_to_hex(binary[:32]),
                bytes_to_hex(binary[32:64])
            ],
            "b": [
                [
                    bytes_to_hex(binary[64:96]),
                    bytes_to_hex(binary[96:128])
                ],
                [
                    bytes_to_hex(binary[128:160]),
                    bytes_to_hex(binary[160:192])
                ]
            ],
            "c": [
                bytes_to_hex(binary[192:224]),
                bytes_to_hex(binary[224:256])
            ]
        },
        "inputs": [
            bytes_to_hex(binary[256:288])
        ]
    }

    with open(pathToProof + proofname + '.json', "w") as f:
        json.dump(proof, f, indent=2)