from blockchain.block import BlockSerializable, BlockSig, BlockNoSig
from blockchain.account import AccSerializable, AffiliateMedia
from blockchain.state import StateTrie
from blockchain.transaction import TxSerializable
from eth_utils import keccak
from eth_keys import keys
from os import urandom
import json
import time

def getCreds():
    private_key_bytes = urandom(32)
    sk = keys.PrivateKey(private_key_bytes)
    pk = sk.public_key

    adam = AccSerializable.blank()
    id = keccak('hesoyam'.encode('ascii'))
    adam.update(balance=1000000000000000, id_hash=id, passive_sc=50, active_sc=1000, validator_pub_key=pk.to_bytes(), soc_media=[AffiliateMedia(b'\x01', 'Life', b'\x00' * 288)])
    adamAddress = pk.to_canonical_address()

    state = StateTrie()
    state.addAccount(adam, adamAddress)
    state.addValidator(adamAddress, 1000)

    with open('config/config.json') as f:
                config = json.load(f)

    x = config['sc_constants']['domain_randao']

    genesis = BlockNoSig(
        keccak('hesoyam'.encode('ascii')),
        state.getRootHash(),
        keccak(b''),
        keccak(b''),
        b'\x00' * 32,
        0,
        0,
        sk.sign_msg_hash(BlockSerializable.int_to_minimal_bytes(x) + BlockSerializable.int_to_minimal_bytes(0)).to_bytes(),
        urandom(65),
        adamAddress,
        int(time.time()),
        b''
    ).sign(sk.to_bytes()).addTXandAttLists([], [])

    return ((sk, pk), adam, adamAddress, state, genesis)
