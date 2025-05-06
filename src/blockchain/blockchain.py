from blockchain.block import BlockSerializable, BlockNoSig, Attestation, AttestationNoSig
from blockchain.transaction import TxSerializable, TxSerializableNoSig, TxMeta, TxMetaNoSig
from blockchain.state import StateTrie
from blockchain.account import AccSerializable, RegisterData, AffiliateMediaList, AffiliateMedia
from blockchain.consensus import PoSC
from middleware.middleware import Postman
from middleware.rpc import Param, RPC
from eth_keys import keys
from eth_utils import keccak
from rlp import encode
import asyncio
import json
import time
from os import urandom


class Blockchain:
    def __init__(self, bridge: Postman, acc: AccSerializable | None, address: bytes, sk: bytes = b'', genesis: BlockSerializable | None = None, sts: StateTrie | None = None):
        self.chain: BlockSerializable | None = genesis
        self.newBlock: BlockSerializable | None = None
        self.blockFile = None
        self.cProt = PoSC()
        self.state = sts if sts is not None else StateTrie()
        self.account: AccSerializable | None = acc
        self.address: bytes = address
        self.attestationList: list[Attestation] = []
        self.newAttestationList: list[Attestation] = []
        self.mempool: list[TxSerializable] = []
        self.slashingList = []
        self.waiting = False
        if not sk:
            self.secretKey = keys.PrivateKey(urandom(32))
        else:
            self.secretKey = keys.PrivateKey(sk)
        self.pubk = self.secretKey.public_key
        self.middleware: Postman = bridge
        with open('config/config.json') as f:
            self.config = json.load(f)

        print("Blockchain INIT")

    def setAccount(self, acc: AccSerializable) -> None:
        self.account = acc

    # Store current block to file
    def store(self):
        pass

    def getPastBlock(self, idx) -> BlockSerializable | None:
        pass

    def getPastBlockHashList(self) -> list[bytes]:
        # TODO
        return []

    def getReward(self) -> int:
        # Recover block number
        num = self.chain.block_number
        # Calculate epoch
        epoch_no = num // self.config['currency']['halving_interval']
        # Calculate reward
        # (+1 to avoid division by zero)
        return self.config['currency']['initial_reward'] // (epoch_no + 1)

    def recvAttestation(self, at: Attestation) -> None:
        # Validate Attestation
        # Sender is a validator
        acc = at.recoverAddress()
        if not self.state.getValidator(acc):
            return
        # Sender matches signature
        if not at.verifySig():
            self.slash(acc)
            return
        # Attestation should match current block or past blocks
        if acc.block_hash != self.newBlock.rebuildHash():
            if acc.block_hash in self.getPastBlockHashList():
                self.slash(at.sender)
                return
        # If Attestation is correct, add it to list
        self.newAttestationList.append(at)

        # Calculate the number of positive attestations
        positive = 0
        for att in self.newAttestationList:
            if att.verdict():
                positive += 1
        
        negative = len(self.newAttestationList) - positive
        more = max(positive, negative)
        # If consensus cannot be reached
        # menanig there is no logner an honest supermajority
        # the best coarse of action is to leave the network
        if (self.state.getValidatorLen() - len(self.newAttestationList) + more) < self.state.getValidatorSupermajorityLen():
            print("Consensus cannot be reached. Terminating...")
            exit(1)
        # If we don't have a supermajority yet
        elif len(self.newAttestationList) < self.state.getValidatorSupermajorityLen():
            return
        # If positive supermajority is reached
        elif len(positive) > self.state.getValidatorSupermajorityLen():
            # Attestations are stored for the next block
            self.attestationList = self.newAttestationList
            # TMP list is wiped
            self.newAttestationList = []
            # Proposed block can be safely added to the chain
            self.store()
            self.chain = self.newBlock
            self.newBlock = None
        else:
            # Negative supermajority is reached
            self.newAttestationList = []
            self.newBlock = None
        return

    def generateBlock(self) -> None:
        # Check current node is supposed to be the proposer
        if not self.cProt.getLeader() == self.address:
            return None
        # Check mempool has enough TXs
        print("A", len(self.mempool))
        if len(self.mempool) < self.config['constraints']['tx_limit']:
            return None
        print('b')
        # Gather Attestations of the last block
        # Attestations are verified on-receive
        attList = []
        for att in self.attestationList:
            if att.block_hash == self.chain.rebuildHash():
                attList.append(att)
        # Order TXs based on feasibility metric
        # feasibility metric: unit fee per byte
        # Pick n best
        txs = sorted(self.mempool, key=lambda t: t.getFeasibilityMetric(), reverse=True)[0:self.config['constraints']['tx_limit']]
        # Request new state after TXs
        tmpBl = BlockSerializable(
            b'\x00' * 32,
            b'\x00' * 32,
            b'\x00' * 32,
            b'\x00' * 32,
            b'\x00' * 32,
            0,
            0,
            b'\x00' * 96,
            b'\x00' * 96,
            b'\x00' * 20,
            0,
            0, 
            0,
            0,
            txs,
            []
        )
        # New randao value
        message = tmpBl.int_to_minimal_bytes(self.config['sc_constrants']['domain_randao']) + tmpBl.int_to_minimal_bytes(self.chain.block_number + 1)
        message = keccak(message)
        # Get new state hash
        stateHash = tmpBl.getStateAfterExecution(self.state, self.getReward()).getRootHash()
        # Construct a block
        bl = BlockNoSig(
            self.chain.rebuildHash(),
            stateHash,
            tmpBl.calculateListHash(txs),
            tmpBl.calculateListHash(attList),
            b'\x00' * 32,
            0,
            self.chain.block_number + 1,
            self.sk.sign_msg_hash(message).to_bytes(),
            self.cProt.randao.get_seed(),
            self.address,
            int(time.time()),
            b''
        ).sign(self.secretKey.sserialize()).addTXandAttLists(txs, attList)
        # Block is ready
        # No need to verify as blocks are verified on arrival
        # Proposed blocks are sent from here to recvBlock()
        self.middleware.send(RPC.constructRPC('/block', [Param.constructParam('bl', 4, bl.sserialize())]))
        self.waiting = True
        return
    
    def reassignRequest(self, txm: TxMeta) -> None:
        pass
    
    def generateReassign(self, recp: bytes, value: int) -> TxMeta:
        return TxMetaNoSig(
            self.account.forwarder,
            self.address,
            recp,
            int(time.time()),
            # Value is used for SC
            value
        ).sign(self.secretKey.sserialize())
    
    def generateRegisterData(self, id_hash: bytes, vc_zkp: bytes) -> bytes:
        return encode(RegisterData(
            id_hash,
            vc_zkp
        ))
    
    def generateAffMediaList(self, validator_pub_key: bytes, media: list[tuple[bool, str, bytes]]) -> bytes:
        mediaList = []
        for medium in media:
            mediaList.append(AffiliateMedia(
                b'\x01' if medium[0] else b'\x00',
                bytes(medium[1], 'utf-8'),
                medium[2]
            ))
        return encode(AffiliateMediaList(
            validator_pub_key,
            mediaList
        ))
    
    def generateReplacementTx(self) -> TxSerializable | None:
        # Find TX
        for tx in self.mempool:
            if tx.sender == self.address and tx.nonce == self.account.nonce:
                # Increase fee & sign
                ntx = tx.update(fee=max(1, tx.fee * self.config['constraints']['replacement_tx_fee_multiplier'])).sign(self.secretKey.sserialize())
                # WARNING Change type to 4, but leave SIG intact
                # Upon reaching a node type of TXs type 4 is changed to orig type
                # therefore SIG is correct
                return ntx.update(type=4)
        return None
    
    def generateTX(self, type: int, fee: int, recp: bytes, value: int, data: bytes = b'', **kwargs) -> None:
        # Create a placeholder TX
        txData = data
        # Decide on TX based on TxType
        if type == 1:
            # Scap (re)assign
            # If kwargs contain 'MetaTX': True
            # - Data param should already contain MetaTX transaction
            # - We are receiver of SC
            # - Data is prefilled, same as transfer
            # If no 'MetaTX': True or 'MetaTX': False
            # - We want to assign SC to someone else
            if (('MetaTX' not in kwargs.keys()) or not kwargs['MetaTX']):
                # Construct, Sign and Send MetaTX
                txm = self.generateReassign(recp, value)
                self.middleware.send(RPC.constructRPC('/txm', [Param.constructParam('txm', 6, txm.sserialize())]))
        elif type == 2:
            # Register
            # Fill data with registerData serialized
            if (('id_hash' not in kwargs.keys()) or ('vc_zkp' not in kwargs.keys(0))):
                return None
            if not isinstance(kwargs['id_hash'], bytes) or not isinstance(kwargs['vc_zkp'], bytes):
                return None
            txData = self.generateRegisterData(kwargs['id_hash'], kwargs['vc_zkp'])
        elif type == 3:
            # SocMedia Register
            # Fill data with AffiliateMediaList serialized
            if (('validator_pub_key' not in kwargs.keys()) or ('media' not in kwargs.keys())):
                return None
            if not isinstance(kwargs['validator_pub_key'], bytes) or not isinstance(kwargs['media'], list[tuple[bool, str, bytes]]):
                return None
            txData = self.generateAffMediaList(kwargs['validator_pub_key'], kwargs['media'])
        elif type == 4:
            # Replacement TX
            return self.generateReplacementTx()
        else:
            pass
    
        tx = TxSerializableNoSig(
            self.account.nonce,
            type,
            fee,
            self.address,
            b'\x00' * 20 if type in (1, 2, 3) else recp,
            value,
            int(time.time()),
            txData
        )
        print("tx: ", tx)
        ttx = tx.sign(self.secretKey.to_bytes())
        print("ttx: ", ttx)
        print(isinstance(ttx.sserialize(), bytes))
        print("AAAA")
        self.middleware.send(RPC.constructRPC('/tx', [Param.constructParam('tx', 5, ttx.sserialize())]))
        return

    def recvTx(self, tx: TxSerializable) -> None:
        print("Called recvTX")
        # Reserve tmp for TX
        txn = tx 
        # If TX type is 4 (replacement), replace type with orig type
        # WARNING, ReplaceTX sig will match, See TX creation fn
        if (tx.type == 4):
            for txl in self.mempool:
                if txl.sender == tx.sender and txl.nonce == tx.nonce:
                    if tx.fee >= max(1, (txl.fee * self.config['constrants']['replacement_tx_fee_multiplier'])):
                        txn = TxSerializable(
                            tx.nonce, txl.type,
                            tx.fee, tx.sender,
                            tx.to, tx.value,
                            tx.timestamp, tx.data,
                            tx.v, tx.r, tx.s
                        )
                        self.mempool.remove(txl)
                        break
                    else:
                        return None
        # Verify TX on arrival
        if self.state.transaction(txn, True, False):
            print("Appended to mempool")
            self.mempool.append(txn)
        # Else, discard
        return None

    def slash(self, address: bytes) -> None:
        # Mechanism:
        # - Reduce SC by 1/5
        # - Return SC to endorsers
        # - Ban account from getting endorsed for X time (from config)
        pass

    def recvBlock(self, bl: BlockSerializable) -> Attestation | None:
        self.newBlock = bl
        # Validate block on consensus layer
        ret = self.cProt.attest(self.state, self.chain.rebuildHash(), self.chain.block_number, self.getReward(), bl)
        # Stop waiting for block
        self.waiting = False
        # If this node is not the beneficiary
        # If the block seems correct, 
        if self.address:
            if self.address != bl.beneficiary:
                # Send attestation
                atns = AttestationNoSig(
                    self.address,
                    bl.rebuildHash(),
                    b'\x01' if ret[1] else b'\x00'
                )
                at = atns.sign(self.secretKey.sserialize())
                self.middleware.send(RPC.constructRPC('/attestation', [Param.constructParam('at', 7, at.sserialize())]))
        return None

    def pushBlock(self, bl: BlockSerializable):
        # Without asking, accept incomming block
        self.chain = bl
        pass

    def passBlock(self) -> RPC:
        # Peer requested last block
        # Send own block at the top of the chain
        if self.chain is not None:
            rpc = RPC.constructRPC('/pushblock', [Param.constructParam('bl', 4, self.chain.sserialize())])
        else:
            rpc = RPC.constructRPC('/passblock', [])
        return rpc
    
    def start(self):
        asyncio.run(self.run())

    async def run(self):
        asyncio.create_task(self.listenToNetwork())
        asyncio.create_task(self.listenToUserInput())
        await self.gameplayLoop()

    async def listenToUserInput(self):
        while True:
            await asyncio.sleep(4)
            print("USER: generating TX")
            self.generateTX(0, 10, b'\x10' * 20, 1000)

    async def listenToNetwork(self):
        while True:
            msg = self.middleware.recv()
            if msg:
                print(f"[BC] Got from P2P: {msg}")
                if type(msg) == RPC:
                    self.handleMessage(msg)
            await asyncio.sleep(0.1)

    def handleMessage(self, msg: RPC):
        # Decode procedure call
        procCall = msg.procedure.decode('ascii')
        # Block request
        if procCall == '/passBlock':
            data = self.passBlock()
            data.sender = msg.sender
            # Send block to orig sender
            self.middleware.send(data)
        elif procCall == '/pushBlock':
            if self.chain is None:
                self.pushBlock(BlockSerializable.deserialize(msg.params[0].value))
        elif procCall == '/block':
            self.recvBlock(BlockSerializable.deserialize(msg.params[0].value))
        elif procCall == '/attestation':
            self.recvAttestation(Attestation.deserialize(msg.params[0].value))
        elif procCall == '/tx':
            self.recvTx(TxSerializable.deserialize(msg.params[0].value))
        elif procCall == '/txm':
            self.reassignRequest(TxMeta.deserialize(msg.params[0].value))
        return

    async def gameplayLoop(self):
        print("Blockchain START")
        if self.chain is None:
            print("BL: Ask for last block")
            # Ask for chain
            self.middleware.send(RPC.constructRPC('/passBlock', []))
        while self.chain is None:
            await asyncio.sleep(0.1)
        print("BL: Last block READY")

        self.cProt.randao.reseed(self.chain.randao_seed)
        print("BL: RANDAO reseeded")
        while True:
            # -- Repeat indefinitely --
            # 1. Select a leader (every system should start with at least one registered creator)
            self.cProt.selectLeader(self.state)
            print("BL: Leader selected as ", self.cProt.getLeader())
            # 2. If WE have been selected
            if self.cProt.getLeader() == self.address:
                print("BL: I AM LEADER!!!")
                # 2a. Generate a block
                b = None
                # 3a. Wait until WE have enough TXs in mempool
                while b is None and not self.waiting:
                    print("Can generate block??")
                    # 4a. Generate a block
                    b = self.generateBlock()
                    await asyncio.sleep(10)
                print("I HAVE HAD ENOUGH TXS")
                while self.waiting:
                    await asyncio.sleep(0.1)
                # 5a. Encapsulate the block (to be send-ready)
                rpc = RPC.constructRPC('/block', [Param.constructParam('b', 4, b.sserialize())])
                # 6a. Send the encapsulated block through the network
                self.middleware.send(rpc)
            else:
                # 2b. Wait for a new block to arrive
                while self.newBlock is None:
                    await asyncio.sleep(0.1)
                # 3b. When a new block arrives, /recvBlock is called,
                #     the block is validated and an attestation is sent (automatically)
            # 7. (or 4.) Attestations were sent automatically upon block arrival
            # 8. Upon attestation arrival, attestation list is queried
            # 9. Block is either received or rejected
            #    (also we can wait for more attestations or consensus may not be reached)
            # 10. We wait until the new block has been processed
            while self.newBlock is not None:
                await asyncio.sleep(0.1)
            # 11. Rinse and Repeat!