from blockchain.block import BlockSerializable, BlockNoSig, Attestation, AttestationNoSig
from blockchain.transaction import TxSerializable, TxSerializableNoSig, TxMeta, TxMetaNoSig
from blockchain.state import StateTrie
from blockchain.account import AccSerializable, RegisterData, AffiliateMediaList, AffiliateMedia
from blockchain.consensus import PoSC
from blockchain.utils import Genesis
from middleware.middleware import Postman
from middleware.rpc import Param, RPC
from node.peer import to_int
from eth_keys import keys
from eth_utils import keccak
from rlp import encode, decode
import asyncio
import json
import time
from os import urandom
import traceback

import random

class Blockchain:
    def __init__(self, bridge: Postman, address: bytes, sk: bytes = b'', acc: AccSerializable | None = None, genesis: BlockSerializable | None = None, sts: StateTrie | None = None):
        g = Genesis()
        self.gettingReady = True
        self.chain: BlockSerializable | None = g.constructGenesisBlock()
        self.newBlock: BlockSerializable | None = None
        self.cProt = PoSC()
        self.state = sts if sts is not None else g.getGenesisState()
        self.account: AccSerializable | None = acc
        self.address: bytes = address
        self.attestationList: list[Attestation] = []
        self.newAttestationList: list[Attestation] = []
        self.mempool: list[TxSerializable] = []
        self.slashingList = []
        self.badNonces: list[int] = []
        self.nonce = 0
        self.waiting = False
        self.consensus_reached = False
        if not sk:
            self.secretKey = keys.PrivateKey(urandom(32))
        else:
            self.secretKey = keys.PrivateKey(sk)
        self.pubk = self.secretKey.public_key
        self.middleware: Postman = bridge
        with open('config/config.json') as f:
            self.config = json.load(f)
        # SIGINT/SIGTERM stopper
        self.shutdownEvent = asyncio.Event()
        self.middleware.send(RPC.constructRPC('/getNodeID', []))
        self.nodeId = ''
        # print("Blockchain INIT")

    def setAccount(self, acc: AccSerializable) -> None:
        # Eiter use this fn or pass account in constructor
        # WARNING
        # When passing account in constructor, the account has to already be in the stateTrie
        self.account = acc
        if self.state.getAccount(self.address) is None:
            self.state.addAccount(acc, self.address)
        self.nonce = acc.nonce

    def updateAccount(self) -> None:
        self.account = self.state.getAccount(self.address)

    # Store current block to file
    def store(self):
        if self.chain.block_number == 0:
            return
        with open('./storage/' + self.nodeId + '.txt', 'ab') as f:
            f.write(self.chain.sserialize())
        with open('./storage/' + self.nodeId + '_lperfix.txt', 'a') as f:
            f.write(str(len(self.chain.sserialize())) + '\n')

    def getPastBlockHashList(self) -> list[bytes]:
        # TODO
        return []

    def getReward(self, block_num:int = -1) -> int:
        # Recover block number
        if block_num < 0:
            num = self.chain.block_number + 1
        else:
            num = block_num
        # Calculate epoch
        epoch_no = num // self.config['currency']['halving_interval']
        # Calculate reward
        # (+1 to avoid division by zero)
        return self.config['currency']['initial_reward'] // (epoch_no + 1)

    def recvAttestation(self, at: Attestation) -> None:
        print(f"[{self.nodeId}]: ATTESTATION RECEIVED")
        # Validate Attestation
        # Sender is a validator
        add = at.recoverAddress()
        if not self.state.getValidator(add):
            return
        # Sender matches signature
        if not at.verifySig():
            self.slash(add)
            return
        # Attestation should match current block or past blocks
        if at.block_hash != self.newBlock.rebuildHash():
            if at.block_hash in self.getPastBlockHashList():
                self.slash(at.sender)
                return
        # If Attestation is correct, add it to list
        self.newAttestationList.append(at)

        # Calculate the number of positive attestations
        positive = 0
        for att in self.newAttestationList:
            if att.getVerdict():
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
        elif positive > self.state.getValidatorSupermajorityLen():
            # Attestations are stored for the next block
            self.attestationList = self.newAttestationList
            # TMP list is wiped
            self.newAttestationList = []
            # Proposed block can be safely added to the chain
            self.store()
            self.state = self.newBlock.getStateAfterExecution(self.state, self.getReward())[0]
            #print("THIS ACC NONCE IS", self.state.getAccount(self.address).nonce)
            self.chain = self.newBlock
            self.newBlock = None
            # Remove TXs from mempool
            for tt in self.chain.transactions:
                skip = False
                for t in self.mempool:
                    if skip:
                        continue
                    # print(f"Comparing NONCE: {t.nonce} VS. {tt.nonce}")
                    if t.eq(tt):
                        self.mempool.remove(t)
                        skip = True
                    else:
                        print("NOT EQUAL")
            print(f"[{self.nodeId}]:CONSENSUS REACHED, keeping block")
            self.consensus_reached = True
        else:
            # Negative supermajority is reached
            self.newAttestationList = []
            self.newBlock = None
            print(f"[{self.nodeId}]: CONSENSUS REACHED, discarding block")
            self.consensus_reached = True
        return

    def generateBlock(self) -> None:
        # Check current node is supposed to be the proposer
        if not self.cProt.getLeader() == self.address:
            return None
        # Check mempool has enough viable TXs
        if len(self.mempool) < self.config['constraints']['tx_limit']:
            return None
        # print("MEMPOOL VIABLE")
        # Gather Attestations of the last block
        # Attestations are verified on-receive
        attList = []
        for att in self.attestationList:
            if att.block_hash == self.chain.rebuildHash():
                attList.append(att)
        # Order TXs based on feasibility metric
        # feasibility metric: unit fee per byte
        # Pick n best
        txs = sorted(self.mempool, key=lambda t: (t.nonce, t.getFeasibilityMetric()))[0:self.config['constraints']['tx_limit']]
        #for t in txs:
            # print("NONCE: ", t.nonce)
        # New randao value
        randao_seed = bytes.fromhex(self.config['sc_constants']['domain_randao']) + BlockSerializable.int_to_minimal_bytes(self.chain.block_number + 1)
        randao_seed = keccak(randao_seed)
        # Get new state hash
        stateHash = BlockSerializable.getStateAfterExec(self.state, txs, self.address, self.getReward())[0].getRootHash()
        # Construct a block
        bl = BlockNoSig(
            self.chain.rebuildHash(),
            stateHash,
            BlockSerializable.calculateListHash(txs),
            BlockSerializable.calculateListHash(attList),
            b'\x00' * 32,
            0,
            self.chain.block_number + 1,
            self.secretKey.sign_msg_hash(randao_seed).to_bytes(),
            self.cProt.randao.get_seed(),
            self.address,
            int(time.time()),
            b''
        ).sign(self.secretKey.to_bytes()).addTXandAttLists(txs, attList)
        # print('send block')
        try:
            bl.sserialize()
        except Exception as e:
            print(e)
        print(f"[{self.nodeId}]: PROPOSED BLOCK:", bl)
        # Block is ready
        # No need to verify as blocks are verified on arrival
        # Proposed blocks are sent from here to recvBlock()
        # print("SENDING BLOCK")
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
        ).sign(self.secretKey.to_bytes())
    
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
                ntx = tx.update(fee=max(1, tx.fee * self.config['constraints']['replacement_tx_fee_multiplier'])).sign(self.secretKey.to_bytes())
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
        # TxSerializableNoSig(nonce=0, type=0, fee=967, sender=b'\x8b\xfc\x19\xd4\x1dQ\x060\xabT\xb9\x12\x92\xee<\xaa\r\xbf8\x84', to=b'\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10', value=1000, timestamp=1747002060, data=b'')
        # TxSerializableNoSig(nonce=0, type=0, fee=140, sender=b'\xf3\x14\x87\xf4\xa5\xe8\xb4\xac8\xfe\x16\xbb\xb0j\xaf\xf8\xdeqz\xbb', to=b'\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10', value=1000, timestamp=1747002060, data=b'')
        print(f'[{self.nodeId}]: MY ADDRESS: {self.address.hex()}/{len(self.address)}', flush=True)
        tx = TxSerializableNoSig(
            self.nonce,
            type,
            fee,
            self.address,
            b'\x00' * 20 if type in (1, 2, 3) else recp,
            value,
            int(time.time()),
            txData
        )
        print(f'[{self.nodeId}]: GENERATED TX: {tx}', flush=True)
        self.nonce += 1
        # Verify TX before sending
        ttx = tx.sign(self.secretKey.to_bytes())
        print(f'[{self.nodeId}][genTX]: Transaction GOOD?', flush=True)
        try:
            if not self.state.transaction(ttx, True, False):
                print(f'[{self.nodeId}][genTX]: Transaction discarded')
                self.nonce -= 1
                return
        except Exception as e:
            print(f"[{self.nodeId}]: EXCEPTION: {e}", flush=True)
        self.middleware.send(RPC.constructRPC('/tx', [Param.constructParam('tx', 5, ttx.sserialize())]))
        return

    def recvTx(self, tx: TxSerializable) -> None:
        # print("Called recvTX")
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
        # TODO NONCE
        # TODO Every TX with nonce greater/equal to account nonce is correct,
        # TODO if not execute=True
        if self.state.transaction(txn, True, False):
            self.mempool.append(txn)
            print(f"[{self.nodeId}]: Successfully added to mempool")
        # Else, discard
        # But if this node created that TX, store it's nonce (for future replace)
        if self.address == tx.sender:
            # But disallow nonces lower than account nonce
            if (self.state.getAccount(self.address).nonce >= tx.nonce):
                self.badNonces.append(tx.nonce)
        return None

    def slash(self, address: bytes) -> None:
        # Mechanism:
        # - Reduce SC by 1/5
        # - Return SC to endorsers
        # - Ban account from getting endorsed for X time (from config)
        pass

    def recvBlock(self, bl: BlockSerializable) -> Attestation | None:
        # print("BLOCK RECEIVED")
        self.newBlock = bl
        # Validate block on consensus layer
        ret = self.cProt.attest(self.state, self.chain.rebuildHash(), self.chain.block_number, self.getReward(), bl)
        # print("CONSENSUS RETURNED THIS, ", ret)
        # Stop waiting for block
        self.waiting = False
        # If this node is not a validator
        if not self.state.getValidator(self.address):
            return None
        # If this node is not the beneficiary
        # If the block seems correct, 
        if self.address:
            # Disabled for testing purposes
            # if self.address != bl.beneficiary:
            if True:
                # Send attestation
                atns = AttestationNoSig(
                    self.address,
                    bl.rebuildHash(),
                    b'\x01' if ret[1] else b'\x00'
                )
                at = atns.sign(self.secretKey.to_bytes())
                self.middleware.send(RPC.constructRPC('/attestation', [Param.constructParam('at', 7, at.sserialize())]))
        return None

    def pushBlock(self, bll: list[Param]):
        # Set updatingState flag to store incomming proposed blocks
        # TODO
        # print("Pushblock, GOT:", bll)
        if not bll or bll[0].value == b'':
            self.gettingReady = False
            # print("NOWORKRETUREN")
            return
        # The current state is far, in the distance
        blocks = bll[0]
        cumulus = 0
        for l in bll[1:]:
            val = to_int(l.value)
            nBlock = BlockSerializable.ddeserialize(blocks[cumulus:cumulus + val])
            cumulus += val
            # Apply changes to state
            nstate = nBlock.getStateAfterExecution(self.state, self.getReward(nBlock.block_number))
            # If recvd blocks are incorrect,
            # discard changes and request again
            if not nstate[1]:
                self.chain = None
                self.state = None
                self.passBlock()
                return
            # If block is sound, update values
            self.store()
            self.chain = nBlock
            self.state = nstate[0]
            self.cProt.randao.reseed(self.chain.randao_seed)
        self.gettingReady = False
        # print("WHOOOOOOOA")
            # Continue to the next block
        # TODO
        # What else needs to be set?
        # TODO

    def passBlock(self) -> RPC:
        # Peer requested last block
        # Send own block at the top of the chain
        if self.chain is not None and self.chain.block_number != 0:
            with open('./storage/' + self.nodeId + '.txt', 'rb') as f:
                data = f.read()
            paramList = [Param.constructParam('bl', 4, data)]
            with open('/storage/' + self.nodeId + '_lprefix.txt', 'r') as f:
                lengths = [int(line.strip()) for line in f]
            for l in lengths:
                paramList.append(Param.constructParam('length', 0, l.to_bytes((l.bit_length() + 7) // 8, byteorder='big')))
            rpc = RPC.constructRPC('/pushBlock', paramList)
        else:
            # print("Answer with a question")
            rpc = RPC.constructRPC('/pushBlock', [])
        return rpc
    
    def start(self):
        asyncio.run(self.run())

    async def run(self):
        asyncio.create_task(self.listenToNetwork())
        asyncio.create_task(self.listenToUserInput())
        await self.startLoop()

    def shutdown(self):
        self.shutdownEvent.set()

    async def startLoop(self):
        chainTask = asyncio.create_task(self.gameplayLoop())
        await self.shutdownEvent.wait()
        chainTask.cancel()
        print("[BL] Shutdown complete")

    async def listenToUserInput(self):
        while not self.shutdownEvent.is_set():
            await asyncio.sleep(4)
            if self.gettingReady:
                continue
            print(f"[{self.nodeId}]: USER: generating TX")
            self.generateTX(0, random.randint(0, 1500), b'\x10' * 20, 1000)

    async def listenToNetwork(self):
        while not self.shutdownEvent.is_set():
            msg = self.middleware.recv()
            if msg:
                print(f"[{self.nodeId}]: [BC] Got from P2P {msg.procedure}")
                if type(msg) == RPC:
                    self.handleMessage(msg)
            await asyncio.sleep(0.1)

    def handleMessage(self, msg: RPC):
        # Decode procedure call
        procCall = msg.procedure.decode('ascii')
        # Block request
        if procCall == '/passBlock':
            data = self.passBlock()
            data.senderId = msg.senderId
            data.xclusive = True
            # Send block to orig sender
            self.middleware.send(data)
        elif procCall == '/pushBlock':
            if self.chain is None or self.chain.block_number == 0:
                # print("Calling here")
                self.pushBlock(msg.params)
        elif procCall == '/block':
            self.recvBlock(BlockSerializable.ddeserialize(msg.params[0].value))
        elif procCall == '/attestation':
            self.recvAttestation(Attestation.ddeserialize(msg.params[0].value))
        elif procCall == '/tx':
            self.recvTx(TxSerializable.ddeserialize(msg.params[0].value))
        elif procCall == '/txm':
            self.reassignRequest(TxMeta.ddeserialize(msg.params[0].value))
        elif procCall == '/setNodeID':
            self.nodeId = msg.params[0].value.decode('utf-8')
            print("Node ID set:", self.nodeId)
        return

    async def gameplayLoop(self):
        # print("Blockchain START")
        # print("BL: Ask for last block")
        # Ask for chain
        self.middleware.send(RPC.constructRPC('/passBlock', []))
        await asyncio.sleep(5)
        while self.gettingReady:
            await asyncio.sleep(5)
        
        print(f"[{self.nodeId}]: BL: Last block READY", flush=True)
        while True:
            # -- Repeat indefinitely --
            self.consensus_reached = False
            # 1. Select a leader (every system should start with at least one registered creator)
            self.cProt.selectLeader(self.state)
            print(f"[{self.nodeId}]: BL: Leader selected as ", self.cProt.getLeader(), flush=True)
            # 2. If WE have been selected
            if self.cProt.getLeader() == self.address:
                print(f"[{self.nodeId}]: BL: I AM LEADER!!!", flush=True)
                # 2a. Generate a block
                b = None
                # 3a. Wait until WE have enough TXs in mempool
                while not self.waiting:
                    #print("Can generate block??")
                    # 4a. Generate a block
                    try:
                        self.generateBlock()
                    except Exception as e:
                        print(e)
                        traceback.print_exc()
                    if not self.waiting:
                        await asyncio.sleep(10)
                print(f"[{self.nodeId}]: I HAVE HAD ENOUGH TXS", flush=True)
                while self.waiting:
                    print("here?", flush=True)
                    await asyncio.sleep(0.1)
                print(f"[{self.nodeId}]: I HAVE WAITED ENOUGH!", flush=True)
                # 5a. Encapsulate the block (to be send-ready)
                # 6a. Send the encapsulated block through the network
                #     The steps above are executed in generateBlock()
            print(f"[{self.nodeId}]: Wait for block.", flush=True)
            # 7. Wait for a new block to arrive
            # 8. When a new block arrives, /recvBlock is called,
            #    the block is validated and an attestation is sent (automatically)
            # 9. Attestations were sent automatically upon block arrival
            # 10. Upon attestation arrival, attestation list is queried
            # 11. Block is either received or rejected
            #    (also we can wait for more attestations or consensus may not be reached)
            # 12. We wait until the new block has been processed
            print(f"[{self.nodeId}]: Waiting for block processing / Attestation verdict", flush=True)
            while not self.consensus_reached:
                await asyncio.sleep(0.1)
            # 13. Rinse and Repeat!
            print(f"[{self.nodeId}]: ---NEXT ROUND!---", flush=True)
            self.cProt.randao.reseed(self.chain.randao_seed)
            print(f"[{self.nodeId}]: BL: RANDAO reseeded", flush=True)