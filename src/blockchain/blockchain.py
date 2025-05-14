from blockchain.block import BlockSerializable, BlockNoSig, Attestation, AttestationNoSig
from blockchain.transaction import TxSerializable, TxSerializableNoSig, TxMeta, TxMetaNoSig
from blockchain.state import StateTrie
from blockchain.account import AccSerializable, RegisterData, AffiliateMediaList, AffiliateMedia
from blockchain.consensus import PoSC
from blockchain.zkp_manager import generate
from blockchain.utils import Genesis, chainLog
from middleware.middleware import Postman
from middleware.rpc import Param, RPC
from network.peer import to_int
from chainlogger.logger import setupLogger
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
    def __init__(self, bridge: Postman, address: bytes, sk: bytes = b'', acc: AccSerializable | None = None, genesis: BlockSerializable | None = None, sts: StateTrie | None = None, loggerQueue = None, playStyle: int = 0):
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
        self.forwarder = 0
        self.passive_sc = 0
        self.waiting = False
        self.consensus_reached = False
        self.peerAddresses: set[tuple[bytes, str]] = []
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
        self.lastRoundValidatorCount = 0
        # TODO
        # For testing purposes
        self.chainlogger = setupLogger(loggerQueue)
        self.playStyle = playStyle
        self.log('INIT', 'Blockchain initialized')

    def log(self, fn, msg: str = ''):
        chainLog(self.chainlogger, self.nodeId, False, fn, msg)

    def setAccount(self, acc: AccSerializable) -> None:
        # Eiter use this fn or pass account in constructor
        # WARNING
        # When passing account in constructor, the account has to already be in the stateTrie
        self.account = acc
        if self.state.getAccount(self.address) is None:
            self.state.addAccount(acc, self.address)
        self.nonce = acc.nonce

    def getNodeIdFromRecipient(self, recp) -> str | None:
        for n in list(self.peerAddresses):
            if n[0] == recp:
                return n[1]
        return None

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
        self.log('STORE', 'Last block stored to file')

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
        self.log('recvAttestation', 'Attestation Received')
        if self.newBlock is None:
            self.attestationList.append(at)
            return
        # Validate Attestation
        # Sender is a validator
        add = at.recoverAddress()
        if not self.state.getValidator(add):
            self.log('recvAttestation', 'Discarding Attestation - sender is not a validator')
            return
        # Sender matches signature
        if not at.verifySig():
            self.slash(add)
            self.log('recvAttestation', 'Discarding Attestation - sender does not match the signature')
            return
        #print(f'[{self.nodeId}]: ATTESTATIONS: {self.attestationList}, New Block Present? {True if self.newBlock else False}')
        # Attestation should match current block or past blocks
        if at.block_hash != self.newBlock.rebuildHash():
            if at.block_hash in self.getPastBlockHashList():
                self.slash(at.sender)
                self.log('recvAttestation', 'Discarding Attestation - Attestation is not for the current block')
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
        vlaidatorLen = self.state.getValidatorSupermajorityLenFromNum(self.lastRoundValidatorCount)
        if (self.state.getValidatorLen() - len(self.newAttestationList) + more) < vlaidatorLen:
            self.log('recvAttestaton', "Consensus cannot be reached. Terminating...")
            exit(1)
        # If we don't have a supermajority yet
        elif len(self.newAttestationList) < vlaidatorLen:
            return
        # If positive supermajority is reached
        elif positive >= vlaidatorLen:
            # Attestations are stored for the next block
            self.attestationList = self.newAttestationList
            # TMP list is wiped
            self.newAttestationList = []
            # Proposed block can be safely added to the chain
            self.log('recvAttestation', 'State update started')
            self.store()
            self.lastRoundValidatorCount = self.state.getValidatorLen()
            self.state = self.newBlock.getStateAfterExecution(self.state, self.getReward())[0]
            self.log('recvAttestation', 'State update finished')
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
                    #else:
                    #    print("NOT EQUAL")
            self.log('recvAttestation', f"CONSENSUS REACHED, keeping block. ATTS: (+{positive}:-{negative})")
            self.log('recvAttestation', f'There are {self.state.getValidatorLen()} validators: {self.state.getValidators()}')
            self.consensus_reached = True
        else:
            # Negative supermajority is reached
            self.newAttestationList = []
            self.newBlock = None
            self.log('recvAttestation', f"CONSENSUS REACHED, discarding block. ATTS: (+{positive}:-{negative})")
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
            self.log('generateBlock', f'EXCEPTION: {e}')
        self.log('generateBlock', "PROPOSED BLOCK, sending")
        # Block is ready
        # No need to verify as blocks are verified on arrival
        # Proposed blocks are sent from here to recvBlock()
        # print("SENDING BLOCK")
        self.middleware.send(RPC.constructRPC('/block', [Param.constructParam('bl', 4, bl.sserialize())]))
        self.waiting = True
        return
    
    def reassignRequest(self, txm: TxMeta) -> None:
        # Validate TxMeta on arrival
        st = self.state.clone()
        if st.verifyMetaTX(txm):
            # For simplicity's sake, we accept every request
            self.generateTX(1, random.randint(1000, 2000), b'', 0, txm.sserialize(), MetaTX=True)
    
    def generateReassign(self, recp: bytes, value: int) -> TxMeta:
        return TxMetaNoSig(
            self.forwarder,
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
                medium[1].encode('utf-8'),
                medium[2]
            ))
        # print(f'[{self.nodeId}]: AFF list: {mediaList}')
        return encode(AffiliateMediaList(
            mediaList,
            validator_pub_key
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
    
    def generateTX(self, type: int, fee: int, recp: bytes, value: int, data: bytes = b'', **kwargs) -> bool:
        # Create a placeholder TX
        tmpState = self.state.clone()
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
                self.log('generateTX', 'Generating (MetaTX) forwardable assignment')
                # Construct, Sign and Send MetaTX
                txm = self.generateReassign(recp, value)
                self.forwarder += 1
                if not tmpState.verifyMetaTX(txm):
                    self.forwarder -= 1
                    return False
                resp = RPC.constructRPC('/txm', [Param.constructParam('txm', 6, txm.sserialize())])
                resp.senderId = self.getNodeIdFromRecipient(recp)
                resp.xclusive = True
                if not resp.senderId:
                    return False
                self.middleware.send(resp)
                return True
        elif type == 2:
            self.log('generateTX', 'Generating registration form')
            # Register
            # Fill data with registerData serialized
            if (('id_hash' not in kwargs.keys()) or ('vc_zkp' not in kwargs.keys())):
                return False
            if not isinstance(kwargs['id_hash'], bytes) or not isinstance(kwargs['vc_zkp'], bytes):
                return False
            txData = self.generateRegisterData(kwargs['id_hash'], kwargs['vc_zkp'])
        elif type == 3:
            self.log('generateTX', 'Generating Social Media reg. form')
            # SocMedia Register
            # Fill data with AffiliateMediaList serialized
            if (('validator_pub_key' not in kwargs.keys()) or ('media' not in kwargs.keys())):
                # print(f'[{self.nodeId}]: VAL_PUB_KEY/MEDIA missing.', flush=True)
                return False
            if not isinstance(kwargs['validator_pub_key'], bytes) or not isinstance(kwargs['media'], list) or not all(isinstance(item, tuple) and
                    len(item) == 3 and
                    isinstance(item[0], bool) and
                    isinstance(item[1], str) and
                    isinstance(item[2], bytes)
                    for item in kwargs['media']):
                return False
            txData = self.generateAffMediaList(kwargs['validator_pub_key'], kwargs['media'])
        elif type == 4:
            self.log('generateTX', 'Generating replacement TX')
            # Replacement TX
            return self.generateReplacementTx()

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
        self.log('generateTX', f'GENERATED TX ({type})')
        self.nonce += 1
        # Verify TX before sending
        ttx = tx.sign(self.secretKey.to_bytes())
        try:
            if not self.state.transaction(ttx, True, False):
                self.log('generateTX', 'Transaction discarded')
                self.nonce -= 1
                return False
        except Exception as e:
            self.log('generateTX', f"EXCEPTION: {e}")
        self.middleware.send(RPC.constructRPC('/tx', [Param.constructParam('tx', 5, ttx.sserialize())]))
        return True

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
        self.log('recvTx', 'Starting Tx validation')
        if self.state.transaction(txn, verify=True, execute=False):
            self.log('recvTx', 'Finished Tx validation')
            self.mempool.append(txn)
            self.log('recvTx', f"Successfully added TX to mempool ({txn.nonce}/{txn.sender.hex()})")
        else:
            self.log('recvTx', 'Transaction invalid, discarding')
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
        self.log('recvBlock', f"BLOCK RECEIVED from {bl.beneficiary.hex()}")
        self.newBlock = bl
        # Validate block on consensus layer
        self.log('recvBlock', 'Starting block validation')
        ret = self.cProt.attest(self.state, self.chain.rebuildHash(), self.chain.block_number, self.getReward(), self.lastRoundValidatorCount, bl)
        self.log('recvBlock', f'Finished block validation as {"IN" if not ret[1] else ""}CORRECT')
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
                self.log('recvBlock', f'[{self.nodeId}]: ISSUING {"POSITIVE" if ret[1] else "NEGATIVE"} ATTESTATION.')
                self.middleware.send(RPC.constructRPC('/attestation', [Param.constructParam('at', 7, at.sserialize())]))
        #for at in self.attestationList:
        #    if at.block_hash != self.newBlock.rebuildHash():
        #        self.recvAttestation(at)
        return None

    def pushBlock(self, bll: list[Param]):
        # Set updatingState flag to store incomming proposed blocks
        # TODO
        # print("Pushblock, GOT:", bll)
        if not bll or bll[0].value == b'':
            self.log('pushBlock', 'Genesis state in the current state')
            acc = self.state.getAccount(self.address)
            self.account = acc if acc else AccSerializable.blank()
            self.gettingReady = False
            self.lastRoundValidatorCount = self.state.getValidatorLen()
            return
        self.log('pushBlock', 'The current state is ahead of Genesis')
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
            self.lastRoundValidatorCount = self.state.getValidatorLen()
        
        acc = self.state.getAccount(self.address)
        self.account = acc if acc else AccSerializable.blank()
        self.gettingReady = False
        self.lastRoundValidatorCount = self.state.getValidatorLen()
        self.log('pushBlock', 'State updated')
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
        self.log('start', 'Starting Blockchain')
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
        self.log('Main Logic Loop', "Shutdown complete")

    async def listenToUserInput(self):
        blockwait = 0
        blockno = 0
        while not self.shutdownEvent.is_set():
            await asyncio.sleep(4)
            if self.gettingReady:
                continue
            if (len(self.peerAddresses) == 0):
                continue
            if (self.state.getAccount(self.address) is None):
                continue
            blockno = self.chain.block_number
            try:
                if self.playStyle == 0:
                    # This style only sends TXs
                    to = random.sample(self.peerAddresses, 1)[0][0]
                    self.peerAddresses = set(self.peerAddresses)
                    self.log('USER', f"Generating TX to [{to.hex()}]")
                    self.generateTX(0, random.randint(0, 1500), to, 10000)
                if self.playStyle in (1, 2, 5, 7, 8, 9, 10):
                    # This style gossips a registration Tx
                    # Then waits until it is in a block
                    # Then distributes SC
                    # Then sneds notmal Txs
                    if (self.state.getAccount(self.address).isVerified() and self.playStyle != 5):
                        if self.playStyle in (7, 8):
                            self.log('USER', 'Account has been verified!')
                            if self.playStyle == 7:
                                self.playStyle = 5
                            else:
                                #print(f'[{self.nodeId}]: Setting style from [{self.playStyle}] to [9].', flush=True)
                                self.playStyle = 9
                        else:
                            if self.playStyle != 10:
                                # Generate Soc Media TX
                                if not self.generateTX(3, random.randint(1000, 2000), b'', 0, b'', validator_pub_key=self.pubk.to_bytes(), media=[(True, 'YouTube', b'\x10' * 288)]):
                                    #print(f'[{self.nodeId}]: [genTX]: Something happened for type 3.', flush=True)
                                    continue
                                else:
                                    self.log('USER', 'Registrating Social Media')
                                    self.playStyle = 10
                            else:
                                if not self.state.getValidator(self.address):
                                    continue
                                else:
                                    self.log('USER', 'I AM A VALIDATOR :sunglasses emoji:')
                                    blockwait = blockno + 2
                                    self.playStyle = 5
                                    #print(f'[{self.nodeId}]: [genTX]: Setting style to 0 - {self.playStyle}.', flush=True)
                    elif self.playStyle == 5:
                        if blockwait == 0 or blockwait == blockno:
                            if self.account.passive_sc == 0:
                                self.playStyle = 0
                                continue
                            else:
                                # Find a validator capable of receiving SC
                                #print(f'[{self.nodeId}]: [genTX]: validators = {self.state.getValidators()}')
                                recp = random.sample(list(self.state.getValidators().keys()), 1)[0]
                                # Generate MetaTX of SC assignment
                                if not self.generateTX(1, 0, recp, random.randint(0, self.account.passive_sc)):
                                    continue
                                blockwait = self.chain.block_number + 2
                                self.log('USER', f'Endorsing {recp.hex()}')
                    else:
                        if self.playStyle not in (7, 8):
                            vczkp = await asyncio.to_thread(generate, self.nodeId + str(int(time.time())))
                            if not vczkp:
                                continue
                            # print('GENERATED ZKPPPPPP: ' + vczkp.hex(), flush=True)
                            if not self.generateTX(2, random.randint(1000, 2000), b'', 0, b'', id_hash=urandom(32), vc_zkp=vczkp):
                                continue
                            self.log('USER', 'ID hash send, waiting to get registered')
                            if self.playStyle == 1:
                                self.playStyle = 7
                            else:
                                #print(f'[{self.nodeId}]: [genTX]: Setting style to 8.', flush=True)
                                self.playStyle = 8
            except Exception as e:
                self.log('USER', f'ERROR HAPPENED: {e}')

    async def listenToNetwork(self):
        while not self.shutdownEvent.is_set():
            msg = self.middleware.recv()
            if msg:
                self.log("Network Listener", f'Call: {msg.procedure.decode("ascii")}')
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
            self.state.nodeID = self.nodeId
            self.log('Message from Network', f"Node ID set: {self.nodeId}")
        elif procCall == '/getAddress':
            resp = RPC.constructRPC('/setAddress', [Param.constructParam('addr', 3, self.address)])
            resp.senderId = msg.senderId
            self.middleware.send(resp)
        elif procCall == '/setAddress':
            if (self.address == msg.params[0].value):
                return
            self.log('Message from Network', f'Registering peer [{msg.senderId}] address [{msg.params[0].value.hex()}]')
            self.peerAddresses = set(self.peerAddresses)
            self.peerAddresses.add((msg.params[0].value, msg.senderId))
        return

    async def gameplayLoop(self):
        # print("Blockchain START")
        # print("BL: Ask for last block")
        # Ask for chain
        self.middleware.send(RPC.constructRPC('/passBlock', []))
        await asyncio.sleep(5)
        while self.gettingReady:
            await asyncio.sleep(5)
        
        self.log('GameplayLoop', f"Last block READY")
        while True:
            # -- Repeat indefinitely --
            self.consensus_reached = False
            # 1. Select a leader (every system should start with at least one registered creator)
            self.cProt.selectLeader(self.state)
            self.log('GameplayLoop', f'Leader selected ({self.cProt.getLeader().hex()})')
            # 2. If WE have been selected
            if self.cProt.getLeader() == self.address:
                self.log('GameplayLoop', "I AM LEADER!!!")
                # 2a. Generate a block
                b = None
                # 3a. Wait until WE have enough TXs in mempool
                while not self.waiting:
                    #print("Can generate block??")
                    # 4a. Generate a block
                    try:
                        self.generateBlock()
                    except Exception as e:
                        self.log('GameplayLoop', f'EXCEPTION: {e}')
                    if not self.waiting:
                        await asyncio.sleep(10)
                self.log('GameplayLoop', "Block generated")
                while self.waiting:
                    await asyncio.sleep(0.1)
                #print(f"[{self.nodeId}]: I HAVE WAITED ENOUGH!", flush=True)
                # 5a. Encapsulate the block (to be send-ready)
                # 6a. Send the encapsulated block through the network
                #     The steps above are executed in generateBlock()
            self.log('GameplayLoop', "Waiting for block & attestations")
            # 7. Wait for a new block to arrive
            # 8. When a new block arrives, /recvBlock is called,
            #    the block is validated and an attestation is sent (automatically)
            # 9. Attestations were sent automatically upon block arrival
            # 10. Upon attestation arrival, attestation list is queried
            # 11. Block is either received or rejected
            #    (also we can wait for more attestations or consensus may not be reached)
            # 12. We wait until the new block has been processed
            # print(f"[{self.nodeId}]: Waiting for block processing / Attestation verdict", flush=True)
            while not self.consensus_reached:
                await asyncio.sleep(0.1)
            # 13. Rinse and Repeat!
            self.log("---NEXT ROUND---")
            # 14. Update own account from state
            self.updateAccount()
            self.log('GameplayLoop', 'Account Updated')
            # 15. Reseed RANDAO
            self.cProt.randao.reseed(self.chain.randao_seed)
            self.log('GameplayLoop', f"RANDAO reseeded ({self.cProt.randao.get_seed().hex()})")