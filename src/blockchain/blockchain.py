from block import BlockSerializable, BlockSig, BlockNoSig, Attestation, AttestationNoSig
from transaction import TxSerializable, TxSerializableNoSig, TxMeta, TxMetaNoSig
from state import StateTrie
from account import AccSerializable, RegisterData, AffiliateMediaList, AffiliateMedia
from consensus import PoSC
from eth_keys import keccak
from rlp import encode
import json
import time
import blst


class Blockchain:
    def __init__(self):
        self.chain: BlockSerializable = BlockSerializable()
        self.newBlock: BlockSerializable | None = None
        self.blockFile = None
        self.cProt = PoSC()
        self.state = StateTrie()
        self.account: AccSerializable | None = None
        self.address: bytes | None = None
        self.attestationList: list[Attestation] = []
        self.mempool: list[TxSerializable] = []
        self.slashingList = []
        self.secretKey: bytes = b''
        self.blsKey: bytes = b''
        with open('../config/config.json') as f:
            self.config = json.load(f)

    def setAccount(self, acc: AccSerializable) -> None:
        self.account = acc

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
        self.attestationList.append(at)
        return

    def generateBlock(self) -> BlockSerializable | None:
        # Check current node is supposed to be the proposer
        if not self.cProt.getLeader == self.address:
            return None
        # Check mempool has enough TXs
        if len(self.mempool) != self.config['constraints']['tx_limit']:
            return None
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
            blst.sign(self.blsKey, message).compress(),
            self.cProt.randao.get_seed(),
            self.address,
            int(time.time()),
            b''
        ).sign(self.secretKey).addTXandAttLists(txs, attList)
        # Block is ready
        # No need to verify as blocks are verified on arrival
        # Proposed blocks are sent from here to recvBlock()
        return bl
    
    def generateReassign(self, recp: bytes, value: int) -> TxMeta:
        return TxMetaNoSig(
            self.account.forwarder,
            self.address,
            recp,
            int(time.time()),
            # Value is used for SC
            value
        ).sign(self.secretKey)
    
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
                ntx = tx.update(fee=max(1, tx.fee * self.config['constraints']['replacement_tx_fee_multiplier'])).sign(self.secretKey)
                # WARNING Change type to 4, but leave SIG intact
                # Upon reaching a node type of TXs type 4 is changed to orig type
                # therefore SIG is correct
                return ntx.update(type=4)
        return None
    
    def generateTX(self, type: int, fee: int, recp: bytes, value: int, data: bytes = b'', **kwargs) -> TxSerializable | TxMeta | None:
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
                return self.generateReassign(recp, value)
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
            return None
    
        tx = TxSerializableNoSig(
            self.account.nonce,
            type,
            fee,
            self.account,
            b'\x00' * 20 if type in (1, 2, 3) else recp,
            value,
            int(time.time()),
            txData
        )
        return tx.sign(self.secretKey)

    def recvTx(self, tx: TxSerializable) -> None:
        # Reserve tmp for TX
        txn = tx 
        # If TX type is 4 (replacement), replace type with orig type
        # WARNING, ReplaceTX sig will match, See TX creation fn
        if (tx.type == 4):
            for txl in self.mempool:
                if txl.sender == tx.sender and txl.nonce == tx.nonce:
                    if tx.fee >= max(1, (txl.fee * self.config['constrants']['replacement_tx_fee_multiplier'])):
                        txn = TxSerializable(
                            tx.nonce,
                            txl.type,
                            tx.fee,
                            tx.sender,
                            tx.to,
                            tx.value,
                            tx.timestamp,
                            tx.data,
                            tx.v,
                            tx.r,
                            tx.s
                        )
                        self.mempool.remove(txl)
                        break
                    else:
                        return None
        # Verify TX on arrival
        if self.state.transaction(txn, True, False):
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
        # If this node is not the beneficiary
        if self.address:
            if self.address != bl.beneficiary:
                # If the length of attestationList is smaller than supermajority
                if len(self.attestationList < self.state.getValidatorSupermajorityLen()):
                    # Construct Attestation
                    atns = AttestationNoSig(
                        self.address,
                        bl.rebuildHash(),
                        b'\x01' if ret[1] else b'\x00'
                    )
                    at = atns.sign(self.secretKey)
                    return at
        return None
    
    def recvConsensusBlock(self):
        pass

    def gameplayLoop() -> bool:
        pass