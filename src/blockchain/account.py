
from rlp import encode, decode, Serializable
from rlp.sedes import big_endian_int, Binary, binary, CountableList


from transaction import TxSerializable, TxSerializableNoSig, TxMetaNoSig, TxMeta

class AffiliateMedia(Serializable):
    fields = [
        ('add_flag', Binary.fixed_length(1, allow_empty=False)),
        ('media', binary),
        ('zkp_ownership', Binary.fixed_length(288, allow_empty=False))
    ]

class AffiliateMediaList(Serializable):
    fields = [
        ('media', CountableList(AffiliateMedia))
    ]

class Endorsement(Serializable):
    fields = [
        ('address', Binary.fixed_length(20, allow_empty=False)),
        ('value', big_endian_int)
    ]

class RegisterData(Serializable):
    fields = [
        ('id_hash', Binary.fixed_length(32, allow_empty=True)),
        ('vc_zkp', Binary.fixed_length(288, allow_empty=True))
    ]

class AccSerializable(Serializable):
    fields = [
        ('nonce', big_endian_int), # no of txs sent
        ('forwarder', big_endian_int),
        ('balance', big_endian_int),
        ('id_hash', Binary.fixed_length(32, allow_empty=True)),
        ('vc_zkp', Binary.fixed_length(288, allow_empty=True)),
        ('passive_sc', big_endian_int),
        ('active_sc', big_endian_int),
        ('effective_sc', big_endian_int),
        ('endorsed', CountableList(Endorsement)),
        ('endorsed_by', CountableList(Endorsement)),
        ('soc_media', CountableList(AffiliateMedia))
    ]

    def isVerified(self) -> bool:
        if (self.id_hash in (None, b'') or self.vc_zkp in (None, b'')):
            return False
        return True

    def isConsensusNode(self) -> bool:
        if (not self.isVerified()):
            return False
        if (not self.soc_media):
            return False
        return True

class Account():
    def __init__(self, non, bal):
        self.nonce = non
        self.forwarder = 0 # nonce for metaTX
        self.balance = bal
        self.id_hash = b''
        self.vc_zkp = b''
        self.passive_sc = 0
        self.active_sc = 0
        self.effective_sc = 0
        self.endorsed = []
        self.affiliateMedia = {}
    
    def register(self, id, zkp):
        pass
    
    def endorse(self, benef: bytes, amount: int):
        '''if (not self.id_hash):
            raise ValueError('Can\'t endorse without a valid identity.')
    
        if (self.passive_sc < amount):
            raise ValueError('Can\'t endorse, not enough social capital.')
    
        self.passive_sc -= amount
        self.endorsed.append((benef, amount))'''
        pass


    def serialize(self):
        pass
        #return encode(AccSerializable(self.nonce, self.balance, self.id_hash, self.vc_zkp, self.passive_sc, self.active_sc, self.effective_sc))
    
