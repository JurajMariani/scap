
from rlp import encode, decode, Serializable
from rlp.sedes import big_endian_int, Binary, binary, CountableList
from __future__ import annotations

class AffiliateMedia(Serializable):
    fields = [
        ('add_flag', Binary.fixed_length(1, allow_empty=False)),
        ('media', binary),
        ('zkp_ownership', Binary.fixed_length(288, allow_empty=False))
    ]

class AffiliateMediaList(Serializable):
    fields = [
        ('media', CountableList(AffiliateMedia)),
        ('validator_pub_key', Binary.fixed_length(48, allow_empty=False))
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
        # BLS key
        ('validator_pub_key', Binary.fixed_length(48, allow_empty=True)),
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
    
    def update(
        self, nonce: bool = False, forwarder: bool = False,
        balance: int = 0, id_hash: bytes = b'', vc_zkp: bytes = b'',
        passive_sc: int = 0, active_sc: int = 0, effective_sc: int = 0,
        validator_pub_key: bytes = b'', endorsed: list[Endorsement] = [],
        endorsed_by: list[Endorsement] = [], soc_media: list[AffiliateMedia] = []
    ) -> AccSerializable:
        return AccSerializable(
            self.nonce + 1 if nonce else self.nonce,
            self.forwarder + 1 if forwarder else self.forwarder,
            balance if balance else self.balance,
            id_hash if id_hash else self.id_hash,
            vc_zkp if vc_zkp else self.vc_zkp,
            passive_sc if passive_sc else self.passive_sc,
            active_sc if active_sc else self.active_sc,
            effective_sc if effective_sc else self.effective_sc,
            validator_pub_key if validator_pub_key else self.validator_pub_key,
            endorsed if endorsed else self.endorsed,
            endorsed_by if endorsed_by else self.endorsed_by,
            soc_media if soc_media else self.soc_media
        )
    
    def blank(self) -> AccSerializable:
        return AccSerializable(
            0,  # nonce
            0,  # forwarder
            0,  # balance
            b'',# id hash
            b'',# vc zkp
            0,  # passive sc
            0,  # active sc
            0,  # effective sc
            b'',# validator pub key
            [], # endorsed
            [], # endorsed by
            []  # soc media
        )

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
    
