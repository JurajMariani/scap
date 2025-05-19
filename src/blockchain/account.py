"""
blockchain/account.py

This module defines serializable classes for user account & Tx payload for account modification.

Example:
    You can use this as a module:
        from blockchain.account import AccountSerializable (, *)

Author: Bc. Juraj Marini, <xmaria03@stud.fit.vutbr.cz>
Date: 19/05/2025
"""

from __future__ import annotations
from rlp import encode, decode, Serializable
from rlp.sedes import big_endian_int, Binary, binary, CountableList

class AffiliateMedia(Serializable):
    """
    Serializable class, used for social media registration (to become a consensus node).

    In case a consensus node wants to no longer be a consensus node,
    it has to send a registration transaction with add_flag set to False
    """
    fields = [
        ('add_flag', Binary.fixed_length(1, allow_empty=False)),
        ('media', binary),
        ('zkp_ownership', Binary.fixed_length(288, allow_empty=False))
    ]

class AffiliateMediaList(Serializable):
    """
    Class containing a list of social media.

    The validator's public key is a necessity for randao.
    Every consensus node needs to have one.
    Therefore, it is sent in a registration transaction.
    """
    fields = [
        ('media', CountableList(AffiliateMedia)),
        ('validator_pub_key', Binary.fixed_length(64, allow_empty=False))
    ]

class Endorsement(Serializable):
    """
    Endorsement payload class.

    Address denotes the social capital beneficiary,
    value denotes the amount of social capital awarded.
    Could be found in the data filed of a TxMeta
    """
    fields = [
        ('address', Binary.fixed_length(20, allow_empty=False)),
        ('value', big_endian_int)
    ]

class RegisterData(Serializable):
    """
    A Tx data payload sent by a node that wants to register their identity on-chain in a privacy-preserving way.

    A keccak() hash is expected along with the use of a provided ZKP circuit '/src/zkp/verifyVC.zok'
    To handle the ZKP generation and verification, a high-level wrapper is implemented in '/src/blockchain/zkp_manager.py'
    """
    fields = [
        ('id_hash', Binary.fixed_length(32, allow_empty=True)),
        ('vc_zkp', Binary.fixed_length(288, allow_empty=True))
    ]

class AccSerializable(Serializable):
    """
    Class Account stores all data associated with one's account.

    Used as a basis for the STATE of the blockchain.
    Although the filed 'effective_sc' is present, it is currently unused as effective social capital
    is dynamically calculated based on the current scaling fn (and active social capital') in '/src/blockchain/consensus.py'
    The 'validator_pub_key', originally a BLS key, is replaced with a normal Ethereum key
    """
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
        ('validator_pub_key', Binary.fixed_length(64, allow_empty=True)),
        ('endorsed', CountableList(Endorsement)),
        ('endorsed_by', CountableList(Endorsement)),
        ('soc_media', CountableList(AffiliateMedia))
    ]

    def isVerified(self) -> bool:
        """
        Returns TRUE if this user is verified.
        """
        if (self.id_hash in (None, b'\x00' * 32) or self.vc_zkp in (None, b'\x00' * 288)):
            return False
        return True

    def isConsensusNode(self) -> bool:
        """
        Returns TRUE if this node is a consensus node.

        To be a consensus node means to be verified and have at least one social media associated with your account.
        """
        if (not self.isVerified()):
            return False
        if (not self.soc_media):
            return False
        return True
    
    def update(
        self, nonce: bool = False, forwarder: bool = False,
        balance: int | None = None, id_hash: bytes | None = None,
        vc_zkp: bytes | None = None, passive_sc: int | None = None,
        active_sc: int | None = None, effective_sc: int | None = None,
        validator_pub_key: bytes | None = None, endorsed: list[Endorsement] | None = None,
        endorsed_by: list[Endorsement] | None = None, soc_media: list[AffiliateMedia] | None = None
    ) -> AccSerializable:
        """
        A monolith used to update an account.

        Implemented for ease of use.
        
        NOTE:
        This method returns a new instance of 'AccSerializable' as any 'rlp.Serializable' class is immutable.
        """
        return AccSerializable(
            self.nonce + 1 if nonce else self.nonce,
            self.forwarder + 1 if forwarder else self.forwarder,
            balance if balance is not None else self.balance,
            id_hash if id_hash is not None else self.id_hash,
            vc_zkp if vc_zkp is not None else self.vc_zkp,
            passive_sc if passive_sc is not None else self.passive_sc,
            active_sc if active_sc is not None else self.active_sc,
            effective_sc if effective_sc is not None else self.effective_sc,
            validator_pub_key if validator_pub_key is not None else self.validator_pub_key,
            endorsed if endorsed is not None else self.endorsed,
            endorsed_by if endorsed_by is not None else self.endorsed_by,
            soc_media if soc_media is not None else self.soc_media
        )
    
    @classmethod
    def blank(cls) -> AccSerializable:
        """
        A constructor for an empty account.
        """
        return AccSerializable(
            0,              # nonce
            0,              # forwarder
            0,              # balance
            b'\x00' * 32,   # id hash
            b'\x00' * 288,  # vc zkp
            0,              # passive sc
            0,              # active sc
            0,              # effective sc
            b'\x00' * 64,   # validator pub key
            [],             # endorsed
            [],             # endorsed by
            []              # soc media
        )
    
    def sserialize(self) -> bytes:
        """
        Method used to serialize the class.

        Wrapper for function 'rlp.encode()'
        """
        return encode(self)
    
    @classmethod
    def ddeserialize(cls, acc: bytes) -> AccSerializable:
        """
        Deserializator.

        Wrapper for 'rlp.decode(bytes, SerializableClass)'
        """
        return decode(acc, AccSerializable)
