import sys
sys.path.append('../blockchain')
from block import Block, BlockFull
from transaction import Transaction
from rlp import encode, decode

tx1 = Transaction(bytes.fromhex('ab5801a7d398351b8be11c439e05c5b3259aec9b'), bytes.fromhex('ab5801a7d398351b8be11c439e05c5b3259bbbbb'), 10, 1, 21000, 20000000000)
tx2 = Transaction(bytes.fromhex('ab5801a7d398351b8be11c439e05c5b3259aec9b'), bytes.fromhex('ab5801a7d398351b8be11c439e05c5b3259bbbbb'), 10, 1, 21000, 20000000000)
tx3 = Transaction(bytes.fromhex('ab5801a7d398351b8be11c439e05c5b3259aec9b'), bytes.fromhex('ab5801a7d398351b8be11c439e05c5b3259bbbbb'), 10, 1, 21000, 20000000000)
tx4 = Transaction(bytes.fromhex('ab5801a7d398351b8be11c439e05c5b3259aec9b'), bytes.fromhex('ab5801a7d398351b8be11c439e05c5b3259bbbbb'), 10, 1, 21000, 20000000000)
tx5 = Transaction(bytes.fromhex('ab5801a7d398351b8be11c439e05c5b3259aec9b'), bytes.fromhex('ab5801a7d398351b8be11c439e05c5b3259bbbbb'), 10, 1, 21000, 20000000000)

b = Block(bytes.fromhex('aabb1122554477663355bbaaffee4466dd22ee4f57463218654575f5dafeabbb'), bytes.fromhex('aabb1122554477663355bbaaffee4466dd22ee4f57463218654575f5dafeabbc'), bytes.fromhex('aabb1122554477663355bbaaffee4466dd22ee4f57463218654575f5dafeabbd'), bytes.fromhex('ab5801a7d398351b8be11c439e05c5b3259aec9b'), 48, 1744803526, bytes.fromhex("000000000000000000000000000000000000000000000000000000000000012a"))
b.addTransaction(tx1)
b.addTransaction(tx2)
b.addTransaction(tx3)
b.addTransaction(tx4)
b.addTransaction(tx5)

tx1.sign('4c0883a69102937d6231471b5dbb6204fe512961708279f0eecaeed7434a3d98')
tx2.sign('4c0883a69102937d6231471b5dbb6204fe512961708279f0eecaeed7434a3d98')
tx3.sign('4c0883a69102937d6231471b5dbb6204fe512961708279f0eecaeed7434a3d98')
tx4.sign('4c0883a69102937d6231471b5dbb6204fe512961708279f0eecaeed7434a3d98')

b.sign('4c0883a69102937d6231471b5dbb6204fe512961708279f0eecaeed7434a3d99')
bok = b.serialize()
print(bok)

print(b.serializeSig().hex())
print("---")
print(b.serializeNoSig().hex())
#print("Txs:")
#print(b.serializeTxs())


# f90104a0 ?
# aabb1122554477663355bbaaffee4466dd22ee4f57463218654575f5dafeabbb parent hash
# a0 ?
# aabb1122554477663355bbaaffee4466dd22ee4f57463218654575f5dafeabbc state root
# a0 ?
# 58bca9df72c99abd7e37cea3cc6c3f72b5186b1bdc6240716931247a9d15dda8 txs root
# a0 ?
# aabb1122554477663355bbaaffee4466dd22ee4f57463218654575f5dafeabbd receipts hash
# 32 block num
# 94 ?
# ab5801a7d398351b8be11c439e05c5b3259aec9b beneficiary
# 84 ?
# 67ff96c6 timestamp
# b841 ?
# 6ce33348fff98214de3e7836faabd4cf72387fd9021dec61e62f0aa41db231e26b4a10bf44037e18c93c2ee2866a22405f905650d1fa5aedc86b5c01d696e06100 sig
# a0 ?
# 000000000000000000000000000000000000000000000000000000000000002a data
# c0 txs perhaps? (the list is empty)

# header only
# f90103 ? nieco to znaci. Pri class bez tx list je to 0103, s je to 0104
# a0 ? vyera ako separator / padding
# aabb1122554477663355bbaaffee4466dd22ee4f57463218654575f5dafeabbb
# a0
# aabb1122554477663355bbaaffee4466dd22ee4f57463218654575f5dafeabbc
# a0
# 58bca9df72c99abd7e37cea3cc6c3f72b5186b1bdc6240716931247a9d15dda8
# a0
# aabb1122554477663355bbaaffee4466dd22ee4f57463218654575f5dafeabbd
# 32
# 94
# ab5801a7d398351b8be11c439e05c5b3259aec9b
# 84
# 67ff96c6
# b841
# 6ce33348fff98214de3e7836faabd4cf72387fd9021dec61e62f0aa41db231e26b4a10bf44037e18c93c2ee2866a22405f905650d1fa5aedc86b5c01d696e06100
# a0
# 000000000000000000000000000000000000000000000000000000000000002a


# '\xf9\x01\x04\xa0
# par h
# \xa0
# state h
# \xa0
# tx hash
# \xa0
# receipt r
# 2
# b num
# benef
# \x84
# timestamp
# \xb8A
# sig
# \xa0
# empty tx