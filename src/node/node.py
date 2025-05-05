import asyncio
from uuid import uuid4
import json
from collections import deque
from peer import Peer, Message, MessageHeader
from rlp import decode
from middleware.rpc import RPC
from middleware.middleware import Postman

# MSG:
# {
#   id:             str(nodeID),
#   type:           str(messageType),
#   subtype:        str(messageSubType),
#   sender:         tuple[nodeID, nodeIp, nodePort],
#   payload_length  int,
#   payload:        dict(RPC)
# }

class Node:
    def __init__(self, bridge: Postman, host: str, port: int, bstrapPeers: set[Peer]):
        self.node = Peer.create(str(uuid4()), host, port)
        self.peers: set[Peer] = bstrapPeers
        self.server = None
        with open('../config/config.json') as f:
            self.config = json.load(f)
        self.recent_messages = deque(maxlen=self.config['network']['max_messages_kept'])
        self.message_set = set()
        self.middleware: Postman = bridge

    async def run(self):
        asyncio.create_task(self.listenToBlockchain())
        await self.startServer()

    async def startServer(self):
        self.server = await asyncio.start_server(self.handleConnection, self.node.host, self.node.port)
        print(f"Node listening on {self.node.host}:{self.node.port}")
        await self.connectToBootstrapPeers()
        await self.server.serve_forever()

    async def listenToBlockchain(self):
        while True:
            msg = self.middleware.recv()
            if msg:
                print(f"[{self.node.getId()}][P2P] Got message from blockchain: {msg}")
                await self.send(msg, msg.type, 'x' if msg.xclusive else '', msg.sender if msg.xclusive else None, [self.node] if msg.sendback else None)
            await asyncio.sleep(0.1)

    async def start(self):
        asyncio.run(self.run())

    async def connectToBootstrapPeers(self):
        for peer in self.peers.copy():
            await self.sendMessage(self.getPeerHello(), peer)
            # Ask peer for header block
            await self.sendMessage(self.getPeerHeaderBlock(), peer)

    async def handleConnection(self):
        try:
            # Read fixed-size message header
            header_data = await self.node.reader.readexactly(MessageHeader.getSize())
            # Deserialize header
            header = decode(header_data, MessageHeader)
            # Read the payload based on payload_length from header
            payload_data = await self.node.reader.readexactly(header.getPL())
            # Deserialize RPC message
            payload = RPC.deserialize(payload_data)
            message = Message(header, payload)
            # Process message
            await self.handleMessage(message)

        except asyncio.IncompleteReadError:
            print("Connection closed before message fully received.")
        except Exception as e:
            print(f"Error while handling connection: {e}")

    def addPeer(self, peer: Peer):
        if peer not in self.peers:
            if len(self.peers) < self.config['network']['max_peers']:
                self.peers.add(peer)

    def getPeerMessage(self, type: str = ''):
        return Message.fromDict({
            'id': str(uuid4()),
            'type': type,
            'subtype': '',
            'sender': self.node,
            'payload_length': 0,
            'payload': b''
        })
    
    def getPeerHeaderBlock(self) -> Message:
        return self.getPeerMessage('BlockHead?')

    def getPeerHello(self) -> Message:
        return self.getPeerMessage('PeerHello')

    def getPeerOlleh(self) -> Message:
        return self.getPeerMessage('PeerOlleh')

    async def handleMessage(self, msg: Message):
        mmsg = msg.toDict()
        msgId = mmsg['header'].get('id')
        if self.hasSeen(msgId):
            return
        self.rememberMsg(msgId)
        print(f"[{self.port}] Received: msgid: {mmsg['header'].get('id')}")
        # Auto-add sender to peer list
        self.addPeer(mmsg['header'].get('sender'))

        # Categorize based on type
        msgType = mmsg['header'].get('type')
        # Subtype serves no purpose fo far
        # msgSubType = msg.get('subtype')
        if msgType == "PeerHello":
            await self.sendMessage(self.getPeerOlleh(), decode(mmsg['header'].get('sender')))
        elif msgType == "PeerOlleh":
            return
        elif msgType == "BlockHead?":
            # TODO
            self.middleware.send({})
        else:
            # Synchornization logic
            # 1. Flood message if not subtype exclusive (x)
            if mmsg['header']['subtype'] != 'x':
                await self.sendMessage(msg, exclude=[self.node])
            # 2. Include message details for sendback
            payload = msg.payload
            payload.sender = mmsg['header']['sender']
            # 3. Execute message on Blockchain layer
            self.middleware.send(msg.payload)

    def hasSeen(self, msg_id):
        return msg_id in self.message_set

    def rememberMsg(self, msg_id):
        if len(self.recent_messages) == self.recent_messages.maxlen:
            old = self.recent_messages.popleft()
            self.message_set.remove(old)
        self.recent_messages.append(msg_id)
        self.message_set.add(msg_id)

    async def discoverPeers(self) -> None:
        # Discover only bootstrapping peers
        # (For now)
        for p in self.peers:
            if not p.reader and not p.writer:
                p.reader, p.writer = await asyncio.open_connection(p.getHost(), p.getPort())
    
    async def closeConnections(self) -> None:
        for p in self.peers:
            if not p.reader and not p.writer:
                try:
                    p.reader.close()
                    await p.reader.wait_closed()
                    p.writer.close()
                    await p.writer.wait_closed()
                    self.peers.remove(p)
                except Exception as e:
                    print(f"[{self.node.getId()}] Something happened when closing connection to {p.getHost()}:{p.getPort()} — {e}")

    async def send(self, payload: RPC, type: str, subtype: str = '', to: Peer | None = None, exclude: list[Peer] | None = None):
        # Construct Message over the RPC
        msg_header = MessageHeader.fromDict({
            'id': str(uuid4()),
            'type': type,
            'subtype': subtype,
            'sender': self.node,
            'payload_length': payload.size(),
        })
        msg = Message(msg_header, payload)
        # Send the mesaage
        await self.sendMessage(msg, to, exclude)

    # Gossip sends messages to all peers (calls send message)
    # Gossip is a delegator
    async def gossip(self, msg: Message):
        await self.sendMessage(msg)

    async def networkSend(self, to: Peer, what: Message):
        try:
            to.writer.write(what.serialize())
            await to.writer.drain()
        except Exception as e:
            print(f"[{self.node.getId()}] Failed to send message to {to.getHost()}:{to.getPort()} — {e}")

    async def sendMessage(self, msg: Message, target: Peer | None = None, exclude: list[Peer] | None = None):
        self.rememberMsg(msg.getId())
        if target != None:
            # Send only one message (to target)
            if exclude != None and target in exclude:
                return
            else:
                await self.networkSend(target, msg)
        else:
            # Send to all peers
            for p in self.peers:
                # That are not in exclude list
                if exclude != None and p in exclude:
                    continue
                else:
                    await self.networkSend(p, msg)