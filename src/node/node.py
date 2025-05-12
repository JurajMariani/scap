import asyncio
from uuid import uuid4
import json
from collections import deque
from node.peer import Peer, to_int, fit_X
from node.message import Message, MessageHeader
from rlp import encode, decode
from middleware.rpc import RPC, Param
from middleware.middleware import Postman
import random
import traceback

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
    def __init__(self, bridge: Postman, host: str, port: int, bstrapPeers: set[Peer], id: str = ''):
        self.node = Peer.create(str(uuid4()) if not id else id, host, port)
        self.peers: set[Peer] = bstrapPeers
        print(f'[{self.node.getId()}]: PeerList = {self.peers}', flush=True)
        self.peerIds: set[str] = set()
        self.activePeers: set[Peer] = set()
        self.server = None
        with open('config/config.json') as f:
            self.config = json.load(f)
        self.recent_messages = deque(maxlen=self.config['network']['max_messages_kept'])
        self.message_set = set()
        self.middleware: Postman = bridge
        # SIGINT/SIGTERM stopper
        self.shutdown_event = asyncio.Event()
        self.peerMgmtTask = None

    def getActiveIds(self) -> set[str]:
        res = set()
        for p in self.activePeers:
            res.add(p.getId())
        return res
    
    def getNonActivePeers(self) -> set[Peer]:
        res = set()
        for p in self.peers:
            if p not in self.activePeers:
                res.add(p)
        return res

    async def run(self):
        asyncio.create_task(self.listenToBlockchain())
        # self.peerMgmtTask = asyncio.create_task(self.peerMgmgt())
        await self.startServer()

    async def startServer(self):
        try:
            self.server = await asyncio.start_server(self.handleConnection, self.node.getHost(), self.node.getPort())
            print(f"[{self.node.getId()}]: Node listening on {self.node.getHost()}:{self.node.getPort()}", flush=True)
            await self.discoverPeers()
            # Start serving in background
            server_task = asyncio.create_task(self.server.serve_forever())
            # Wait until shutdown_event is set
            await self.shutdown_event.wait()
            print("Shutting down server...", flush=True)
            server_task.cancel()
            self.server.close()
            await self.server.wait_closed()
        except Exception as e:
            print("Exception!: ", e, flush=True)


    async def listenToBlockchain(self):
        print(f"[{self.node.getId()}]: Listening to Middleware starts", flush=True)
        while not self.shutdown_event.is_set():
            msg = self.middleware.recv()
            if msg and type(msg) == RPC:
                print(f"[{self.node.getId()}][P2P] Got message from blockchain", flush=True)
                # Query procedure for inter procedures
                if msg.procedure.decode('utf-8') == '/getNodeID':
                    try:
                        self.middleware.send(RPC.constructRPC('/setNodeID', [Param.constructParam('', 0, self.node.getId().encode('ascii'))]))
                    except Exception as e:
                        print(f"[{self.node.getId()}]: HEER IS E", e, flush=True)
                    continue
                if (msg.procedure.decode('ascii') == '/passBlock' and len(self.activePeers) == 0):
                    # print("Got no one to get blocks from.")
                    self.middleware.send(RPC.constructRPC('/pushBlock', []))
                    continue
                if (msg.procedure.decode('ascii') == '/setAddress'):
                    print(f'[{self.node.getId()}]: Sending SetADDRESS to peer [{msg.senderId}]', flush=True)
                    await self.send(msg, 'PeerOlleh', 'x', msg.senderId)
                if (msg.senderId is not None):
                    await self.send(msg, '', 'x' if msg.xclusive else '', msg.senderId, [self.node] if msg.senderId != '' else None)
                else:
                    await self.send(msg, '')
            await asyncio.sleep(0.1)
        print("Shutdown initiated", flush=True)

    async def peerMgmgt(self):
        try:
            while not self.shutdown_event.is_set():
                await asyncio.sleep(self.config['network']['active_redraw_time'])
                if len(self.activePeers) == self.config['network']['max_peers']:
                    perct = len(self.activePeers) // 5
                    # Drop 20% of active Peers
                    dropList = random.sample(self.activePeers, perct)
                    for p in dropList:
                        self.activePeers.remove(p)
                    nonactiveSet = self.getNonActivePeers()
                    addList = random.sample(nonactiveSet, perct)
                    for p in addList:
                        self.activePeers.add(p)
        except asyncio.CancelledError:
            print("Shutting Down Peer Management", flush=True)

    def start(self):
        asyncio.run(self.run())

    #async def connectToBootstrapPeers(self):
    #    await self.discoverPeers()
        #for peer in self.peers:
            
            #await self.sendMessage(self.getPeerHello(), peer)
            # Ask peer for header block
            # await self.sendMessage(self.getPeerHeaderBlock(), peer)

    async def handleConnection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        senderID = str(uuid4())
        # print(f"[{self.node.getId()}]: Handle connection from [tmp {senderID}]", flush=True)
        # Handler block
        while True:
            # Read fixed-size message length
            length = to_int(await reader.readexactly(6))
            print(f"[{self.node.getId()}]: MSG len: {length}", flush=True)
            # Load the whole Message
            msgRaw = await reader.readexactly(length)
            # Deserialize header
            try:
                msg = Message.ddeserialize(msgRaw)
                # print(f'[{self.node.getId()}]: INCOMMING MESSAGE: {msg.getId()}, ({msg.header.type})', flush=True)
                # print(f'[{self.node.getId()}]: INCOM: (tmp [{senderID}] == [{msg.header.sender.getId()}])', flush=True)
                # print("PROCESS INCOMMING MSG")
                # Process message
                await self.handleMessage(msg, reader, writer)
            except asyncio.IncompleteReadError:
                print("Connection closed before message fully received.", flush=True)
            except Exception as e:
                print(f"Error while handling connection: {e}", flush=True)

    def addToPeerList(self, peer: Peer):
        if peer.getId() not in (self.peerIds | {self.node.getId()}):
            self.peers.add(peer)
            self.peerIds.add(peer.getId())

    def addPeer(self, peer: Peer) -> bool:
        self.addToPeerList(peer)
        if peer.getId() not in (self.getActiveIds() | {self.node.getId()}):
            if len(self.activePeers) < self.config['network']['max_peers']:
                self.activePeers.add(peer)
                # print(f"[{self.node.getId()}]: ADDED peer {peer.getId()}. Peer list has {len(self.activePeers)}/{len(self.peers)} peers", flush=True)
                return True
        return False


    def getPeerMessage(self, type: str = ''):
        return Message.fromDict({
            'id': str(uuid4()),
            'type': type,
            'subtype': '',
            'sender': self.node,
            'payload_length': 0,
            'payload': RPC.fromDict({'layer': 0, 'phase': 0, 'procedure': '', 'params': []})
        })
    
    def getPeerHeaderBlock(self) -> Message:
        return self.getPeerMessage('Blocks?')

    def getPeerHello(self) -> Message:
        return self.getPeerMessage('PeerHello')

    def getPeerOlleh(self) -> Message:
        return self.getPeerMessage('PeerOlleh')

    async def handleMessage(self, msg: Message, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        mmsg = msg.toDict()
        msgId = mmsg['header'].get('id')
        if self.hasSeen(msgId):
            print(f"[{self.node.getId()}]: I have seen message {msg.getId()}", flush=True)
            return
        self.rememberMsg(msgId)
        # print(f"[{self.node.getId()}] Received: msgid: {mmsg['header'].get('id')}/'{mmsg['header']['type']}' from {mmsg['header']['sender'].getId()}", flush=True)
        # Auto-add sender to peer list
        sender: Peer = mmsg['header'].get('sender')
        # Strore reader and writer of Peer
        sender.reader = reader
        sender.writer = writer

        fstPeerHello = False
        if (sender.getId() not in self.peerIds):
            fstPeerHello = True
        self.addPeer(sender)
        # print(f'[{self.node.getId()}]: I have {len(self.activePeers)}/{len(self.peers)} peers: ({self.getActiveIds()})', flush=True)
        
        if sender.getId() == self.node.getId():
            # Store connection to self separately
            if self.node.reader is None:
                self.node.reader = reader
            if self.node.writer is None:
                self.node.writer = writer
        # Categorize message based on type
        msgType = mmsg['header'].get('type')
        # Subtype serves no purpose fo far
        # msgSubType = msg.get('subtype')
        # print(f"[{self.node.getId()}]: MSGTYPE:", msgType, flush=True)
        if msgType == "PeerHello":
            if sender.getId() == self.node.getId():
                return
            if fstPeerHello:
                await self.sendMessage(self.getPeerHello(), sender, [self.peers.difference({sender})])
            query = RPC.constructRPC('/getAddress', [])
            query.senderId = sender.getId()
            self.middleware.send(query)
            print(f"[{self.node.getId()}]: Recvd PeerHello from peer {mmsg['header']['sender'].getId()}", flush=True)
            # Respond with courtesy
            # await self.sendMessage(self.getPeerOlleh(), sender, [self.node])
        elif msgType == "GetPeers":
            pass
            #self.sendMessage(self.getPeerMessage('SetPeers', encode(list(self.peers))), sender)
        elif msgType == "SetPeers":
            #peerList = decode(msg.payload)
            #for p in peerList:
            #    self.addPeer(p)
            pass
        elif msgType == "PeerOlleh":
            # print(f"[{self.node.getId()}]: Received PeerOlleh from peer {mmsg['header']['sender'].getId()}", flush=True)
            pass
        else:
            # Synchornization logic
            # 1. Flood message if not subtype exclusive (x)
            if mmsg['header']['subtype'] != 'x' and sender.getId() != self.node.getId():
                await self.sendMessage(msg, exclude=[self.node])
            # 2. Include message details for sendback
            payload = msg.payload
            payload.senderId = sender.getId()
            # 3. Execute message on Blockchain layer
            self.middleware.send(payload)

    def hasSeen(self, msg_id):
        return msg_id in self.message_set

    def rememberMsg(self, msg_id):
        if len(self.recent_messages) == self.recent_messages.maxlen:
            old = self.recent_messages.popleft()
            self.message_set.remove(old)
        self.recent_messages.append(msg_id)
        self.message_set.add(msg_id)

    async def discoverPeer(self, p: Peer, i: int) -> None:
        print(f"[{self.node.getId()}]: Opening connection {i}", flush=True)
        if  p == self.node:
            # print("Opening to self")
            pass
        if not p.reader and not p.writer:
            p.reader, p.writer = await asyncio.open_connection(p.getHost(), p.getPort())
            print(f"[{self.node.getId()}]: Sending PeerHello to {p.getId()}", flush=True)
            asyncio.create_task(self.handleConnection(p.reader, p.writer))
            await self.sendMessage(self.getPeerHello(), p)
        
    async def closeConnection(self, p: Peer) -> None:
        if p.writer:
            try:
                p.writer.close()
                await p.writer.wait_closed()
            except Exception as e:
                print(f"[{self.node.getId()}] Something happened when closing writer to {p.getHost()}:{p.getPort()} — {e}", flush=True)

    async def discoverPeers(self) -> None:
        for p in self.peers:
            self.peerIds.add(p.getId())
        # print(f'[{self.node.getId()}]: I HAVE THESE PEERS {self.peerIds}', flush=True)
        self.peers = set(self.peers)
        if len(self.peers) <= self.config['network']['max_peers']:
            self.activePeers = self.peers.copy()
        else:
            self.activePeers = set(random.sample(self.peers, self.config['network']['max_peers']))
        i = 0
        self.activePeers = set(self.activePeers)
        # print(f'[{self.node.getId()}]: I HAVE THESE ACTIVE PEERS {self.getActiveIds()}', flush=True)
        for p in self.activePeers | {self.node}:
            print(f"[{self.node.getId()}]: Discovering peer {p.getId()}", flush=True)
            await self.discoverPeer(p, i)
            i+=1
    
    def shutdown(self) -> None:
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.stop())
        except RuntimeError:
            asyncio.run(self.stop())

    async def stop(self) -> None:
        # Set Shutdown flag
        self.shutdown_event.set()
        # Stop server
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        if self.peerMgmtTask:
            self.peerMgmtTask.cancel()
        # Close all reader/writer Streams
        for p in self.peers:
            await self.closeConnection(p)
        print("Stopped", flush=True)

    async def send(self, payload: RPC, type: str, subtype: str = '', to: str = '', exclude: list[Peer] | None = None):
        recv = None
        if to != '':
            for p in self.peers:
                if p.getId() == to:
                    recv = p
        # Construct Message over the RPC
        msg_header = MessageHeader.fromDict({
            'id': str(uuid4()),
            'type': type,
            'subtype': subtype,
            'sender': self.node,
            'payload_length': payload.size(),
        })
        msg = Message(msg_header, payload)
        # print("MSG created, ready to send")
        # Send the mesaage
        await self.sendMessage(msg, recv, exclude)

    # Gossip sends messages to all peers (calls send message)
    # Gossip is a delegator
    async def gossip(self, msg: Message):
        await self.sendMessage(msg)

    async def networkSend(self, to: Peer, what: Message):
        # print("NETWORK SEND")
        try:
            sendBytes = what.sserialize()
            if len(sendBytes) >= 2**(6*8):
                raise Exception(f"Message too large ({len(sendBytes)}>= {2**(6*8)}).")
            # print(f'[{self.node.getId()}]: Sending message[{what.getId()}] to [{to.getId()}]', flush=True)
            to.writer.write(fit_X(len(sendBytes), 6) + sendBytes)
            await to.writer.drain()
        except Exception as e:
            print(f"[{self.node.getId()}] Failed to send message to {to.getHost()}:{to.getPort()} — {e}", flush=True)

    async def sendMessage(self, msg: Message, target: Peer | None = None, exclude: list[Peer] | None = None):
        if msg.header.type != b'\x00' * 16:
            self.rememberMsg(msg.getId())
        #if (msg.header.type == fit_X("PeerOlleh", 16)):
        #    print(f"[{self.node.getId()}]: Trying to send PeerOlleh to {target.getId()}", flush=True)
        if target != None:
            # Send only one message (to target)
            if exclude != None and target in exclude:
                return
            else:
                # if (msg.header.type == fit_X("PeerOlleh", 16)):
                #     print(f"[{self.node.getId()}]: Trying to send PeerOlleh to ONE PEER", flush=True)
                await self.networkSend(target, msg)
                #if (msg.header.type == fit_X("PeerOlleh", 16)):
                #    print(f"[{self.node.getId()}]: PeerOlleh successfully sent to {target.getId()}, id: {msg.getId()}", flush=True)
        else:
            for p in self.activePeers:
                if p.writer is None or p.writer.transport is None or p.writer.transport.is_closing():
                    print(f"[{self.node.getId()}] Writer for {p.getId()} is invalid or closed.", flush=True)
            # Send to all peers
            for p in (self.activePeers | {self.node}):
                # That are not in exclude list
                if exclude != None and p in exclude:
                    continue
                else:
                    await self.networkSend(p, msg)
