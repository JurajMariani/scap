"""
network/node.py

This module handles network and peer logic and message forwarding to and from blockchain process.

Example:
    You can use this as a module:
        from network.node import Node

    MSG format:
    {
        id:             str(nodeID),
        type:           str(messageType),
        subtype:        str(messageSubType),
        sender:         tuple[nodeID, nodeIp, nodePort],
        payload_length  int,
        payload:        dict(RPC)
    }

Author: XXXXXXXXXX
Date: 19/05/2025
"""

import asyncio
from uuid import uuid4
import json
from collections import deque
from blockchain.utils import chainLog
from network.peer import Peer, to_int, fit_X
from network.message import Message, MessageHeader
from middleware.rpc import RPC, Param
from middleware.middleware import Postman
from chainlogger.logger import setupLogger
import random



class Node:
    def __init__(self, bridge: Postman, host: str, port: int, bstrapPeers: set[Peer], loggerQueue = None, id: str = ''):
        """
        Network node class, handling peer communication and RPC forwarding to Blockchain layer.
        """
        self.node = Peer.create(str(uuid4()) if not id else id, host, port)
        self.peers: set[Peer] = bstrapPeers
        self.peerIds: set[str] = set()
        self.activePeers: set[Peer] = set()
        self.server = None
        with open('config/config.json') as f:
            self.config = json.load(f)
        self.recent_messages = deque(maxlen=self.config['network']['max_messages_kept'])
        self.message_set = set()
        self.middleware: Postman = bridge
        self.nodelogger = setupLogger(loggerQueue)
        # SIGINT/SIGTERM stopper
        self.shutdown_event = asyncio.Event()
        self.peerMgmtTask = None

    def log(self, fn, msg: str = ''):
        chainLog(self.nodelogger, self.node.getId(), True, fn, msg)

    def getActiveIds(self) -> set[str]:
        """
        Returns node IDs of active peers.
        """
        res = set()
        for p in self.activePeers:
            res.add(p.getId())
        return res
    
    def getNonActivePeers(self) -> set[Peer]:
        """
        Returns node IDs of inactive peers.
        """
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
            self.log('Server Info', f"Listening on {self.node.getHost()}:{self.node.getPort()}")
            await self.discoverPeers()
            # Start serving in background
            server_task = asyncio.create_task(self.server.serve_forever())
            # Wait until shutdown_event is set
            await self.shutdown_event.wait()
            self.log('Server Info', "Shutting down server...")
            server_task.cancel()
            self.server.close()
            await self.server.wait_closed()
        except Exception as e:
            self.log("Server Info", f'Exception: {e}')


    async def listenToBlockchain(self):
        """
        Blockchain RPC handler.
        """
        while not self.shutdown_event.is_set():
            msg = self.middleware.recv()
            if msg and type(msg) == RPC:
                self.log('Blockchain Listener', f"Got a message {msg.procedure.decode('utf-8')}")
                # Query procedure for inter procedures
                if msg.procedure.decode('utf-8') == '/getNodeID':
                    try:
                        self.middleware.send(RPC.constructRPC('/setNodeID', [Param.constructParam('', 0, self.node.getId().encode('ascii'))]))
                    except Exception as e:
                        self.log('Blockchain Listener', f"Exception: {e}")
                    continue
                # passBlock with no active peers means this is the only node.
                # simulate empty response
                if (msg.procedure.decode('ascii') == '/passBlock' and len(self.activePeers) == 0):
                    self.middleware.send(RPC.constructRPC('/pushBlock', []))
                    continue
                # Pass own nodeID to blockchain for logging purposes
                if (msg.procedure.decode('ascii') == '/setAddress'):
                    self.log('Blockchain Listener', f'Sending PeerOlleh + [my address] to peer [{msg.senderId}]')
                    await self.send(msg, 'PeerOlleh', 'x', msg.senderId)
                # Send message through the network
                # Target the sepecified sender, if present
                if (msg.senderId is not None):
                    await self.send(msg, '', 'x' if msg.xclusive else '', msg.senderId, [self.node] if msg.senderId != '' else None)
                else:
                    # Flood the message
                    await self.send(msg, '')
            await asyncio.sleep(0.1)
        self.log('Blockchain Listener', "Shutdown initiated")

    async def peerMgmgt(self):
        """
        Attempt at PeerManagement

        CURRENTLY UNUSED, broken
        """
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
            self.log('Peer Management', "Shutting Down Peer Management")

    def start(self):
        asyncio.run(self.run())


    async def handleConnection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """
        Process incomming TCP connection
        """
        # Handler block
        while True:
            # Read fixed-size message length
            try:
                length = to_int(await reader.readexactly(6))
                # Load the whole Message
                msgRaw = await reader.readexactly(length)
            except asyncio.IncompleteReadError:
                self.log('Handling Connection', "Connection closed before message fully received.")
                break
            # Deserialize header
            try:
                msg = Message.ddeserialize(msgRaw)
                # Process message
                await self.handleMessage(msg, reader, writer)
            except Exception as e:
                self.log('Handling Connection', f"Error while handling connection: {e}")

    def addToPeerList(self, peer: Peer):
        if peer.getId() not in (self.peerIds | {self.node.getId()}):
            self.peers.add(peer)
            self.peerIds.add(peer.getId())

    def addPeer(self, peer: Peer) -> bool:
        """
        Add peer to peerlist
        """
        # add peer to all peers
        self.addToPeerList(peer)
        if peer.getId() not in (self.getActiveIds() | {self.node.getId()}):
            if len(self.activePeers) < self.config['network']['max_peers']:
                # if elligible, add peer to active peers
                self.activePeers.add(peer)
                return True
        return False


    def getPeerMessage(self, type: str = ''):
        """
        Construct a peer message - part of peer discovery.
        """
        return Message.fromDict({
            'id': str(uuid4()),
            'type': type,
            'subtype': '',
            'sender': self.node,
            'payload_length': 0,
            'payload': RPC.fromDict({'layer': 0, 'phase': 0, 'procedure': '', 'params': []})
        })

    def getPeerHello(self) -> Message:
        return self.getPeerMessage('PeerHello')

    def getPeerOlleh(self) -> Message:
        return self.getPeerMessage('PeerOlleh')

    async def handleMessage(self, msg: Message, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """
        Process message, forward to blockchain.
        """
        mmsg = msg.toDict()
        msgId = mmsg['header'].get('id')
        # If the message is a duplicate, no need to pocess
        if self.hasSeen(msgId):
            return
        self.rememberMsg(msgId)
        # Auto-add sender to peer list
        sender: Peer = mmsg['header'].get('sender')
        # Strore reader and writer of Peer
        sender.reader = reader
        sender.writer = writer
        # Set first peer hello flag
        fstPeerHello = False
        if (sender.getId() not in self.peerIds):
            fstPeerHello = True
        self.addPeer(sender)
        
        if sender.getId() == self.node.getId():
            # Store connection to self separately
            if self.node.reader is None:
                self.node.reader = reader
            if self.node.writer is None:
                self.node.writer = writer
        # Categorize message based on type
        msgType = mmsg['header'].get('type')
        # Subtype serves no purpose fo far
        if msgType == "PeerHello":
            if sender.getId() == self.node.getId():
                return
            self.log('Message Handler', f"Recvd PeerHello from peer {sender.getId()}")
            if fstPeerHello:
                self.log('Message Handler', f'Sending PeerHello to [{sender.getId()}]')
                await self.sendMessage(self.getPeerHello(), sender, [self.peers.difference({sender})])
            query = RPC.constructRPC('/getAddress', [])
            query.senderId = sender.getId()
            self.middleware.send(query)
            # Respond with courtesy
        elif msgType == "GetPeers":
            pass
        elif msgType == "SetPeers":
            pass
        elif msgType == "PeerOlleh":
            self.log('Message HAndler', f'Recvd PeerOlleh from [{sender.getId()}], how polite.')
            pass
        else:
            # Message for blockchain
            # Synchornization logic
            # 1. Flood message if not subtype exclusive (x)
            if mmsg['header']['subtype'] != 'x' and sender.getId() != self.node.getId():
                self.log('Message Handler', 'Flooding network with message')
                await self.sendMessage(msg, exclude=[self.node])
            # 2. Include message details for sendback
            payload = msg.payload
            payload.senderId = sender.getId()
            # 3. Execute message on Blockchain layer
            self.log('Message Handler', f'Delegating message {payload.procedure.decode("ascii")} to blockchain')
            self.middleware.send(payload)

    def hasSeen(self, msg_id):
        return msg_id in self.message_set

    def rememberMsg(self, msg_id):
        """
        Double execution protection.
        """
        if len(self.recent_messages) == self.recent_messages.maxlen:
            old = self.recent_messages.popleft()
            self.message_set.remove(old)
        self.recent_messages.append(msg_id)
        self.message_set.add(msg_id)

    async def discoverPeer(self, p: Peer, i: int) -> None:
        """
        Mock peer discovery.
        """
        self.log('Discover Peers', f"Opening connection {i} to {p.getHost()}:{p.getPort()}")
        if  p == self.node:
            pass
        if not p.reader and not p.writer:
            p.reader, p.writer = await asyncio.open_connection(p.getHost(), p.getPort())
            self.log('Discover Peers', f"Sending PeerHello to {p.getId()}")
            asyncio.create_task(self.handleConnection(p.reader, p.writer))
            await self.sendMessage(self.getPeerHello(), p)
        
    async def closeConnection(self, p: Peer) -> None:
        if p.writer:
            try:
                p.writer.close()
                await p.writer.wait_closed()
            except Exception as e:
                self.log('Closing Connections', f"Something happened when closing writer to {p.getHost()}:{p.getPort()} — {e}")

    async def discoverPeers(self) -> None:
        """
        Mock peer discovery.
        Peers are 'discovered' from a provided peerList at initialization.
        """
        for p in self.peers:
            self.peerIds.add(p.getId())
        self.peers = set(self.peers)
        if len(self.peers) <= self.config['network']['max_peers']:
            self.activePeers = self.peers.copy()
        else:
            self.activePeers = set(random.sample(self.peers, self.config['network']['max_peers']))
        i = 0
        self.activePeers = set(self.activePeers)
        for p in self.activePeers | {self.node}:
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
        self.log('STOP', "Server stopped")

    async def send(self, payload: RPC, type: str, subtype: str = '', to: str = '', exclude: list[Peer] | None = None):
        """
        Blockchain send handler.
        """
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
        # Send the mesaage
        await self.sendMessage(msg, recv, exclude)

    async def gossip(self, msg: Message):
        """
        Gossip sends messages to all peers (calls send message)
        Gossip is a delegator
        """
        await self.sendMessage(msg)

    async def networkSend(self, to: Peer, what: Message):
        """
        Send message through the network to the peer.
        """
        msgtype = what.header.type.decode("utf-8").rstrip("\x00")
        self.log('Network Send', f'Sending message ("{msgtype}") to {to.getId()}')
        try:
            sendBytes = what.sserialize()
            if len(sendBytes) >= 2**(6*8):
                raise Exception(f"Message too large ({len(sendBytes)}>= {2**(6*8)}).")
            to.writer.write(fit_X(len(sendBytes), 6) + sendBytes)
            await to.writer.drain()
        except Exception as e:
            self.log('NEtwork Send', f"Failed to send message to {to.getHost()}:{to.getPort()} — {e}")

    async def sendMessage(self, msg: Message, target: Peer | None = None, exclude: list[Peer] | None = None):
        """
        Low-level 'networkSend' recipient handler.
        """
        if msg.header.type != b'\x00' * 16:
            self.rememberMsg(msg.getId())
        if target != None:
            # Send only one message (to target)
            if exclude != None and target in exclude:
                return
            else:
                await self.networkSend(target, msg)
        else:
            for p in self.activePeers:
                if p.writer is None or p.writer.transport is None or p.writer.transport.is_closing():
                    self.log('Sending Message', f"Writer for {p.getId()} is invalid or closed.")
            # Send to all peers
            for p in (self.activePeers | {self.node}):
                # That are not in exclude list
                if exclude != None and p in exclude:
                    continue
                else:
                    await self.networkSend(p, msg)
