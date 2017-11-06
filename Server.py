import asyncio
import playground
import random, zlib, logging
from playground import getConnector
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, STRING, UINT64, UINT16, UINT8, BUFFER, LIST
from playground.network.packet.fieldtypes.attributes import Optional
from playground.network.common.Protocol import StackingProtocol, StackingProtocolFactory, StackingTransport
import sys
import os

class BasePacketType(PacketType):
    DEFINITION_IDENTIFIER = "netsecfall2017.pls.basepacket"
    DEFINITION_VERSION = "1.0"

class PlsHello(BasePacketType):
  DEFINITION_IDENTIFIER = "netsecfall2017.pls.hello"
  DEFINITION_VERSION = "1.0"
  FIELDS = [
    ("Nonce", UINT64),
    ("Certs", LIST(BUFFER))
  ]

class PlsKeyExchange(BasePacketType):
  DEFINITION_IDENTIFIER = "netsecfall2017.pls.keyexchange"
  DEFINITION_VERSION = "1.0"
  FIELDS = [
    ("PreKey", BUFFER),
    ("NoncePlusOne", UINT64),
  ]

class PlsHandshakeDone(BasePacketType):
  DEFINITION_IDENTIFIER = "netsecfall2017.pls.handshakedone"
  DEFINITION_VERSION = "1.0"
  FIELDS = [
    ("ValidationHash", BUFFER)
  ]

class PlsData(BasePacketType):
  DEFINITION_IDENTIFIER = "netsecfall2017.pls.data"
  DEFINITION_VERSION = "1.0"
  FIELDS = [
    ("Ciphertext", BUFFER),
    ("Mac", BUFFER)
  ]

class PlsClose(BasePacketType):
  DEFINITION_IDENTIFIER = "netsecfall2017.pls.close"
  DEFINITION_VERSION = "1.0"
  FIELDS = [
    ("Error", STRING(Optional))
  ]

class PLSStackingTransport(StackingTransport):
    pass


class PLSServer(StackingProtocol):
    def __init__(self):
        self.deserializer = BasePacketType.Deserializer()
        self.transport = None


    def connection_made(self, transport):
        self.transport = transport
        packet = PlsHello()
        packet.Nonce = os.urandom(8)
        packet.Certs = []
        packs = packet.__serialize__()
        self.transport.write(packs)

    def data_received(self, data):
        self.deserializer.update(data)
        for packet in self.deserializer.nextPackets():

            if isinstance(packet, PlsHello):




