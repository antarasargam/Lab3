import asyncio
import playground
import random, zlib, logging
from playground import getConnector
from servercertfactory import getIDCertsForAddr, getPrivateKeyForAddr, getCertsForAddr, getRootCertsForAddr
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, STRING, UINT64, UINT16, UINT8, BUFFER, LIST
from playground.network.packet.fieldtypes.attributes import Optional
from playground.network.common.Protocol import StackingProtocol, StackingProtocolFactory, StackingTransport
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from OpenSSL import crypto

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

'''class PlsClose(BasePacketType):
  DEFINITION_IDENTIFIER = "netsecfall2017.pls.close"
  DEFINITION_VERSION = "1.0"
  FIELDS = [
    ("Error", STRING(Optional))
  ]'''

class PLSStackingTransport(StackingTransport):
    pass


class PLSServer(StackingProtocol):
    def __init__(self, loop):
        print("###PLSServer connection made###")
        self.deserializer = BasePacketType.Deserializer()
        self.transport = None
        self.loop = loop

    def connection_made(self, transport):
        print("###PLSServer connection made###")
        self.transport = transport

    def validate(self, certificate):
        cert = x509.load_pem_x509_certificate(certificate[0], default_backend())
        if cert.Issuer == "C = US, ST = MD, L = Baltimore, O = JHUNetworkSecurityFall2017, OU = PETF, CN = 20174.1.666, emailAddress = vbollap1@jhu.edu":
            cert_store = crypto.X509Store()
            cert_store.add_cert(cert)
            store_ctx = crypto.X509StoreContext(cert_store, cert)
            store_ctx.verify_certificate()
            return

    def data_received(self, data):
        print("###SSL layer data received called!###")
        self.deserializer.update(data)
        for packet in self.deserializer.nextPackets():
            if packet.DEFINITION_IDENTIFIER == "netsecfall2017.pls.hello":
                if self.validate(packet.Certs):
                    serverhello = PlsHello()
                    serverhello.Nonce = os.urandom(8)
                    idcert = getIDCertsForAddr()
                    pubkey = getCertsForAddr()
                    root = getRootCertsForAddr()
                    serverhello.Certs.append(idcert)
                    serverhello.Certs.append(pubkey)
                    serverhello.Certs.append(root)
                    packs = serverhello.__serialize__()
                    self.transport.write(packs)

    def connection_lost(self,exc):
        self.transport.close()
        self.loop.stop()
        self.transport = None


if __name__ == "__main__":

    loop = asyncio.get_event_loop()
    # Each client connection will create a new protocol instance

    #logging.getLogger().setLevel(logging.NOTSET)  # this logs *everything*
    #logging.getLogger().addHandler(logging.StreamHandler())  # logs to stderr

    coro = playground.getConnector().create_playground_server(lambda: PLSServer(loop),8888)
    server = loop.run_until_complete(coro)
    # Serve requests until Ctrl+C is pressed
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    # Close the server
    server.close()
    loop.close()

