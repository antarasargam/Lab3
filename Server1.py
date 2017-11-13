#Server

import asyncio
import playground
import hashlib
import random, zlib, logging
from playground import getConnector
from serverfactory import getPrivateKeyForAddr, getRootCertsForAddr, getCertsForAddr, getIDCertsForAddr
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, STRING, UINT64, UINT16, UINT8, BUFFER, LIST
from playground.network.packet.fieldtypes.attributes import Optional
from playground.network.common.Protocol import StackingProtocol, StackingProtocolFactory, StackingTransport
import os
from playground.common import CipherUtil
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives import hashes

class BasePacketType(PacketType):
    DEFINITION_IDENTIFIER = "netsecfall2017.pls.basepacket"
    DEFINITION_VERSION = "1.0"

class PlsHello(BasePacketType):
  DEFINITION_IDENTIFIER = "netsecfall2017.pls.hello"
  DEFINITION_VERSION = "1.0"
  FIELDS = [
    ("Nonce", UINT64),
    ("Certs", LIST(STRING))
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

    incoming_cert = []

    def __init__(self, loop):
        print("###PLSServer connection made###")
        self.deserializer = BasePacketType.Deserializer()
        self.transport = None
        self.loop = loop

    def connection_made(self, transport):
        print("###PLSServer connection made###")
        self.transport = transport

    def validate(self, certificate):
        print("In Cert Validation")
        clientissuer = CipherUtil.getCertIssuer(certificate[0])
        clientsubject = CipherUtil.getCertSubject(certificate[0])
        IntermediateIssuer = {'emailAddress': 'vbollap1@jhu.edu', 'stateOrProvinceName': 'MD', 'countryName': 'US', 'commonName': '20174.1.666', 'organizationalUnitName': 'PETF', 'localityName': 'Baltimore', 'organizationName': 'JHUNetworkSecurityFall2017'}
        if clientissuer == IntermediateIssuer:
                print("Issuer verified.")
                Certificate_result = CipherUtil.ValidateCertChainSigs(certificate)
                if Certificate_result:
                    return True
                else:
                    print ("Certificate Validation Failed")
                    return False

    def data_received(self, data):
        print("###SSL layer data received called!###")
        self.deserializer.update(data)
        for packet in self.deserializer.nextPackets():
            #print(packet.Certs[0], packet.Certs[1], packet.Certs[2])
            if isinstance(packet, PlsHello):
                self.incoming_cert.append(CipherUtil.getCertFromBytes(str.encode(packet.Certs[0])))
                self.incoming_cert.append(CipherUtil.getCertFromBytes(str.encode(packet.Certs[1])))
                self.incoming_cert.append(CipherUtil.getCertFromBytes(str.encode(packet.Certs[2])))
                print("\nReceived Client Hello packet. Trying to verify issuer...")
                #print(packet.Certs)
                if self.validate(self.incoming_cert):
                    self.nc = packet.Nonce
                    self.m = hashlib.sha1()
                    self.m.update(packet.__serialize__())
                    print("Certificate Validated. Sending Server hello!\n")
                    self.clientnonce = packet.Nonce
                    serverhello = PlsHello()
                    serverhello.Nonce = 12345678
                    self.ns = serverhello.Nonce
                    idcert = getIDCertsForAddr()
                    pubkey = getCertsForAddr()
                    root = getRootCertsForAddr()
                    serverhello.Certs = []
                    serverhello.Certs.append(idcert)
                    serverhello.Certs.append(pubkey)
                    serverhello.Certs.append(root)
                    srvhello = serverhello.__serialize__()
                    print("Sent Server Hello!\n")
                    self.m.update(srvhello)
                    self.transport.write(srvhello)

            if isinstance(packet, PlsKeyExchange):
                print("Received Client Key Exchange. Server Server Keys\n\n")
                self.m.update(packet.__serialize__())
                serverpriv = CipherUtil.loadPrivateKeyFromPemFile("/root/keys/server/sagar-server.key")
                decrypted = serverpriv.decrypt(packet.PreKey, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(), label=None))
                print("Decrypted Pre-Master Secret: ", decrypted)
                self.pkc = decrypted.decode()
                #====================================
                #Creating Server Pre-Master
                serverkey = PlsKeyExchange()
                randomvalue = b'1234567887654321'
                self.pks = randomvalue.decode()
                serverkey.NoncePlusOne = self.clientnonce + 1
                pub_key = self.incoming_cert[0].public_key()
                encrypted1 = pub_key.encrypt(randomvalue, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(), label=None))
                print("Encrypted String is: ", encrypted1)
                serverkey.PreKey = encrypted1
                skey = serverkey.__serialize__()
                print("Sent the Prekey to Client.\n\n")
                self.m.update(skey)
                self.transport.write(skey)

            if isinstance(packet, PlsHandshakeDone):
                print("Received Client Handshake done message.")
                clientdigest = packet.ValidationHash
                serverdigest = self.m.digest()
                print("Hash digest is: ", serverdigest)
                hdone = PlsHandshakeDone()
                hdone.ValidationHash = serverdigest
                if (serverdigest == clientdigest):
                    print("Digest verification done!")
                    self.key_generator()
                hdone_s = hdone.__serialize__()
                self.transport.write(hdone_s)


    def key_generator(self):
        print("\n\nIn key_generator")
        self.block0 = hashlib.sha1()
        self.block0.update(b"PLS1.0")
        self.block0.update(str(self.nc).encode())
        self.block0.update(str(self.ns).encode())
        self.block0.update(str(self.pkc).encode())
        self.block0.update(str(self.pks).encode())
        self.block0_digest = self.block0.digest()
        print("Block 0 digest is: ", self.block0_digest)
        block1 = hashlib.sha1()
        block1.update(self.block0_digest)
        block1digest =  block1.digest()
        print("Block 1 digest is: ", block1digest)
        block2 = hashlib.sha1()
        block2.update(block1digest)
        block2digest =  block2.digest()
        print("Block 2 digest is: ", block2digest)
        block3 = hashlib.sha1()
        block3.update(block2digest)
        block3digest =  block3.digest()
        print("Block 3 digest is: ", block3digest)
        block4 = hashlib.sha1()
        block4.update(block3digest)
        block4digest =  block4.digest()
        print("Block 4 digest is: ", block4digest)
        print(type(block1digest))
        print("Block 1 digest decoded is: ", block1digest.hex())

        concatenated = (self.block0_digest.decode() + block1digest.decode() + block2digest.decode() + block3digest.decode() + block4digest.decode())
        print("Concatenated string is: ", concatenated)


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

