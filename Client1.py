#Client

import asyncio
import playground
import hashlib
import random, zlib, logging
from playground import getConnector
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, STRING, UINT64, UINT16, UINT8, BUFFER, LIST, ListFieldType
from playground.network.packet.fieldtypes.attributes import Optional
from playground.network.common.Protocol import StackingProtocol, StackingProtocolFactory, StackingTransport
from clientfactory import getIDCertsForAddr, getCertsForAddr, getRootCertsForAddr, getPrivateKeyForAddr
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


class PLSClient(StackingProtocol):

    incoming_cert = []

    def __init__(self, loop):
        print("###PLSClient init###\n")
        self.deserializer = BasePacketType.Deserializer()
        self.transport = None
        self.loop = loop

    def connection_made(self, transport):
        print("###PLSClient connection made###")
        self.transport = transport
        clienthello = PlsHello()
        clienthello.Nonce = 12345678
        idcert = getIDCertsForAddr()
        pubkey = getCertsForAddr()
        root = getRootCertsForAddr()
        clienthello.Certs = []
        clienthello.Certs.append(idcert)
        clienthello.Certs.append(pubkey)
        clienthello.Certs.append(root)
        print(clienthello.Certs[1])
        clhello = clienthello.__serialize__()
        print("\nSent the Client hello.")
        self.m = hashlib.sha1()
        self.m.update(clhello)
        self.transport.write(clhello)


    def validate(self, certificate):
        print("In Cert Validation")
        clientissuer = CipherUtil.getCertIssuer(certificate[0])
        clientsubject = CipherUtil.getCertSubject(certificate[0])
        print("Client Issuer", clientissuer)
        print("Client Subject", clientsubject)
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
        self.deserializer.update(data)
        for packet in self.deserializer.nextPackets():
            if isinstance(packet, PlsHello):
                self.incoming_cert.append(CipherUtil.getCertFromBytes(str.encode(packet.Certs[0])))
                self.incoming_cert.append(CipherUtil.getCertFromBytes(str.encode(packet.Certs[1])))
                self.incoming_cert.append(CipherUtil.getCertFromBytes(str.encode(packet.Certs[2])))
                print("\nReceived Server Hello. Trying to verify issuer...")
                if self.validate(self.incoming_cert):
                    self.m.update(packet.__serialize__())
                    print(" Server Certificate Validated. Sending Client Key Exchange!\n")
                    clientkey = PlsKeyExchange()
                    randomvalue = b'1234567887654321'
                    clientkey.NoncePlusOne = packet.Nonce + 1
                    pub_key = self.incoming_cert[0].public_key()
                    encrypted1 = pub_key.encrypt(randomvalue, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
                    print ("Encrypted String is: ",encrypted1)
                    clientkey.PreKey = encrypted1
                    clkey = clientkey.__serialize__()
                    print("Sent the Prekey to Server.")
                    self.m.update(clkey)
                    self.transport.write(clkey)

            if isinstance(packet, PlsKeyExchange):
                print("Received Server Key Exchange.")
                self.m.update(packet.__serialize__())
                serverpriv = CipherUtil.loadPrivateKeyFromPemFile("/root/keys/client/sagar-client.key")
                decrypted = serverpriv.decrypt(packet.PreKey, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(), label=None))
                print("Decrypted Pre-Master Secret: ", decrypted)
                #====================================
                #sending digest
                self.clientdigest = self.m.digest()
                print("Hash digest is: ", self.clientdigest)
                hdone = PlsHandshakeDone()
                hdone.ValidationHash = self.clientdigest
                hdone_s = hdone.__serialize__()
                print("Sent the PLS Handshake Done to server.")
                self.transport.write(hdone_s)

            if isinstance(packet, PlsHandshakeDone):
                print("\n\nReceived Server Handshake done message.")
                if (self.clientdigest == packet.ValidationHash):
                    print("Digest verification done!")




    def connection_lost(self,exc):
        self.transport.close()
        self.loop.stop()
        self.transport = None

if __name__ == "__main__":

    loop = asyncio.get_event_loop()

    Clientfactory = StackingProtocolFactory(lambda: PLSClient(loop))

    coro = playground.getConnector().create_playground_connection(Clientfactory, '20174.1.1.1', 8888)
    loop.run_until_complete(coro)
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    loop.close()

