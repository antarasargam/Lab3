#Client

import asyncio
import playground
import random, zlib, logging
from playground import getConnector
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, STRING, UINT64, UINT16, UINT8, BUFFER, LIST, ListFieldType
from playground.network.packet.fieldtypes.attributes import Optional
from playground.network.common.Protocol import StackingProtocol, StackingProtocolFactory, StackingTransport
from Certfactory import getIDCertsForAddr, getPrivateKeyForAddr, getPrivateKeyForAddrServer, getIDCertsForAddrServer, getCertsForAddr, getRootCertsForAddr
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
            self.incoming_cert.append(CipherUtil.getCertFromBytes(str.encode(packet.Certs[0])))
            self.incoming_cert.append(CipherUtil.getCertFromBytes(str.encode(packet.Certs[1])))
            self.incoming_cert.append(CipherUtil.getCertFromBytes(str.encode(packet.Certs[2])))
            if isinstance(packet, PlsHello):
                print("\nReceived Server Hello. Trying to verify issuer...")
                if self.validate(self.incoming_cert):
                    print(" Server Certificate Validated. Sending Client Key Exchange!\n")
                    clientkey = PlsKeyExchange()
                    randomvalue = b'1234567887654321'
                    #clientkey.PreKey = os.urandom(16)
                    clientkey.NoncePlusOne = packet.Nonce + 1
                    print ("HEREE")
                    pub_key = self.incoming_cert[0].public_key()
                    print("Public key", pub_key)
                    encrypted1 = pub_key.encrypt(randomvalue, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),algorithm=hashes.SHA1(),label=None))
                    print ("Ecrypted :",encrypted1)
                    clientkey.PreKey = encrypted1
                    #serverpriv = CipherUtil.loadPrivateKeyFromPemFile("/root/antaraprivate")
                    #print(serverpriv)
                    #decrypted = serverpriv.decrypt(encrypted1, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),algorithm=hashes.SHA1(),label=None))
                    #print("decrypted", decrypted)
                    print(clientkey)
                    self.transport.write(clientkey.__serialize__())

            if isinstance(packet, PlsKeyExchange):
                print("Received Server Key Exchange.")
                privkey = getPrivateKeyForAddr()
                priv_key = RSA.importKey(privkey)
                Data = packet.PreKey
                Dataint = int(Data)
                enc = (Dataint,)
                dec_data = priv_key.decrypt(enc)
                print("Decrypted Pre-Master Secret: ", dec_data)
                #====================================

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

