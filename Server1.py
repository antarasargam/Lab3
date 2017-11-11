#Server

import asyncio
import playground
import random, zlib, logging
from playground import getConnector
from Certfactory import getIDCertsForAddr, getPrivateKeyForAddr, getPrivateKeyForAddrServer, getIDCertsForAddrServer, getCertsForAddr, getRootCertsForAddr
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
        print ("In Server Data Received")
        print("###SSL layer data received called!###")
        self.deserializer.update(data)
        for packet in self.deserializer.nextPackets():
            #print(packet.Certs[0], packet.Certs[1], packet.Certs[2])
            self.incoming_cert.append(CipherUtil.getCertFromBytes(str.encode(packet.Certs[0])))
            self.incoming_cert.append(CipherUtil.getCertFromBytes(str.encode(packet.Certs[1])))
            self.incoming_cert.append(CipherUtil.getCertFromBytes(str.encode(packet.Certs[2])))
            if isinstance(packet, PlsHello):
                print("\nReceived Client Hello packet. Trying to verify issuer...")
                #print(packet.Certs)
                if self.validate(self.incoming_cert):
                    print("Certificate Validated. Sending Server hello!\n")
                    self.clientnonce = packet.Nonce
                    serverhello = PlsHello()
                    serverhello.Nonce = 12345678
                    idcert = getIDCertsForAddrServer()
                    pubkey = getCertsForAddr()
                    root = getRootCertsForAddr()
                    serverhello.Certs = []
                    serverhello.Certs.append(idcert)
                    serverhello.Certs.append(pubkey)
                    serverhello.Certs.append(root)
                    srvhello = serverhello.__serialize__()
                    print("Sent Server Hello!\n")
                    self.transport.write(srvhello)

            if isinstance(packet, PlsKeyExchange):
                print("Received Client Key Exchange.")
                serverpriv = CipherUtil.loadPrivateKeyFromPemFile("/root/antaraprivate")
                print(serverpriv)
                decrypted = serverpriv.decrypt(packet.PreKey, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),algorithm=hashes.SHA1(), label=None))
                print("Decrypted Pre-Master Secret: ", decrypted)
                #====================================
                #Creating Server Pre-Master
                serverkey = PlsKeyExchange()
                randomvalue = 1234567887659999
                serverkey.NoncePlusOne = self.clientnonce + 1
                cert1 = crypto.load_certificate(crypto.FILETYPE_PEM, self.certificate[0])
                k = cert1.get_pubkey()
                bio = crypto._new_mem_buf()
                rsa = crypto._lib.EVP_PKEY_get1_RSA(k._pkey)
                crypto._lib.PEM_write_bio_RSAPublicKey(bio, rsa)
                s = crypto._bio_to_string(bio)
                pubkey1 = s.decode()
                pubkey = RSA.importKey(pubkey1)
                pub_key = pubkey.publickey()
                enc_data = pub_key.encrypt(randomvalue, self.clientnonce + 1)
                enc1 = str(enc_data[0])
                enc2 = enc1.encode()
                serverkey.PreKey = enc2
                ckey = serverkey.__serialize__()
                print("\nSent the Server Key Exchange.")
                self.transport.write(ckey)

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

