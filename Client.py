import asyncio
import playground
import random, zlib, logging
from playground import getConnector
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, STRING, UINT64, UINT16, UINT8, BUFFER, LIST, ListFieldType
from playground.network.packet.fieldtypes.attributes import Optional
from playground.network.common.Protocol import StackingProtocol, StackingProtocolFactory, StackingTransport
from clientcertfactory import getCertsForAddr, getPrivateKeyForAddr, getIDCertsForAddr, getRootCertsForAddr
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from OpenSSL import crypto
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Util import asn1
from base64 import b64decode


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
        clhello = clienthello.__serialize__()
        print("\nSent the Client hello.")
        self.transport.write(clhello)


    def validate(self, certificate0, certificate1, certificate2):
        #cert = x509.load_pem_x509_certificate(str.encode(certificate[0]), default_backend())
        cert1 = crypto.load_certificate(crypto.FILETYPE_PEM, certificate0)
        clientIssuer = str(cert1.get_issuer())
        IntermediateIssuer = "<X509Name object '/C=US/ST=MD/L=Baltimore/O=JHUNetworkSecurityFall2017/OU=PETF/CN=20174.1.666/emailAddress=vbollap1@jhu.edu'>"
        if clientIssuer == IntermediateIssuer:
            print("Issuer verified.")
            try:
                cert_store = crypto.X509Store()
                certpub = crypto.load_certificate(crypto.FILETYPE_PEM, certificate1)
                certroot = crypto.load_certificate(crypto.FILETYPE_PEM, certificate2)
                cert_store.add_cert(certpub)
                cert_store.add_cert(certroot)
                print("Client certificates added to the trust store.")
                store_ctx = crypto.X509StoreContext(cert_store, cert1)
                store_ctx.verify_certificate()
                return True
            except Exception as e:
                print(e)
                return True

    def data_received(self, data):
        self.deserializer.update(data)
        for packet in self.deserializer.nextPackets():
            if isinstance(packet, PlsHello):
                print("\nReceived Server Hello. Trying to verify issuer...")
                if self.validate(packet.Certs[0], packet.Certs[1], packet.Certs[2]):
                    print(" Server Certificate Validated. Sending Client Key Exchange!\n")
                    clientkey = PlsKeyExchange()
                    randomvalue = 1234567887654321
                    #clientkey.PreKey = os.urandom(16)
                    clientkey.NoncePlusOne = packet.Nonce + 1
                    cert1 = crypto.load_certificate(crypto.FILETYPE_PEM, packet.Certs[0])
                    k = cert1.get_pubkey()
                    bio = crypto._new_mem_buf()
                    rsa = crypto._lib.EVP_PKEY_get1_RSA(k._pkey)
                    crypto._lib.PEM_write_bio_RSAPublicKey(bio, rsa)
                    s = crypto._bio_to_string(bio)
                    pubkey1 = s.decode()
                    pubkey = RSA.importKey(pubkey1)
                    pub_key = pubkey.publickey()
                    enc_data = pub_key.encrypt(randomvalue, packet.Nonce + 1)
                    enc1 = str(enc_data[0])
                    enc2 = enc1.encode()
                    clientkey.PreKey = enc2
                    ckey = clientkey.__serialize__()
                    print("\nSent the Client Key Ecchange.\n\n")
                    self.transport.write(ckey)

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

