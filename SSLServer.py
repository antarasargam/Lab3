import asyncio
import playground
import hashlib
import random, zlib, logging
from playground import getConnector
from Certfactory import getCertsForAddr, getServerPrivateKeyForAddr, getServerIDCertsForAddr, getRootCertsForAddr
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, STRING, UINT64, UINT16, UINT8, BUFFER, LIST
from playground.network.packet.fieldtypes.attributes import Optional
from playground.network.common.Protocol import StackingProtocol, StackingProtocolFactory, StackingTransport
import os
from playground.common import CipherUtil
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives import hashes
import hashlib

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

class PlsClose(BasePacketType):
  DEFINITION_IDENTIFIER = "netsecfall2017.pls.close"
  DEFINITION_VERSION = "1.0"
  FIELDS = [
    ("Error", STRING(Optional))
  ]

class PLSServerStackingTransport(StackingTransport):

    def __init__(self,protocol,transport):
        self.protocol = protocol
        self.transport = transport
        self.exc = None
        super().__init__(self.transport)


    def write(self, data):
        self.protocol.write(data)

    def close(self):
        self.protocol.close()

    def connection_lost(self):
        self.protocol.connection_lost(self.exc)

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
                    idcert = getServerIDCertsForAddr()
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
                serverpriv = CipherUtil.loadPrivateKeyFromPemFile("/home/prashanth/netsec/prashanth.key")
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

            if isinstance(packet, PlsData):
                print("=====================Recieved Data Packet from PLSClient======================")
                self.ctr = 0
                if self.mac_verification_engine(packet.Ciphertext, packet.Mac):
                    print("=====================Pls Client Verification Successful. Decrypting=============")
                    DecryptedPacket = self.decryption_engine(packet.Ciphertext)
                    print("=======================Decryption DONE! =======Sending to HigherLayer===========")
                    self.higherProtocol().data_received(DecryptedPacket)

                    self.ctr = 0

                else:
                    self.ctr += 1

                    if self.ctr != 5:
                        print("Verification Failed. Try Again. Failed {}").format(self.ctr)

                    else:
                        print("Verification failed 5 times. Killing Connection and Sending PlsClose.")
                        self.ctr = 0
                        # Creating and Sending PlsClose
                        Close = PlsClose()
                        Close.Error = "Closing Connection due to 5 Verification failures. Aggrresive Close"
                        serializeClose = Close.__serialize__()
                        self.transport.write(serializeClose)
                        self.transport.close()

            if isinstance(packet, PlsClose):
                print("==================Received PlsClose from Client======================== ")
                self.connection_lost(packet.Error)
                self.transport.close()


    def key_generator(self):
        print("\n\nIn key_generator")
        self.block0 = hashlib.sha1()
        self.block0.update(b"PLS1.0")
        self.block0.update(str(self.nc).encode())
        print("NC string", str(self.nc).encode())
        self.block0.update(str(self.ns).encode())
        print("NS string", str(self.ns).encode())
        self.block0.update(str(self.pkc).encode())
        print("PKC string", str(self.pkc).encode())
        self.block0.update(str(self.pks).encode())
        print("PKS string", str(self.pks).encode())
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
        print("Block 0 digest decoded is: ", self.block0_digest.hex())
        print("Block 1 digest decoded is: ", block1digest.hex())
        print("Block 2 digest decoded is: ", block2digest.hex())
        print("Block 3 digest decoded is: ", block3digest.hex())
        print("Block 4 digest decoded is: ", block4digest.hex())


        concatenated = (self.block0_digest.hex() + block1digest.hex() + block2digest.hex() + block3digest.hex() + block4digest.hex())
        #print("Concatenated string is: ", concatenated)

        #Converting concatenated hash string to binary for breaking into 128 bits key.
        dec = int(concatenated, 16)
        binary = bin(dec)[2:]
        print(concatenated, "\nIn Binary =", binary, "\n")

        #Breaking Binary into keys

        print("EKC: ", binary[0:128])
        self.EKC = binary[0:128]
        print("EKS: ", binary[128:256])
        self.EKS = binary[128:256]
        print("IVC: ", binary[256:384])
        self.IVC = binary[256:384]
        print("IVS: ", binary[384:512])
        self.IVS = binary[384:512]
        print("MKC: ", binary[512:640])
        self.MKC = binary[512:640]
        print("MKS: ", binary[640:768])
        self.MKS = binary[640:768]


    def encryption_engine(self, plaintext):
        print("======================PLS Server Encrypting Data from Upper Layer====================")
        MakeCipher = CipherUtil.CIPHER_AES128_CBC(self.EKS, self.IVS)
        Ciphertext = MakeCipher.encrypt(plaintext)
        print("===============Encrypted that Data. Calling MAC Engine========================")
        self.mac_engine(Ciphertext)

    def decryption_engine(self, ReceivedCiphertext):
        print("======================PLS Server Decrypting Data from Server====================")
        MakePlaintext = CipherUtil.CIPHER_AES128_CBC(self.EKC, self.IVC)
        Plaintext = MakePlaintext.decrypt(ReceivedCiphertext)
        return Plaintext

    def mac_engine(self, ciphertext):
        print("======================PLS Server Inside Mac Engine====================")
        makehmac = CipherUtil.MAC_HMAC_SHA1(self.MKS)
        mac = makehmac.mac(ciphertext)

        #Creating PLS Data Packet and Writing Down to PEEP
        print("=================== Writing Data down to PEEP from Application inside PlsServer================\n")
        serverdata = PlsData()
        serverdata.Ciphertext = ciphertext
        serverdata.Mac = mac
        serializeddata = serverdata.__serialize__()
        self.transport.write(serializeddata)


    def mac_verification_engine(self, ReceivedCiphertext, ReceivedMac):
        print("======================PLS Server Inside Mac Verification Engine====================")
        VerificationCheck = CipherUtil.MAC_HMAC_SHA1(self.MKC)

        return VerificationCheck.verifyMac(ReceivedCiphertext,ReceivedMac)


    def write(self, data):
        self.encryption_engine(data)

    def close(self):

        print ("+++++++++++++++++++++++++++++A Close has been called from higher layer. Sending PlsClose now++++++++++++++++++++++++++")

        Close = PlsClose()
        Close.Error = "A close was called. This means that Server Application is done with all transmissions"
        serializeClose = Close.__serialize__()
        self.transport.write(serializeClose)




    def connection_lost(self,exc):
        print("======================PLS Server Connection Lost Called====================")
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
