#Client

import logging, os
import hashlib, struct
from netsec_2017.Lab_3.packets import PlsHello, PlsData, PlsHandshakeDone, PlsKeyExchange, PlsClose
from playground.network.common.Protocol import StackingProtocol, StackingProtocolFactory, StackingTransport
from .clientfactory import getIDCertsForAddr, getCertsForAddr, getRootCertsForAddr, getPrivateKeyForAddr
from playground.common import CipherUtil
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives import hashes
from netsec_2017.Lab_3.packets import BasePacketType

from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.ciphers.modes import CTR
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.backends import default_backend
backend = default_backend()


class CIPHER_AES128_CTR(object):
    def __init__(self, key, iv):
        cipher = Cipher(AES(key), CTR(iv), backend)
        self.encrypter = cipher.encryptor()
        self.decrypter = cipher.decryptor()
        self.block_size = 128

    def encrypt(self, data):
        padder = PKCS7(self.block_size).padder()
        paddedData = padder.update(data) + padder.finalize()
        return self.encrypter.update(paddedData) + self.encrypter.finalize()

    def decrypt(self, data):
        paddedData = self.decrypter.update(data) + self.encrypter.finalize()
        unpadder = PKCS7(self.block_size).unpadder()
        return unpadder.update(paddedData) + unpadder.finalize()

class PLSStackingTransport(StackingTransport):

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


class PLSClient(StackingProtocol):

    incoming_cert = []

    def __init__(self):
        print("###PLSClient init###\n")
        self.deserializer = BasePacketType.Deserializer()
        self.transport = None
        #self.loop = loop

    def utf8len(self, s):
        return len(s.encode('utf-8'))

    def connection_made(self, transport):
        print("###PLSClient connection made###")
        self.transport = transport
        clienthello = PlsHello()
        clienthello.Nonce = int.from_bytes(os.urandom(8), byteorder='big') #12345678
        print("Client Nonce", clienthello.Nonce)
        self.nc = clienthello.Nonce
        idcert = getIDCertsForAddr()
        pubkey = getCertsForAddr()
        root = getRootCertsForAddr()
        clienthello.Certs = []
        clienthello.Certs.append(idcert)
        clienthello.Certs.append(pubkey)
        clienthello.Certs.append(root)
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
                    randomvalue = os.urandom(16) #b'1234567887654321'
                    print(type(randomvalue))
                    self.pkc = int.from_bytes(randomvalue, byteorder='big')
                    clientkey.NoncePlusOne = packet.Nonce + 1
                    self.ns = packet.Nonce
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
                self.pks = int.from_bytes(decrypted, byteorder='big')
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
                    self.key_generator()
                    plstransport = PLSStackingTransport(self, self.transport)
                    higherTransport = StackingTransport(plstransport)
                    self.higherProtocol().connection_made(higherTransport)

            if isinstance(packet, PlsData):
                print("=====================Recieved Data Packet from PLSServer ======================")
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
                        # Creating and Sending PlsClose
                        self.ctr = 0
                        Close = PlsClose()
                        #Close.Error = "Closing Connection due to 5 Verification failures. Aggressive Close."
                        serializeClose = Close.__serialize__()
                        self.transport.write(serializeClose)
                        self.transport.close()

            if isinstance(packet, PlsClose):
                print("==================Received PlsClose from Server======================== ")
                #self.connection_lost(self)
                self.transport.close()


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
        block1digest = block1.digest()
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
        print("Block 0 digest decoded is: ", self.block0_digest.hex())
        print("Block 1 digest decoded is: ", block1digest.hex())
        print("Block 2 digest decoded is: ", block2digest.hex())
        print("Block 1 digest decoded is: ", block3digest.hex())
        print("Block 1 digest decoded is: ", block4digest.hex())

        concatenated = (self.block0_digest + block1digest + block2digest + block3digest + block4digest).hex()
        print("Concatenated string is: ", concatenated)
        print("Concatenated string size is: ", self.utf8len(concatenated),"bytes")
        binary_string = bin(int(concatenated, 16))[2:]
        print("Value of concatenated string in bits is: ", binary_string)

        self.ekc = binary_string[:128]
        self.eks = binary_string[128:256]
        self.ivc = binary_string[256:384]
        self.ivs = binary_string[384:512]
        self.mkc = binary_string[512:640]
        self.mks = binary_string[640:768]
        print("Value of Ekc is: ", self.ekc)
        print("Value of Eks is: ", self.eks)
        print("Value of ivc is: ", self.ivc)
        print("Value of ivs is: ", self.ivs)
        print("Value of mkc is: ", self.mkc)
        print("Value of mks is: ", self.mks)
        self.ekc = bytes(int(self.ekc[i: i + 8], 2) for i in range(0, len(self.ekc), 8))
        self.eks = bytes(int(self.eks[i: i + 8], 2) for i in range(0, len(self.eks), 8))
        self.ivc = bytes(int(self.ivc[i: i + 8], 2) for i in range(0, len(self.ivc), 8))
        self.ivs = bytes(int(self.ivs[i: i + 8], 2) for i in range(0, len(self.ivs), 8))
        self.mkc = bytes(int(self.mkc[i: i + 8], 2) for i in range(0, len(self.mkc), 8))
        self.mks = bytes(int(self.mks[i: i + 8], 2) for i in range(0, len(self.mks), 8))


    def encryption_engine(self, plaintext):
        print("======================PLS Client Encrypting Data from Upper Layer====================")
        MakeCipher = CIPHER_AES128_CTR(self.ekc, self.ivc)
        Ciphertext = MakeCipher.encrypt(plaintext)
        print("===============Encrypted that Data. Calling MAC Engine========================")
        self.mac_engine(Ciphertext)

    def decryption_engine(self, ReceivedCiphertext):
        print("======================PLS Client Decrypting Data from Server====================")
        MakePlaintext = CIPHER_AES128_CTR(self.eks, self.ivs)
        Plaintext = MakePlaintext.decrypt(ReceivedCiphertext)
        return Plaintext

    def mac_engine(self, ciphertext):
        print("======================PLS Client Inside Mac Engine====================")
        makehmac = CipherUtil.MAC_HMAC_SHA1(self.mkc)
        mac = makehmac.mac(ciphertext)

        # Creating PLS Data Packet and Writing down PEEP
        print("=================== Writing Data down to PEEP from Application inside PlsClient================\n")
        serverdata = PlsData()
        serverdata.Ciphertext = ciphertext
        serverdata.Mac = mac
        serializeddata = serverdata.__serialize__()
        self.transport.write(serializeddata)

    def mac_verification_engine(self, ReceivedCiphertext, ReceivedMac):
        print("======================PLS Client Inside Mac Verification Engine====================")
        VerificationCheck = CipherUtil.MAC_HMAC_SHA1(self.mks)

        return VerificationCheck.verifyMac(ReceivedCiphertext, ReceivedMac)

    def write(self, data):
        self.encryption_engine(data)

    def close(self):
        print(
            "+++++++++++++++++++++++++++++A Close has been called from higher layer. Sending PlsClose now++++++++++++++++++++++++++")

        Close = PlsClose()
        #Close.Error = "A close was called. This means that Client Application is done with all transmissions"
        serializeClose = Close.__serialize__()
        self.transport.write(serializeClose)

    def connection_lost(self,exc):
        self.transport.close()
        #self.stop()
        self.transport = None

logging.getLogger().setLevel(logging.NOTSET)
logging.getLogger().addHandler(logging.StreamHandler())


#Clientfactorypls = StackingProtocolFactory(lambda: PLSClient())

'''if __name__ == "__main__":

    loop = asyncio.get_event_loop()

    Clientfactory = StackingProtocolFactory(lambda: PLSClient(loop))

    coro = playground.getConnector().create_playground_connection(Clientfactory, '20174.1.1.1', 8888)
    loop.run_until_complete(coro)
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    loop.close()'''

