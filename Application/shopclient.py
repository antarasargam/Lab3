from netsec_2017.Lab_3.packets import RequestItem, RequestMoney, RequestToBuy, FinishTransaction, SendItem, SendMoney
from netsec_2017.Lab_3.PLS.client import PLSClient, PLSStackingTransport
from netsec_2017.Lab_3.peepTCP import PeepClientTransport, PEEPClient
import asyncio
import playground
import random, logging
from playground import getConnector
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, STRING, UINT16, UINT8, BUFFER
from playground.network.packet.fieldtypes.attributes import Optional
from playground.network.common.Protocol import StackingProtocol, StackingProtocolFactory, StackingTransport
import zlib
import sys


class ShopClientProtocol(asyncio.Protocol):

    clientstate = 0

    def __init__(self, loop):
        #self.loop = loop
        self.transport = None
        self.loop = loop
        self.deserializer = PacketType.Deserializer()

    def connection_made(self, transport):
        print("ShopClient connection_made is called\n")
        self.transport = transport
        # PACKET 1 - Request to Buy packet
        startbuy = RequestToBuy()
        print("Sending Request to Buy")
        self.transport.write(startbuy.__serialize__())

    def data_received(self, data):
        print("ShopClient Data_received is called")
        self.deserializer.update(data)
        #print(data)
        for pkt in self.deserializer.nextPackets():
            #print("Client <------------{}------------- Server".format(pkt.DEFINITION_IDENTIFIER))

            if isinstance(pkt, RequestItem) and self.clientstate == 0:
                self.clientstate += 1

                # PACKET 3 - Send Item packet
                item = "Butter"
                response = SendItem()
                response.Item = item

                print("Sent SendItem")
                self.transport.write(response.__serialize__())


            elif isinstance(pkt, RequestMoney) and self.clientstate == 1:
                self.clientstate += 1

                # PACKET 5 - Send Money packet
                response = SendMoney()

                response.Cash = pkt.Amount

                print("Sent SendMoney")
                self.transport.write(response.__serialize__())

            elif isinstance(pkt, FinishTransaction) and self.clientstate == 2:

                self.transport.close()

            else:
                print(pkt.Type)
                print("Client Received Incorrect Packet. Closing Connection. Try Again!")
                self.transport.close()


    def connection_lost(self,exc):
        print('\nThe ShopServer sent a connection close to the client')
        self.transport.close()
        self.transport = None
        self.loop.stop()


class initiate():
    #1
    def __init__(self, loop):
        self.loop = loop

    def send_first_packet(self):
        self.loop = loop
        return ShopClientProtocol(loop)

if __name__ == "__main__":

    loop = asyncio.get_event_loop()

    #logging.getLogger().setLevel(logging.NOTSET)  # this logs *everything*
    #logging.getLogger().addHandler(logging.StreamHandler())  # logs to stderr

    f = StackingProtocolFactory(lambda:PLSClient(), lambda: PEEPClient(loop))
    ptConnector = playground.Connector(protocolStack=f)
    playground.setConnector("passthrough", ptConnector)
    go = initiate(loop)
    coro = playground.getConnector('passthrough').create_playground_connection(go.send_first_packet, '20174.1.1.1', 8888)
    client = loop.run_until_complete(coro)
    # Serve requests until Ctrl+C is pressed
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    # Close the server
    loop.close()
