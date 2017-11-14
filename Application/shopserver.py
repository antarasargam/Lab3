from netsec_2017.Lab_3.packets import RequestItem, RequestMoney, RequestToBuy, FinishTransaction, SendItem, SendMoney
from netsec_2017.Lab_3.PLS.server import PLSStackingTransport, PLSServer
from netsec_2017.Lab_3.peepTCP import PEEPServerProtocol, PeepServerTransport
import asyncio
import playground
from playground.network.packet import PacketType
from playground.network.common.Protocol import StackingProtocol, StackingProtocolFactory, StackingTransport

class ShopServerProtocol(asyncio.Protocol):

    serverstate = 0

    def __init__(self, loop):
        self.deserializer = PacketType.Deserializer()
        self.transport = None
        self.loop = loop

    def connection_made(self, transport):
        print("ShopServer connection_made is called")
        self.transport = transport

    def data_received(self, data):
        print("ShopServer Data_received is called")

        self.deserializer.update(data)
        #print(data)
        for pkt in self.deserializer.nextPackets():
                #print("Client ------------{}---------------> Server".format(pkt.DEFINITION_IDENTIFIER))


                if isinstance(pkt, RequestToBuy) and self.serverstate == 0:
                    self.serverstate += 1

                    # PACKET 2 - Request Item packet
                    response = RequestItem()

                    print("Sent RequestItem")
                    self.transport.write(response.__serialize__())
                    #print(self.serverstate)

                elif isinstance(pkt, SendItem) and self.serverstate == 1:
                    self.serverstate += 1

                    # PACKET 4 - Request Money packet
                    response = RequestMoney()

                    if pkt.Item == "Bread":
                        response.Amount = 4
                    elif pkt.Item == "Butter":
                        response.Amount = 10

                    print("Sent RequestMoney")
                    self.transport.write(response.__serialize__())

                elif isinstance(pkt, SendMoney) and self.serverstate == 2:
                    self.serverstate += 1

                    # PACKET 6 - Finish Transaction packet
                    response = FinishTransaction()

                    print("Sent FinishTransaction")
                    self.transport.write(response.__serialize__())
                    self.transport.close()

                else:
                    print(pkt.Type)
                    print("Server Received Incorrect Packet. Closing Connection. Try Again!")
                    self.transport.close()


    def connection_lost(self,exc):
        print('\nThe ShopClient sent a connection close to the server')
        self.transport.close()
        self.loop.stop()

if __name__ == "__main__":

    loop = asyncio.get_event_loop()
    # Each client connection will create a new protocol instance

    #logging.getLogger().setLevel(logging.NOTSET)  # this logs *everything*
    #logging.getLogger().addHandler(logging.StreamHandler())  # logs to stderr

    f = StackingProtocolFactory(lambda: PLSServer(), lambda: PEEPServerProtocol(loop))
    ptConnector= playground.Connector(protocolStack=f)
    playground.setConnector("passthrough",ptConnector)
    coro = playground.getConnector('passthrough').create_playground_server(lambda: ShopServerProtocol(loop),8888)
    server = loop.run_until_complete(coro)

    # Serve requests until Ctrl+C is pressed
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    # Close the server
    server.close()
    loop.close()
