from ethernet_frame import ETHERNET_Frame
from isis_hello import ISIS_HELLO
from isis_fixheader  import ISIS_FixHeader
from isis_lsp import ISIS_LSP
from isis_psnp import ISIS_PSNP
#test git
class ISIS_Packet:

    def __init__(self):
        self.hello = None
        self.fix_header = None
        self.eth_frame= None
        self.lsp = None
        self.psnp= None

    def createHelloPacket(self):
        self.hello = ISIS_HELLO()
    def createLSPPacket (self):
        self.lsp = ISIS_LSP()
    def createEthernetFrame(self):
        self.eth_frame = ETHERNET_Frame()
    def getEthernetFrame (self) -> ETHERNET_Frame:
        return self.eth_frame
    def createPSNPPacket(self):
        self.psnp = ISIS_PSNP()
    def getPSNPPacket(self) -> ISIS_PSNP:
        return self.psnp
    def getLSPPacket(self) -> ISIS_LSP:
        return self.lsp

    def getHello(self) -> ISIS_HELLO:
        if (self.hello != None):
            return self.hello
        else:
            raise Exception("Hello packet not initialised")

    def createFixHeader(self):
        self.fix_header = ISIS_FixHeader()
    def getFixHeader(self) -> ISIS_FixHeader:
        if (self.fix_header != None):
            return self.fix_header
        else:
            raise Exception("Fix header has not been created")


