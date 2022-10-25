from isis_psnp import ISIS_PSNP
from isis_fixheader import ISIS_FixHeader
from ethernet_frame import ETHERNET_Frame
class ISIS_Packet_Builder:
    @classmethod
    def buildPSNPPacket(cls) ->  ISIS_PSNP:
        psnp = ISIS_PSNP()
        return psnp
    @classmethod
    def buildFixHeader(cls) ->  ISIS_FixHeader:
        fixheader=ISIS_FixHeader()
        return fixheader

    @classmethod
    def buildEthernetFrame(cls) -> ETHERNET_Frame:
        eth_frame = ETHERNET_Frame()
        return eth_frame
