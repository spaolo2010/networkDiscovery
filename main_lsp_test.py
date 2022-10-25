import time
from tlv_protocolType import  TLV_Protocol_Supported
from tlv_area_id import  TLV_Area_Id
from tlv_interface_ip import TLV_interface_ip
from tlv_p2p_adjcency_state import TLV_P2P_Adjacency_State
from tlv_instance import TLV_Instance_Id
import traceback as tb
from neighbor import Neighbor

def print_hi(name):
    neigh = Neighbor('br333')
    print(neigh)
    neigh.createISISPacketSend()
    isis_packet = neigh.getISISPacketSend()
    print(isis_packet)
    isis_packet.createFixHeader()
    isis_packet.getFixHeader().populateFixFields('lsp')
    isis_packet.getFixHeader().setPacketType(20)
    isis_packet.createLSPPacket()
    isis_packet.getLSPPacket().setLSP_ID("3333.3333.2222")
    isis_packet.getLSPPacket().setLifetime(1200)
    isis_packet.getLSPPacket().setTypeBlock(2)
    isis_packet.getLSPPacket().genSequenceNumber()
    stream=isis_packet.getLSPPacket().getBinary()
    isis_packet.getLSPPacket().calcChecksum(stream)
    isis_packet.getLSPPacket().setPDULength(len(stream))
    isis_packet.createEthernetFrame()
    isis_packet.getEthernetFrame().setSourceMac("00:00:01:A1:03:02")
    #len_TLVs = len(isis_packet.getHello().getTLVsBinary())

    len_fix_header = len(isis_packet.getFixHeader().getBinary())
    isis_packet.getLSPPacket().setPDULength(len(stream) + len_fix_header)
    #isis_packet.getHello().setPDULength( len(stream) + len_fix_header)
    isis_packet.getEthernetFrame().setlLength( len(stream) +  len_fix_header + 3)
    neigh.start()
if __name__ == '__main__':
     print_hi('paolo')