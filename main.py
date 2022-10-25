import time
from tlv_protocolType import  TLV_Protocol_Supported
from tlv_area_id import  TLV_Area_Id
from tlv_interface_ip import TLV_interface_ip
from tlv_p2p_adjcency_state import TLV_P2P_Adjacency_State
from tlv_instance import TLV_Instance_Id
import ctypes
import traceback as tb
import sys
from neighbor import Neighbor
import admin

def print_hi(name):

    try:
        neigh = Neighbor('Intel(R) Wi-Fi 6 AX201 160MHz')
        #print(neigh)
        #neigh.createISISPacketSend()
        isis_packet = neigh.getISISPacketSend()
        #print(isis_packet)
        isis_packet.createFixHeader()
        isis_packet.getFixHeader().populateFixFields('hello')
        isis_packet.getFixHeader().setPacketType(17)

        isis_packet.createHelloPacket()
        isis_packet.createEthernetFrame()

        isis_packet.getHello().setSystemId("3333.3333.2222")
        isis_packet.getHello().setCktType("level_2")
        isis_packet.getHello().setHoldTime(100)
        isis_packet.getHello().setPriority(5)
        isis_packet.getHello().generateLocalCktId()
        isis_packet.getHello().setInterfaceType("p2p")

        tlv1 = TLV_Protocol_Supported()
        tlv1.setType(129)
        tlv1.setValue(204)
        tlv1.setLength(1)
        isis_packet.getHello().add_tlv(tlv1)

        p2p = TLV_P2P_Adjacency_State()
        p2p.setType(240)
        p2p.setValue(neigh.isis_Neighbor_status())
        p2p.generateExtCkt()
        p2p.setLength(5)

        isis_packet.getHello().add_tlv(p2p)
        # p2p = isis_packet.getHello().get_tlv(p2p)
        # p2p.setValue(2)

        area_id = TLV_Area_Id()
        area_id.setValue("49.0001")
        area_id.setType(1)
        area_id.setLength(4)
        isis_packet.getHello().add_tlv(area_id)

        int_ip = TLV_interface_ip()
        int_ip.setValue("192.168.77.17")
        int_ip.setType(132)
        int_ip.setLength(4)
        isis_packet.getHello().add_tlv(int_ip)

        instance_id = TLV_Instance_Id()
        instance_id.setValue(100)
        instance_id.setType(7)
        instance_id.setLength(4)
        isis_packet.getHello().add_tlv(instance_id)

        isis_packet.getEthernetFrame().setSourceMac("00:00:01:A1:03:02")
        len_TLVs = len(isis_packet.getHello().getTLVsBinary())
        isis_packet.getHello().setPDULength(0)
        len_hello = len(isis_packet.getHello().getBinary())
        len_fix_header = len(isis_packet.getFixHeader().getBinary())
        isis_packet.getHello().setPDULength(len_TLVs + len_hello + len_fix_header)
        isis_packet.getEthernetFrame().setlLength(len_TLVs + len_hello + len_fix_header + 3)
        # all_tlvs_binary=isis_packet.getHello().getTLVsBinary()
        # hello_binary=isis_packet.getHello().getBinary()
        # fix_header_binary=isis_packet.getFixHeader().getBinary()
        neigh.start()

        while (1):
            time.sleep(1)

            if (neigh.isis_Neighbor_status() == 1):
                #p2p1 = TLV_P2P_Adjacency_State()
                return_p2p = isis_packet.getHello().get_tlv(240)
                return_p2p.setValue(1)
                #del p2p1
            elif (neigh.isis_Neighbor_status() == 0):
                #p2p1 = TLV_P2P_Adjacency_State()
                return_p2p = isis_packet.getHello().get_tlv(240)
                return_p2p.setValue(0)
                #del p2p1
                break

        #print("Value", isis_packet.getHello().get_tlv(240).getValue())

        # isis_packet.getHello().setPDULength(1497)
        # neigh.start()
    except ValueError as err:

        tb.print_exc()
    except Exception as e:
        tb.print_exc()
# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    print_hi('paolo')


# See PyCharm help at https://www.jetbrains.com/help/pycharm/
