import struct
import time
from isis_packet import ISIS_Packet
from isis_lsp import ISIS_LSP
from isis_psnp import ISIS_PSNP
from packets_factory import ISIS_Packet_Builder
import re
#from socket import *
#import socket
#from rawsocketpy import RawSocket, to_str
#from socket import socket, AF_PACKET, SOCK_RAW, SOL_SOCKET, htons
from tlv_protocolType import  TLV_Protocol_Supported
from tlv_area_id import  TLV_Area_Id
from tlv_interface_ip import TLV_interface_ip
from tlv_p2p_adjcency_state import TLV_P2P_Adjacency_State
from tlv_instance import TLV_Instance_Id
from isis_hello import  ISIS_HELLO
from tlv_extended_ip_reach import TLV_Extended_IP_Reach
from tlv_lsp_entries import TLV_LSP_Entries
from scapy.all import *
import queue
import ctypes

import threading
import netifaces
class Neighbor(threading.Thread):
    def __init__(self, interface):

        #self.socket = socket(socket.AF_PACKET, socket.SOCK_RAW, 3)
        #HOST = socket.gethostbyname(socket.gethostname())
        #print (HOST)
        #self.socket= socket.socket(socket.AF_INET,socket.SOCK_RAW)
        #print(netifaces.interfaces())
        #print(ifName)
                      # s.bind(("eno1", 0x0801))
        #print (socket.if_nameindex())
        #self.socket.setsockopt(socket.SOL_SOCKET, 25, str('Intel(R) Wi-Fi 6 AX201 160MHz' + '\0').encode('utf-8'))
        #self.socket.bind((interface, 0))
        #print(self.socket.getsockname())
        self.socket = conf.L2socket(iface=interface)
        self.lockobject = threading.Lock()
        from scapy import layers

        #from scapy.layers.l2 import Ether
        #Ether.
        #conf.iface()
        #print(ctypes.windll.shell32.IsUserAnAdmin())
        #ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
        #self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW,3)
        #s.bind((HOST, 0))
        #self.socket = RawSocket(interface, 0xEEFA)
        self.recv_isis_packet = ISIS_Packet()
        self.send_isis_packet = ISIS_Packet()
        self.send_psnp : ISIS_PSNP
        self.recv_psnp : ISIS_PSNP
        self.send_hello: ISIS_HELLO
        self.recv_hello: ISIS_HELLO
        self.lspqueue = queue.Queue()
        #self.recv_isis_packet = None
        #self.send_isis_packet = None
        self.recv_holdtime = -1
        self.hello_binary_complete = b''
        self.lsp_binary_complete = b''
        self.neighbor = 2

        threading.Thread.__init__(self)

    def getIntfParams(self):
        ifName, ifProto, pktType, hwType, hwAddr = self.socket.getsockname()
        return ifName,ifProto,pktType,hwType,hwAddr




    def getISISPacketSend(self) -> ISIS_Packet:
        if (self.send_isis_packet == None):
            raise Exception("ISIS Packet not initialised")
        else:
            return self.send_isis_packet

    def getISISPacketRecv(self) -> ISIS_Packet:
        if (self.recv_isis_packet == None):
            raise Exception("ISIS Packet not initialised")
        else:
            return self.recv_isis_packet

    def isis_Neighbor_status(self):
        return self.neighbor

    def run(self):
        # self.send_isis_packet = ISIS_Packet()
        # self.send_isis_packet.createFixHeader()
        # self.send_isis_packet.createHelloPacket()
        # self.send_isis_packet.createEthernetFrame()
        #self.recv_isis_packet = ISIS_Packet()
        self.recv_isis_packet.createFixHeader()
        self.recv_isis_packet.createHelloPacket()
        #self.recv_isis_packet.createLSPPacket()
        x = threading.Thread(target=self.receivepackets, args=())
        y = threading.Thread(target=self.sendHellopackets, args=())
        w = threading.Thread(target=self.readLSPQueue, args=())
        #z = threading.Thread(target=self.sendLSPPacket, args=())
        # y = threading.Thread(target=self.reduceHoldTime, args=())

        x.start()
        y.start()
        w.start()
        #z.start()
        # y.start()

        # fix_header = self.send_isis_packet.getFixHeader()
        # fix_header.populateFixFields()

        # pass
        # send packets
    def readLSPQueue(self):

         queuelsp: ISIS_LSP
         while (1):
             time.sleep(1)

             if ( not self.lspqueue.empty() ):
                 self.lockobject.acquire()
                 queuelsp =  self.lspqueue.get()
                 if (not isinstance ( queuelsp,ISIS_LSP)):
                     self.lockobject.release()
                     raise Exception (" The object in the queue is not a LSP object")
                 else:

                     lifetime=queuelsp.getLifeTime()
                     lspchecksum=queuelsp.getChecksum()
                     seq_number= queuelsp.getSequenceNumber()
                     lsp_id =  queuelsp.get_LSP_Id()
                     system_id = self.send_isis_packet.getHello().getSystemId()
                     print (lifetime,lspchecksum , seq_number,lsp_id,system_id)
                     self.sendPSNPAckPacket(lifetime ,lspchecksum,seq_number,lsp_id,system_id)
                     self.lockobject.release()




    def sendPSNPAckPacket(self, lifetime ,lspchecksum,seq_number,lsp_id,system_id):
        #self.send_isis_packet.createPSNPPacket()
        psnp = ISIS_Packet_Builder.buildPSNPPacket()
        tlv_instance_id =TLV_Instance_Id()
        tlv_instance_id.setValue(100)
        tlv_instance_id.setType(7)
        tlv_instance_id.setLength(4)

        tlv_lsp_entry = TLV_LSP_Entries()
        tlv_lsp_entry.set_lifetime(lifetime)
        tlv_lsp_entry.set_checksum(lspchecksum)
        tlv_lsp_entry.set_sequence_number(seq_number)
        tlv_lsp_entry.set_lsp_Id(lsp_id)

        cktid=self.send_isis_packet.getHello().getLocalCktId()

        psnp.add_tlv(tlv_instance_id)
        psnp.add_tlv(tlv_lsp_entry)
        psnp.setSource_System_Id(system_id)
        psnp.setLocalCktId(cktid)

        psnp_binary = psnp.getBinary()
        fix_header = ISIS_Packet_Builder.buildFixHeader()
        fix_header.populateFixFields('psnp')
        fix_header.setPacketType(27)
        fix_header_binary = fix_header.getBinary()

        PDU_Len = len(fix_header_binary) + len(psnp_binary) + len(psnp.getTLVsBinary())

        psnp.setPDULength(PDU_Len)
        psnp_binary = psnp.getBinary()
        tlv_binary = psnp.getTLVsBinary()

        eth_frame= ISIS_Packet_Builder.buildEthernetFrame()
        eth_frame.setSourceMac("00:00:01:A1:03:02")
        total_len = len(fix_header_binary) + len(psnp_binary)  + len(psnp.getTLVsBinary())+ 3


        eth_frame.setlLength(total_len)
        eth_frame_binary = eth_frame.getBinary()
        psnp_binary_complete = eth_frame_binary + fix_header_binary + psnp_binary + tlv_binary

        if (len(psnp_binary_complete) != 0):

            self.socket.send(psnp_binary_complete)
            # send the packet
        else:
            raise Exception ('PSNP stream is xero in length')


        del psnp
        del tlv_instance_id
        del tlv_lsp_entry
        del fix_header
        del eth_frame


    def sendLSPPacket(self):
        while (1):

            lsp_binary=self.send_isis_packet.getLSPPacket().getBinary()
            fix_header_binary = self.send_isis_packet.getFixHeader().getBinary()
            eth_frame_binary = self.send_isis_packet.getEthernetFrame().getBinary()
            self.lsp_binary_complete = eth_frame_binary + fix_header_binary + lsp_binary
            if (len(self.lsp_binary_complete) != 0):
                pass
                self.socket.send(self.lsp_binary_complete)
                # send the packet
            else:
                raise Exception("packet length not correct")
            time.sleep(1)
    def getHelloBinary(self):
        if (len(self.hello_binary_complete) == 0):
            raise Exception('The hello packet length cannot be zero')

        return self.hello_binary_complete
    def isSendPacket(self):
        if (self.send_isis_packet != None):
            return self.send_isis_packet
        else:
            return None
    def sendHellopackets(self):
        global hello_interval
        hello_interval = 2
        if (self.send_isis_packet != None):
            while (1):
                time.sleep(hello_interval)
                all_tlvs_binary = self.send_isis_packet.getHello().getTLVsBinary()
                hello_binary = self.send_isis_packet.getHello().getBinary()
                fix_header_binary = self.send_isis_packet.getFixHeader().getBinary()
                eth_frame_binary = self.send_isis_packet.getEthernetFrame().getBinary()

                self.hello_binary_complete = eth_frame_binary + fix_header_binary + hello_binary + all_tlvs_binary
                # print(self.hello_binary_complete)
                # print (all_tlvs_binary)
                if (len(self.hello_binary_complete) != 0):

                    self.socket.send(self.hello_binary_complete)
                    # send the packet
                else:
                    raise Exception("packet length not correct")
                if (self.recv_holdtime != -1):
                    hello_interval = int(self.recv_holdtime / 3)
        else:
            raise Exception("ISIS Packet  has not been created ")

        pass

    def receivepackets(self):

        fix = self.recv_isis_packet.getFixHeader()

        # recvpacket = b'\x01\x00^\x90\x00\x02RT\x00\x82\\4\x05\xdc\xfe\xfe\x03\x83\x14\x01\x00\x11\x01\x00\x00\x02\x00\x00\x00\x00\x00\x03\x00\x1e\x05\xd9\x00\xf0\x05\x02\x00\x00\x00\x0e\x07\x04\x00d\x00\x00\x81\x01\xcc\xd3\x03\x04\x00\x00\x01\x04\x03I\x00\x01\x84\x04\xc0\xa8M\x12\x08\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x9d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
           #global recvpacket
        while (1):
            #print("Receving packets")
            a = True
            while (a == True):

                packet = self.socket.recv(5000)  # Using the library (also contains things like sent time...)
                if (packet != None):
                   # print("Receving packets")
                    a = False

            recvpacket=bytes(packet)
            #test = recvpacket[1]
            #print(type(test))
            dst_mac = recvpacket[:6]
            #print (dst_mac)

            # print (dst_mac)
            dst_mac1, dst_mac2, dst_mac3, dst_mac4, dst_mac5, dst_mac6 = struct.unpack("BBBBBB", dst_mac)
            #print (hex(dst_mac1),hex(dst_mac2),hex(dst_mac3),hex(dst_mac4),hex(dst_mac5),hex(dst_mac6))
            src_mac = recvpacket[6:12]
            # print (src_mac)
            src_mac1, src_mac2, src_mac3, src_mac4, src_mac5, src_mac6 = struct.unpack("BBBBBB", src_mac)

            fixheader = recvpacket[17:25]
            # print(fixheader)
            fix.setValuesFromStream(fixheader)
            # print ("PType",fix.protocolType)
            # print ( recvpacket[15:16], recvpacket[14:15])
            # print (struct.unpack("B",recvpacket[15:16]) )
            #print (struct.unpack("B", recvpacket[15:16]))
            if (struct.unpack("B", recvpacket[15:16])[0] == 254 and
                    struct.unpack("B", recvpacket[14:15])[0] == 254 and src_mac != b'\x00\x00\x01\xa1\x03\x02'):
                # print ("ISIS Packet")
                #print(src_mac)
                if (fix.protocolType == 17):
                    #print ("HELLO",recvpacket[25:37])

                    hello_stream = recvpacket[25:37]
                    self.parseHello(hello_stream)
                    leftcounter = 37
                    self.pasrseTLVs(recvpacket, leftcounter,'hello')
                elif (fix.protocolType == 25):
                    print("CSNP", recvpacket[25:])
                elif (fix.protocolType == 20):
                    print("LSP", recvpacket[25:])
                    self.parseLSP(recvpacket[25:44])
                    leftcounter = 44
                    self.pasrseTLVs(recvpacket, leftcounter,'lsp')
                    lsp1=self.recv_isis_packet.getLSPPacket()
                    self.lockobject.acquire()
                    self.lspqueue.put(lsp1)
                    self.lockobject.release()
                    del lsp1

                else:
                    raise Exception("Fix Header protocol type is wrong")

                if (self.recv_holdtime == 0):
                    break



    def parseHello(self, stream):
        hello = self.recv_isis_packet.getHello()
        #print("HELLO LEN", len(stream))
        hello.populateHelloFieldsFromStream(stream)
        self.recv_holdtime = hello.getHoldTime()

    def parseLSP(self, stream):
        #lsp= self.recv_isis_packet.getLSPPacket()
        self.recv_isis_packet.createLSPPacket()
        lsp = self.recv_isis_packet.getLSPPacket()
        lsp.populateLspFieldsFromStream(stream)


    def parseCSNP(self, stream):
        pass

    def parsePSNP(self, stream):
        pass

    def pasrseTLVs(self, recvpacket, leftcounter,packettype):
        hello = self.recv_isis_packet.getHello()
        lsp  = self.recv_isis_packet.getLSPPacket()
        while (leftcounter < len(recvpacket)):
            initial_tlv_counter = leftcounter
            tlv_type = struct.unpack("B", recvpacket[leftcounter:leftcounter + 1])
            # print (tlv_type)
            # TLV Area ID
            if (int(tlv_type[0]) == 240):
                #tlv_p2p = TLV_P2P_Adjacency_State()


                is_tlv = hello.is_tlv_present(int(tlv_type[0]))

                leftcounter += 1
                tlv_length = struct.unpack("!B", recvpacket[leftcounter:leftcounter + 1])

                leftcounter += int(tlv_length[0]) + 1
                final_tlv_counter = leftcounter
                # print(recvpacket[initial_tlv_counter: final_tlv_counter])

                if (is_tlv == False):
                    tlv_p2p = TLV_P2P_Adjacency_State()
                    tlv_p2p.setValuesFromBinary(recvpacket[initial_tlv_counter: final_tlv_counter])

                    hello.add_tlv(tlv_p2p)
                    self.neighbor = 1
                else:
                    if (self.neighbor != 0):

                        returned_tlv=hello.get_tlv(int(tlv_type[0]))
                        returned_tlv.setValuesFromBinary(recvpacket[initial_tlv_counter: final_tlv_counter])
                        #print("VALUE", returned_tlv.getValue())
                        if (returned_tlv.getValue() == 0):
                            self.neighbor = 0
                    #del tlv_p2p
                    # print (hello.get_tlv(tlv_p2p ).getValue())
            elif (int(tlv_type[0]) == 129):
                # print ("129")
                #tlv_prot_support = TLV_Protocol_Supported()
                #returned_tlv = hello.get_tlv(tlv_prot_support)
                if (packettype == 'hello'):
                    is_tlv = hello.is_tlv_present(int(tlv_type[0]))
                elif (packettype == 'lsp'):
                    is_tlv = lsp.is_tlv_present(int(tlv_type[0]))
                leftcounter += 1
                tlv_length = struct.unpack("!B", recvpacket[leftcounter:leftcounter + 1])
                leftcounter += int(tlv_length[0]) + 1
                final_tlv_counter = leftcounter

                if (is_tlv == False):
                    tlv_prot_support = TLV_Protocol_Supported()
                    tlv_prot_support.setValuesFromBinary(recvpacket[initial_tlv_counter: final_tlv_counter])
                    if (packettype == 'hello'):
                       hello.add_tlv(tlv_prot_support)
                    elif (packettype == 'lsp'):
                       lsp.add_tlv(tlv_prot_support)
                else:
                    if (packettype == 'hello'):
                        returned_tlv = hello.get_tlv(int(tlv_type[0]))
                    elif (packettype == 'lsp'):
                        returned_tlv = lsp.get_tlv(int(tlv_type[0]))
                    returned_tlv.setValuesFromBinary(recvpacket[initial_tlv_counter: final_tlv_counter])



            elif (int(tlv_type[0]) == 1):
                # print ("129")
                #tlv_area_id = TLV_Area_Id()
                #returned_tlv = hello.get_tlv(tlv_area_id)
                if (packettype == 'hello'):
                    is_tlv = hello.is_tlv_present(int(tlv_type[0]))

                elif (packettype == 'lsp'):
                    is_tlv = lsp.is_tlv_present(int(tlv_type[0]))

                #is_tlv = hello.is_tlv_presnt(int(tlv_type[0]))
                leftcounter += 1
                tlv_length = struct.unpack("!B", recvpacket[leftcounter:leftcounter + 1])
                leftcounter += int(tlv_length[0]) + 1
                final_tlv_counter = leftcounter

                if (is_tlv == False):
                    # print ("area", recvpacket[initial_tlv_counter: final_tlv_counter])
                    tlv_area_id = TLV_Area_Id()
                    tlv_area_id.setValuesFromBinary(recvpacket[initial_tlv_counter: final_tlv_counter])
                    if (packettype == 'hello'):
                        hello.add_tlv(tlv_area_id)

                    elif (packettype == 'lsp'):
                        lsp.add_tlv(tlv_area_id)

                else:
                    if (packettype == 'hello'):
                        returned_tlv = hello.get_tlv(int(tlv_type[0]))

                    elif (packettype == 'lsp'):
                        returned_tlv = lsp.get_tlv(int(tlv_type[0]))

                    returned_tlv.setValuesFromBinary(recvpacket[initial_tlv_counter: final_tlv_counter])


            elif (int(tlv_type[0]) == 132):

                if (packettype == 'hello'):
                    is_tlv = hello.is_tlv_present(int(tlv_type[0]))
                elif (packettype == 'lsp'):
                    is_tlv = lsp.is_tlv_present(int(tlv_type[0]))
                leftcounter += 1
                tlv_length = struct.unpack("!B", recvpacket[leftcounter:leftcounter + 1])
                leftcounter += int(tlv_length[0]) + 1
                final_tlv_counter = leftcounter

                if (is_tlv == False):
                    tlv_int_ip = TLV_interface_ip()

                    tlv_int_ip.setValuesFromBinary(recvpacket[initial_tlv_counter: final_tlv_counter])
                    if (packettype == 'hello'):
                       hello.add_tlv(tlv_int_ip)
                    elif (packettype == 'lsp'):
                       lsp.add_tlv(tlv_int_ip)
                else:
                    if (packettype == 'hello'):
                        returned_tlv = hello.get_tlv(int(tlv_type[0]))
                    elif (packettype == 'lsp'):
                        returned_tlv = lsp.get_tlv(int(tlv_type[0]))

                    returned_tlv.setValuesFromBinary(recvpacket[initial_tlv_counter: final_tlv_counter])


            elif (int(tlv_type[0]) == 7):
                #tlv_inst_id = TLV_Instance_Id()
                #returned_tlv = hello.get_tlv(tlv_inst_id)
                is_tlv = hello.is_tlv_present(int(tlv_type[0]))
                leftcounter += 1
                tlv_length = struct.unpack("!B", recvpacket[leftcounter:leftcounter + 1])
                leftcounter += int(tlv_length[0]) + 1
                final_tlv_counter = leftcounter

                if (is_tlv == False):
                    # print ("area", recvpacket[initial_tlv_counter: final_tlv_counter])
                    tlv_inst_id = TLV_Instance_Id()
                    tlv_inst_id.setValuesFromBinary(recvpacket[initial_tlv_counter: final_tlv_counter])
                    hello.add_tlv(tlv_inst_id)
                else:
                    returned_tlv = hello.get_tlv(int(tlv_type[0]))
                    returned_tlv.setValuesFromBinary(recvpacket[initial_tlv_counter: final_tlv_counter])

                # TLV_Instance_Id
            elif (int(tlv_type[0]) == 135):
                leftcounter += 1
                print ('Exteded Reach')
                tlv_length = struct.unpack("!B", recvpacket[leftcounter:leftcounter + 1])
                leftcounter += int(tlv_length[0]) + 1
                final_tlv_counter = leftcounter
                tlv_extended_ip_reach = TLV_Extended_IP_Reach()
                tlv_extended_ip_reach.setValuesFromBinary(recvpacket[initial_tlv_counter: final_tlv_counter])
                tlv_extended_ip_reach.printTLVData()
                print (lsp.get_LSP_Id())
            else:

                # print("TLV TYPE", tlv_type)
                initchunk = leftcounter
                leftcounter += 1
                tlv_length = struct.unpack("!B", recvpacket[leftcounter:leftcounter + 1])
                # print("TLV LEN", tlv_length)
                endchunk=leftcounter + int(tlv_length[0])
                #print (recvpacket[initchunk:endchunk + 1])
                leftcounter += int(tlv_length[0]) + 1


    def reduceHoldTime(self):
        while (1):
            time.sleep(1)

            if (self.recv_holdtime != -1 and self.neighbor == 0):
                self.recv_holdtime -= 1
                if (self.recv_holdtime == 0):
                    self.neighbor = 2
                    break

