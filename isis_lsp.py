import struct
import re
from utils import SystemIdConverter
from utils import calcChecksum
from tlv_protocolType import  TLV_Protocol_Supported
from tlv_area_id import  TLV_Area_Id
from tlv_instance import TLV_Instance_Id
from tlv_extended_ip_reach import TLV_Extended_IP_Reach
from tlv_interface_ip import TLV_interface_ip

class ISIS_LSP:

    def __init__(self):
        pass
        self.pdu_length = 0
        self.remaining_lifetime = None
        self.lsp_id= None
        self.sequence_number=None
        self.checksum = 0
        self.type_block = None
        self.lsp_fragment = 0
        self.sel = 0
        self.lsp_id_1 = None
        self.lsp_id_2 = None
        self.lsp_id_3 = None
        self.lsp_id_4 = None
        self.lsp_id_5 = None
        self.lsp_id_6 = None
        self.packet_status = {
            'pduLength': True,
            'lifeTime': False,
            'lsp_id': False,
            'typeBlock': False,
            'seqNumber': False,
            'checksum': True


        }
        lsp_pdu_binary =b''
        self.tlvs = []
    def setPDULength(self,length):
        pass
        if (isinstance(length ,int)):

            if (length < 18 or length > 9000):
                raise Exception("PDU length out of range")
            else:
                self.pdu_length = length
                self.packet_status['pduLength'] = True

        else:
            raise ValueError("it is not an integer")

    def reduceTheLifeTime(self):
        if (self.remaining_lifetime == None):
            raise Exception("The remaining lifetime is not initialised")
        else:
            self.remaining_lifetime-=1

    def setLifetime(self,lifetime):
        pass
        if (isinstance(lifetime, int)):

            if (lifetime < 18 or lifetime > 1200):
                raise Exception("PDU length out of range")
            else:
                self.remaining_lifetime = lifetime
                self.packet_status['lifeTime']= True

        else:
            raise ValueError("lifetime it is not an integer")
    def incrementFragmentByte(self):
        self.lsp_fragment += 1

    def setLSP_ID(self, lspId):
        pass
        if (re.match("\d{4}\.\d{4}\.\d{4}",lspId)):
            parts_sys_id=lspId.split('.')
            self.lsp_id = parts_sys_id[0] + parts_sys_id[1] + parts_sys_id[2]
            #print("LSP "+ self.lsp_id)

            self.lsp_id_1,self.lsp_id_2,self.lsp_id_3,self.lsp_id_4,self.lsp_id_5,self.lsp_id_6 =   SystemIdConverter.convertSystemId(self.lsp_id)
            #print(self.lsp_id_1)
            self.lsp_id = lspId +'-'+str(self.sel)
            self.packet_status['lsp_id']=True

        else:
            raise ValueError("System ID not correct")
    def setTypeBlock(self,level):


        if (level == 2):
           self.type_block = 3
           self.packet_status['typeBlock']= True
        elif (level == 1):
           self.type_block = 1
           self.packet_status['typeBlock'] = True

        else:
            raise Exception ("Level is not correct")
    def getChecksum(self):
        if (self.checksum == 0):
            raise Exception("Checksum is not set")
        else:
            return self.checksum
    def calcChecksum(self,LSP_stream):
       self.checksum=calcChecksum.calculate(LSP_stream)
    def get_LSP_Id(self):
        if (self.lsp_id == None):
            raise Exception("LSP ID not set")
        else:
            return self.lsp_id

    def genSequenceNumber(self):
        self.sequence_number = 42
        self.packet_status['seqNumber'] = True

    def incrementSequenceNumber(self):
        self.sequence_number +=1
    def getSequenceNumber(self):
        if (self.sequence_number == None):
            raise Exception("Sequence number not set")
        return self.sequence_number
    def getLifeTime(self):
        if (self.sequence_number == None):
            raise Exception("Remaining lifetime is  not set")
        return self.remaining_lifetime
    def getTypeBlock(self):
        if (self.type_block == None):
            raise Exception("Type is  not set")
        return self.type_block
    def getPDULength(self):
        if (self.pdu_length == None):
            raise Exception("PDU Length is  not set")
        return self.pdu_length
    def getBinary(self):
        if (False in self.packet_status.values()):
            #print(self.packet_status)
            raise ValueError("Some of  field(s) " + str(self.packet_status.keys()) + " is/are not set\n")

        else:
            #print (self.pdu_length)
            #print (self.remaining_lifetime)
            #print (self.lsp_id_1)
            #print(self.lsp_id_2)
            #print(self.lsp_id_3)
            #print(self.lsp_id_4)
            #print(self.lsp_id_5)
            #print(self.lsp_id_6)

            lspstream = struct.pack(">HHBBBBBBBBIHB", self.pdu_length,self.remaining_lifetime, self.lsp_id_1,
                                      self.lsp_id_2, self.lsp_id_3, self.lsp_id_4, self.lsp_id_5,
                                    self.lsp_id_6, self.sel, self.lsp_fragment, self.sequence_number,self.checksum,self.type_block)
            #print (lspstream)
            return lspstream
            # for tlv in self.tlvs:
    def is_tlv_present(self,type):
        global found
        found = False
        for tlv in self.tlvs:
            if (tlv.getType() == type):

               found = True
        return found
    def populateLspFieldsFromStream(self, stream):
        if (len(stream) != 19):
            raise Exception("LSP length is not 19 bytes")
        else:
            self.pdu_length, self.remaining_lifetime, self.lsp_id_1, \
            self.lsp_id_2, self.lsp_id_3, self.lsp_id_4, self.lsp_id_5, \
            self.lsp_id_6, self.sel, self.lsp_fragment, self.sequence_number, self.checksum, self.type_block\
                = struct.unpack(">HHBBBBBBBBIHB", stream)

            self.lsp_id= str("{0:0=2d}".format(int(str(hex(self.lsp_id_1))[2:]))) + \
                             str("{0:0=2d}".format(int(str(hex(self.lsp_id_2))[2:]))) + "." + \
                             str("{0:0=2d}".format(int(str(hex(self.lsp_id_3))[2:]))) + \
                             str("{0:0=2d}".format(int(str(hex(self.lsp_id_4))[2:]))) + "." + \
                             str("{0:0=2d}".format(int(str(hex(self.lsp_id_5))[2:]))) + \
                             str("{0:0=2d}".format(int(str(hex(self.lsp_id_6))[2:]))) + "-"+ \
                             str("{0:0=2d}".format(int(str(hex(self.sel))[2:]))) +'-'+ \
                             str("{0:0=2d}".format(int(str(hex(self.lsp_fragment))[2:])))





    def add_tlv(self, tlv):
        for tlv1 in self.tlvs:
            if (isinstance(tlv1, TLV_Protocol_Supported) and type(tlv1) == type(tlv)):
                raise Exception("TLV Protocol Type already present")

            elif (isinstance(tlv1, TLV_Area_Id) and type(tlv1) == type(tlv)):
                raise Exception("TLV area ID already present")
            elif (isinstance(tlv1, TLV_Instance_Id) and type(tlv1) == type(tlv)):
                raise Exception("TLV Instance ID already present")
            elif (isinstance(tlv1,TLV_interface_ip) and type(tlv1) == type(tlv)):
                raise Exception("TLV Interface IP already present")


        if (isinstance(tlv, TLV_Protocol_Supported)):
            self.tlvs.append(tlv)
            # print ("Add TLV Prot")

        elif (isinstance(tlv, TLV_Area_Id)):
            self.tlvs.append(tlv)
            # print("Add tLV aree id")
        elif (isinstance(tlv, TLV_Instance_Id)):
            self.tlvs.append(tlv)
        elif (isinstance(tlv,TLV_Extended_IP_Reach)):
            self.tlvs.append(tlv)
            # print("Add tLV instance id")
        elif (isinstance(tlv,TLV_interface_ip)):
            self.tlvs.append(tlv)
        else:
            raise Exception("TLV not recognised")

    def get_tlv(self, type):
        global found
        found = False
        for tlv in self.tlvs:
            if (tlv.getType() == type):
                return tlv
        return None


    def getTLVsBinary(self):
        all_tlv_binary=b''
        if (len(self.tlvs) == 0):
            raise Exception("TLV list is not populated")
        #print ("LEN TLVs ", len(self.tlvs))
        for tlv in self.tlvs:
            if (isinstance(tlv, TLV_Protocol_Supported)):
               all_tlv_binary+=tlv.getBinary()
               #print ("GET PROT SUPPORTED")
            elif (isinstance(tlv, TLV_Area_Id)):
                all_tlv_binary+=tlv.getBinary()
                #print("AREA ID")
            elif (isinstance(tlv, TLV_Instance_Id)):
                all_tlv_binary += tlv.getBinary()
                #print("INSTANCE ID")
            #print    ( all_tlv_binary)
        return all_tlv_binary


def main():
    LSP= b'\x01M\x02\x8a\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x0b\x04\xd8\x03\x07\x04\x00d\x00\x00\x01\x04\x03I\x00\x01\x81\x01\xcc\x84\x04\x02\x02\x02\x01\x86\x04\x02\x02\x02\x01\x87]\x00\x00\x00\x00`\x02\x02\x02\x01\x11\x03\x06p\x00\x00\x00\x00\x01\x04\x01 \x0b\x04\x02\x02\x02\x01\x00\x00\x00\n`\x16\x16\x16\x01\x11\x03\x06p\x00\x00\x00\x00o\x04\x01 \x0b\x04\x02\x02\x02\x01\x00\x00\x00\n^\xc0\xa8!\x04\x03\x04\x01\x00\x00\x00\x00\n^\xc0\xa8!\x08\x03\x04\x01\x00\x00\x00\x00\n^\xc0\xa8!\x00\x03\x04\x01\x00\x89\x05vsim1\xf2#\x02\x02\x02\x01\x00\x02\t\x80\x00\x07\xd1\x01\x03\x00>\x80\x16\t\x00\x00\x03\xe8\x01\x03\x00:\x98\x17\x02\x01\n\x13\x02\x00\x01\x16\x8a\x00\x00\x00\x00\x00\x03\x00\x00\x00\n\x7f\x04\x08\x00\x00\x00\x13\x00\x00\x00\r\x06\x04\xc0\xa8!\x05\x08\x04\xc0\xa8!\x06\x03\x04\x00\x00\x00\x00\t\x04L\xeek(\n\x04\x00\x00\x00\x00\x0b \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x12\x03\x00\x00\n\xfc \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x05p\x00\x00]\xc0\x1f\x050\x00\x00]\xc1'
    a = LSP[:19]
    #print (len(a))
    lsp = ISIS_LSP()

    lsp.populateLspFieldsFromStream(a)
    print(calcChecksum.calculate(LSP))




if __name__ == '__main__':
    main()