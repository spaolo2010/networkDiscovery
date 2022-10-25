import re
import struct
from utils import SystemIdConverter
from tlv_lsp_entries import TLV_LSP_Entries
from tlv_instance import  TLV_Instance_Id
from utils import calcChecksum

class ISIS_PSNP():
    def __init__(self):

        self.PDU_Length = 0

        self.system_id = None
        self.system_id_1 = None
        self.system_id_2 = None
        self.system_id_3 = None
        self.system_id_4 = None
        self.system_id_5 = None
        self.system_id_6 = None
        self.localcktid = None
        self.tlvs=[]
        self.packet_status = {
                              'system_id' : False,
                              'ckt_id': False,
                              'length': True
        }
    def setPDULength(self,length):
        if (not isinstance(length,int)):
            raise Exception("Length in not an integer")
        elif (length > 255):
            raise Exception("Length out of range")
        else:
            self.PDU_Length = length
            #self.packet_status['length'] = True
    def getPDULength(self):
        if (self.PDU_Length == 0):
            raise Exception("PDU Length not set")
        else:
            return self.PDU_Length


    def setLocalCktId(self,cktid):
        if (not isinstance(cktid, int)):
            raise Exception("Cktid in not an integer")
        elif (cktid < 0 or cktid > 255):
            raise Exception("CktId out of range")
        else:
            self.localcktid = cktid
            self.packet_status['ckt_id'] = True

    def isTLVPresent(self,type):
          for tlv in self.tlvs:
             if (tlv.getType() == 9):
                 return True
             elif (tlv.getType() == 7):
                 return True
          return False
    def get_tlv(self,type):
        global found
        found = False
        for tlv in self.tlvs:
            if (tlv.getType() == type):

               return tlv
        return None

    def add_tlv(self, tlv):
        for tlv1 in self.tlvs:
            if (isinstance(tlv1, TLV_Instance_Id) and type(tlv1) == type(tlv)):
                raise Exception("TLV Protocol Type already present")


        if (isinstance(tlv, TLV_Instance_Id)):
            self.tlvs.append(tlv)
        elif (isinstance(tlv, TLV_LSP_Entries)):
            self.tlvs.append(tlv)
        else:
            raise Exception("TLV not recognised")

    def getTLVsBinary(self):
        all_tlv_binary=b''
        if (len(self.tlvs) == 0):
            raise Exception("TLV list is not populated")

        for tlv in self.tlvs:
            if (isinstance(tlv, TLV_Instance_Id)):
               all_tlv_binary+=tlv.getBinary()
            elif (isinstance(tlv, TLV_LSP_Entries)):
               all_tlv_binary+=tlv.getBinary()

        return all_tlv_binary

    def setSource_System_Id(self,system_id):
        if (re.match("\d{4}\.\d{4}\.\d{4}", system_id)):
            parts_sys_id = system_id.split('.')

            self.system_id = parts_sys_id[0] + parts_sys_id[1] + parts_sys_id[2]

            self.system_id_1, self.system_id_2, self.system_id_3, self.system_id_4, self.system_id_5, self.system_id_6 = SystemIdConverter.convertSystemId(
                self.system_id)
            self.packet_status['system_id'] = True
        else:
            raise ValueError("System ID not correct")

    def getBinary(self):
        if (False in self.packet_status.values()):
            #print(self.packet_status)
            print (self.packet_status)
            raise ValueError( "Some of  field(s) " +  str(self.packet_status.keys())  + " is/are not set")

        else:
            psnpstream= struct.pack(">HBBBBBBB", self.PDU_Length,self.system_id_1,self.system_id_2,
                                                             self.system_id_3,self.system_id_4,self.system_id_5,
                                                             self.system_id_6,self.localcktid)
            return psnpstream


