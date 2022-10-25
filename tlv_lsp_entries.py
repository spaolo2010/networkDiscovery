from tlvs import TLV
import struct
import re
from utils import SystemIdConverter
class TLV_LSP_Entries(TLV):
    def __init__(self):
        self.type = 9
        self.length = 16
        self.lsp_id = None
        self.lsp_fragment = 0
        self.sel = 0
        self.checksum = 0
        self.lifetime = -1
        self.sequence_number = None
        self.lsp_id_1 = None
        self.lsp_id_2 = None
        self.lsp_id_3 = None
        self.lsp_id_4 = None
        self.lsp_id_5 = None
        self.lsp_id_6 = None
        self.packet_status = {

            'lsp_id': False,
            'lifetime': False,
            'sequence_number': False,
            'lsp_id': False,
            'checksum': False
        }
    def setType(self,type):
        pass
    def setValue(self,value):
        pass
    def setLength(self,length):
        pass
    def getLen(self):
        return self.length
    def getType(self):
        return self.type
    def set_checksum(self, checksum):
        if (not isinstance(checksum, int)):
            raise Exception("Checksum is an int")
        elif (checksum <= 0 or checksum > 65535):
            raise Exception("Checksum  not within the range")
        else:
            self.checksum = checksum
            self.packet_status['checksum'] = True

    def set_lifetime(self, lifetime):
        if (not isinstance(lifetime, int)):
            raise Exception('lifetime value in not an int')
        elif (lifetime < 0 or lifetime > 1200):
            raise Exception('lifetime value out of range')
        else:
            self.lifetime = lifetime
            self.packet_status['lifetime'] = True

    def set_sequence_number(self, sequence_number):
        if (not isinstance(sequence_number, int)):
            raise Exception("Sewquence number not an integer")
        elif (sequence_number < 0 or sequence_number > 4294967295):
            raise Exception("Sequence number out of range ")
        else:
            self.sequence_number = sequence_number
            self.packet_status['sequence_number'] = True

    def set_lsp_Id(self, lsp_id):
        if (not re.match('^\w+\w+\w+\w+\.\w+\w+\w+\w+\.\w+\w+\w+\w+-\w+\w+-\w+\w+$', lsp_id)):
            raise Exception('LSP ID format is wrong')
        else:

            lsp_id_parts = lsp_id.split('-')
            self.lsp_fragment = int(lsp_id_parts[1])
            self.sel = int(int(lsp_id_parts[2]))
            elements = lsp_id_parts[0].split('.')
            lsp_id_numeric = elements[0] + elements[1] + elements[2]
            self.lsp_id_1, self.lsp_id_2, self.lsp_id_3, self.lsp_id_4, self.lsp_id_5, self.lsp_id_6 = SystemIdConverter.convertSystemId(
                    lsp_id_numeric)
            self.packet_status['lsp_id'] = True

    def getBinary(self):
        if (False in self.packet_status.values()):
            # print(self.packet_status)
            print(self.packet_status)
            raise ValueError("Some of  field(s) " + str(self.packet_status.keys()) + " is/are not set")

        else:
            lspentrystream = struct.pack(">BBHBBBBBBBBIH",  self.type, self.length,self.lifetime,
                                       self.lsp_id_1, self.lsp_id_2, self.lsp_id_3,
                                     self.lsp_id_4, self.lsp_id_5, self.lsp_id_6, self.sel, self.lsp_fragment,self.sequence_number,self.checksum)
            return lspentrystream

