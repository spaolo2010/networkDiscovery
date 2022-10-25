from tlvs import TLV
import struct
class TLV_Protocol_Supported(TLV):

    def __init__(self):
        self.value = None
        self.type = None
        self.len = None
        self.packet_status ={'type': False , 'length' : False , 'value' : False}
    def setType(self,type):
        if (type != 129):
            raise ValueError("Wrong type")
        else:
            self.type = type
            self.packet_status['type'] = True
    def setValue(self,value):
        if (value != 204):
            raise ValueError("Wrong value")
        else:
            self.value = value
            self.packet_status['value'] = True
    def setLength(self,len):
        if (len != 1):
            raise ValueError("Wrong length")
        else:
            self.len = len
            self.packet_status['length'] = True

    def getLen(self):
        if (self.len == None):
            raise ValueError("Length not set")
        else:
            return self.len

    def getType(self):
        if (self.type == None):
            raise ValueError("Type not set")
        else:
            return self.type

    def getBinary(self):
        if (False in self.packet_status.values()):
            raise ValueError("Some of  field(s) " + str(self.packet_status.keys()) + " is/are not set")
        else:
            return struct.pack("!BBB",self.type,self.len, self.value)
    def setValuesFromBinary(self,stream):
        streamlen = len(stream)
        self.type, self.len, self.value = struct.unpack("BBB",stream)
        #print(self.len)
        #print(self.type)
        #print(self.value)
        if (streamlen != self.len + 2):
            raise Exception("The length of the TLV is not matching the length field")