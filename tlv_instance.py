from tlvs import TLV
import struct

class TLV_Instance_Id(TLV):

    def __init__(self):
        self.value = None
        self.type = None
        self.len = None
        self.itid = 0
        self.packet_status = {'type': False, 'length': False, 'value': False}
    def setType(self, type):
        if (type != 7):
            raise ValueError("Wrong type")
        else:
            self.type = type
            self.packet_status['type'] = True

    def setLength(self, len):
        if (len != 4):
            raise ValueError("Wrong length")
        else:
            self.len = len
            self.packet_status['length'] = True
    def setValue(self,value):
        if (value < 0 or value > 65535):
            raise Exception("Instance ID out of range")
        else:
            self.packet_status['value'] = True
            self.value = value

    def getType(self):
        if (self.type == None):
            raise ValueError("Type not set")
        else:
            return self.type

    def getLen(self):
        if (self.len == None):
            raise ValueError("Length not set")
        else:
            return self.len

    def getValue(self):
        if (self.value == None):
            raise ValueError("Value not set")
        else:
            return self.value
    def getBinary(self):
        if (False in self.packet_status.values()):
            raise ValueError("Some of  field(s) " + str(self.packet_status.keys()) + " is/are not set")
        else:
            return struct.pack(">BBHH", self.type, self.len,self.value,self.itid)

    def setValuesFromBinary(self,stream):
        streamlen= len (stream)
       # print (stream)
        self.type, self.len, self.value, self.itid= struct.unpack("!BBHH",stream)
        #print ("instance_id")
        #print(self.len)
        #print (self.type)
        #print (self.value)
        if  (streamlen != self.len + 2):
            raise Exception("The length of the TLV is not matching the length field")