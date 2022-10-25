from tlvs import TLV
import struct

class SUB_TLV_Pref_SID(TLV):
    def __init__(self):
        self.sid = 0
        self.flag = 0
        self.algorithm = 0
        self.type = None
        self.length = None
        self.packet_status ={

            'type' : False,
            'value' : False,
            'length' : False
        }

    def setType(self,type):
        if (type != 3):
            raise ValueError("Wrong type")
        else:
            self.type = type
            self.packet_status['type'] = True
        pass
    def setLength(self,length):
        if (length != 6):
            raise ValueError("Wrong length")
        else:
            self.length = length
            self.packet_status['length'] = True

    def setValue(self,value):
        pass
    def getType(self):
        if (self.type == None):
            raise Exception ("The Type is not set")
        return self.type
    def getLen(self):
        if (self.length == None):
            raise Exception("The Type is not set")
        return self.type
    def getSID(self):
        return self.sid
    def getFlags(self):
        return self.flags
    def getBinary(self):
        if (False in self.packet_status.values()):
            raise ValueError("Some of  field(s) " + str(self.packet_status.keys()) + " is/are not set")
        else:
            return struct.pack(">BBB", self.type, self.length, self.value)

    def setValuesFromBinary(self,stream):
        self.type, self.length, self.flag,self.algorithm,self.sid = struct.unpack("!BBBBI",stream)