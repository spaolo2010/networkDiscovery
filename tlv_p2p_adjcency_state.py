from tlvs import TLV
import struct
import re
class TLV_P2P_Adjacency_State(TLV):

    def __init__(self):
        self.value = None
        self.type = None
        self.extcktid = None
        self.len = None
        self.neighborcktid= None
        self.neighborsystemid = None
        self.system_id_1 = None
        self.system_id_2 = None
        self.system_id_3 = None
        self.system_id_4 = None
        self.system_id_5 = None
        self.system_id_6 = None
        self.packet_status ={'type': False , 'length' : False , 'value' : False}

    def setType(self,type):
        if (type != 240):
            raise ValueError("Wrong type")
        else:
            self.type = type
            self.packet_status['type'] = True
    def setValue(self,value):
        if (value != 0 and value != 1 and value != 2 ):
            raise ValueError("Wrong value")
        else:
            self.value = value
            self.packet_status['value'] = True
            self.generateExtCkt()

    def generateExtCkt(self):
        import random as rand
        self.extcktid  = int(rand.random() * 1000)


    def setLength(self,len):
        if (len != 5 and len != 15):
            raise ValueError("Wrong length")
        else:
            self.len = len
            self.packet_status['length'] = True
    def getLen(self):
        if (self.len == None):
            raise ValueError("Length not set")
        else:
            return self.len
    def getValue (self):
        if(self.value == None):
            raise ValueError("Value not set")
        else:
            return self.value

    def getType(self):
        if (self.type == None):
            raise ValueError("Type not set")
        else:
            return self.type
    def getBinary(self):
        if (False in self.packet_status.values()):
            raise ValueError("Some of  field(s) " + str(self.packet_status.keys()) + " is/are not set")
        else:
            if (self.neighborcktid == None and self.neighborsystemid == None):
                return struct.pack("!BBBI",self.type,self.len, self.value,self.extcktid)
            else:
                return struct.pack("!BBBIBBBBBBI", self.type, self.len, self.value, self.extcktid,
                                   self.system_id_1,self.system_id_2,self.system_id_3 ,self.system_id_4,
                                   self.system_id_5,self.system_id_6)

    def setNeighborSystemId(self,system_id):
        pass

        if (re.match("\d{4}\.\d{4}\.\d{4}",system_id)):
            parts_sys_id=system_id.split('.')


            self.system_id = parts_sys_id[0] + parts_sys_id[1] + parts_sys_id[2]

            self.system_id_1,self.system_id_2,self.system_id_3,self.system_id_4,self.system_id_5,self.system_id_6 =   SystemIdConverter.convertSystemId(self.system_id)
            self.packet_status['system_id'] = True
        else:
            raise ValueError("System ID not correct")
    def setNeighborCktId(self,cktId):
        if (isinstance (cktId, int)):
            self.neighborcktid = cktId
        else:
            raise Exception("Neighbor circuit id not a integer")

    def getNeighborSystemId(self):
         if (self.neighborcktid != None):
            return self.neighborcktid
         else:
             raise Exception("Remote ckt id is None")
    def getNeighborCktId(self):
        if (self.neighborcktid != None):
            return self.neighborsystemid
        else:
            raise Exception("Remote neighbor id is None")

    def setValuesFromBinary(self,stream):
        streamlen= len (stream)
       # print ("TLV p2p_adj", stream)
        #print ("TLV p2p",streamlen)
        if (streamlen == 7 ):
            self.type, self.len, self.value, self.extcktid = struct.unpack("!BBBI",stream)
        elif (streamlen == 17):
            self.type, self.len, self.value, self.extcktid,self.system_id_1, \
                    self.system_id_2,self.system_id_3,self.system_id_4,self.system_id_5, \
                    self.system_id_6 ,self.neighborcktid = struct.unpack("!BBBIBBBBBBI", stream)
        #print(self.len)
        #print (self.type)
        #print (self.value)
        if  (streamlen != self.len + 2):
            raise Exception("The length of the TLV is not matching the length field")