import struct
import re
from tlv_protocolType import  TLV_Protocol_Supported
from tlv_area_id import  TLV_Area_Id
from tlv_interface_ip import TLV_interface_ip
from tlv_p2p_adjcency_state import TLV_P2P_Adjacency_State
from tlv_instance import TLV_Instance_Id
from utils import SystemIdConverter



class ISIS_HELLO:

    def __init__(self):
        self.tlvs=[]
        self.holdtime = None
        self.ckttype = None
        self.system_id= None
        self.priority= None
        self.PDUlen = None
        self.localcktid = None
        self.system_id_1 = None
        self.system_id_2 = None
        self.system_id_3 = None
        self.system_id_4 = None
        self.system_id_5 = None
        self.system_id_6 = None
        self.interface_type = None

        self.packet_status={
                      'holdtime': False,
                      'ckttype' : False,
                      'system_id': False,
                      'localcktid': False,
                      'PDUlen': False,
                      'interface_type' : False


        }



    def setInterfaceType(self,interface_type):
        if (interface_type != "p2p"):
            raise Exception("Interface type should be point to point, (p2p)")
        else:
            self.interface_type = interface_type
            self.packet_status['interface_type'] = True
    def setSystemId(self,system_id):
        if (re.match("\d{4}\.\d{4}\.\d{4}",system_id)):
            parts_sys_id=system_id.split('.')

            self.system_id = system_id
            system_id_numeric = parts_sys_id[0] + parts_sys_id[1] + parts_sys_id[2]
            #self.system_id = self.system_id.encode('ascii')
            self.system_id_1,self.system_id_2,self.system_id_3,self.system_id_4,self.system_id_5,self.system_id_6 =   SystemIdConverter.convertSystemId(system_id_numeric)
            self.packet_status['system_id'] = True
        else:
            raise ValueError("System ID not correct")
    def getSystemId(self):
        if (self.system_id == None):
            raise Exception("System ID not set")
        else:
            return self.system_id
    def generateLocalCktId(self):
        import random as rand
        self.localcktid=int(rand.random() * 100)
        self.packet_status['localcktid'] = True
    def getLocalCktId(self):
        return self.localcktid
        #print (self.localcktid)
    def setCktType(self,cktype):
        if (cktype =='level_1' or cktype =='level_2'):
            if (cktype == "level_1"):
                self.ckttype = 1
                self.packet_status['ckttype'] = True
            else:
                self.ckttype = 2
                self.packet_status['ckttype'] = True
        else:
            raise ValueError("Level is not correct")

    def setHoldTime(self,holdtime):
        if (not isinstance(holdtime , int)):
            raise ValueError("Hold time not an integer")
        else:
            if (holdtime < 1 or holdtime > 255):
                raise ValueError("Hold time value out of range")
            else:
                #print("set holdtime")
                self.holdtime = holdtime
                self.packet_status['holdtime'] = True
    def getHoldTime(self):
        if (self.holdtime == None):
            raise Exception("Holdtime not set")

        else:
            return self.holdtime
    def setPriority(self,priority):
        if  (priority < 1 or priority > 255):
            raise ValueError("priority out of range")


    def add_tlv(self,tlv):
        for tlv1 in self.tlvs:
            if (isinstance(tlv1,TLV_Protocol_Supported) and type(tlv1) == type(tlv)):
                raise Exception("TLV Protocol Type already present")
            elif(isinstance(tlv1,TLV_interface_ip) and type(tlv1) == type(tlv)):
                raise Exception("TLV interface IP already present")
            elif(isinstance(tlv1,TLV_P2P_Adjacency_State) and type(tlv1) == type(tlv)):
                raise Exception("TLV point to point adjacency already present")
            elif (isinstance(tlv1,TLV_Area_Id) and type(tlv1) == type(tlv)):
                raise Exception("TLV area ID already present")
            elif (isinstance(tlv1, TLV_Instance_Id ) and type(tlv1) == type(tlv)):
                raise Exception("TLV Instance ID already present")


        if (isinstance(tlv,TLV_Protocol_Supported)):
            self.tlvs.append(tlv)
            #print ("Add TLV Prot")
        elif (isinstance(tlv, TLV_interface_ip)):
            self.tlvs.append(tlv)
            #print("Add tlv int")
        elif (isinstance(tlv, TLV_P2P_Adjacency_State)):
            self.tlvs.append(tlv)
            #print("P2P adj")
        elif (isinstance(tlv, TLV_Area_Id)):
            self.tlvs.append(tlv)
            #print("Add tLV aree id")
        elif (isinstance(tlv,TLV_Instance_Id)):
            self.tlvs.append(tlv)
            #print("Add tLV instance id")
        else:
            raise Exception ("TLV not recognised")
    def get_tlv(self,type):
        global found
        found = False
        for tlv in self.tlvs:
            if (tlv.getType() == type):

               return tlv
        return None
    def is_tlv_present(self,type):
        global found
        found = False
        for tlv in self.tlvs:
            if (tlv.getType() == type):

               found = True
        return found



    def setPDULength(self,len):
        self.PDUlen = len
        self.packet_status['PDUlen'] = True


    def getPDULength(self):
        if (self.PDUlen == None):
            raise ValueError("PDULength is not set")
        else:
            return self.PDUlen
    def populateHelloFieldsFromStream(self,stream):
        if (len(stream) != 12):
            raise Exception ("Hello stream is less than 12 bytes")
        else:
            self.ckttype, self.system_id_1,\
            self.system_id_2, self.system_id_3, self.system_id_4, self.system_id_5,\
            self.system_id_6, self.holdtime, self.PDUlen, self.localcktid = struct.unpack("!BBBBBBBHHB",stream)
            self.system_id = str("{0:0=2d}".format(int(str(hex(self.system_id_1))[2:]))) +\
                             str("{0:0=2d}".format(int(str(hex(self.system_id_2))[2:])))  + "."+ \
                             str("{0:0=2d}".format(int(str(hex(self.system_id_3))[2:]))) + \
                             str("{0:0=2d}".format(int(str(hex(self.system_id_4))[2:]))) + "." + \
                             str("{0:0=2d}".format(int(str(hex(self.system_id_5))[2:]))) + \
                             str("{0:0=2d}".format(int(str(hex(self.system_id_6))[2:])))
            #print (self.system_id)



            #print ("{0:0=2d}".format(self.system_id_1),self.system_id_2,self.system_id_3,self.system_id_4,self.system_id_5,self.system_id_6)
            #print (self.holdtime,self.PDUlen)
            #print(self.ckttype)
            #print (self.system_id)
    def getBinary(self):
        global hellostream
        hellostream = b''
        #print (self.packet_status)
        #print (self.system_id_1)
        #print(self.system_id_2)
        #print(self.system_id_3)
        #print(self.system_id_4)
        #print(self.system_id_5)
        #print(self.system_id_6)
        if (False in self.packet_status.values()):
            #print(self.packet_status)
            raise ValueError( "Some of  field(s) " +  str(self.packet_status.keys())  + " is/are not set")

        else:
            hellostream= struct.pack(">BBBBBBBHHB",self.ckttype, self.system_id_1,
                                     self.system_id_2, self.system_id_3, self.system_id_4, self.system_id_5,
                                     self.system_id_6,self.holdtime,self.PDUlen,self.localcktid)
            #for tlv in self.tlvs:
                #hellostream+=tlv.getBinary()
            return hellostream
    def getTLVsBinary(self):
        all_tlv_binary=b''
        if (len(self.tlvs) == 0):
            raise Exception("TLV list is not populated")
        #print ("LEN TLVs ", len(self.tlvs))
        for tlv in self.tlvs:
            if (isinstance(tlv, TLV_Protocol_Supported)):
               all_tlv_binary+=tlv.getBinary()
               #print ("GET PROT SUPPORTED")
            elif (isinstance(tlv, TLV_interface_ip)):
                all_tlv_binary+=tlv.getBinary()
                #print("GET INT IP")
            elif (isinstance(tlv, TLV_P2P_Adjacency_State)):
                all_tlv_binary += tlv.getBinary()

                #print("GET ADJ ", tlv.getBinary())
            elif (isinstance(tlv, TLV_Area_Id)):
                all_tlv_binary+=tlv.getBinary()
                #print("AREA ID")
            elif (isinstance(tlv, TLV_Instance_Id)):
                all_tlv_binary += tlv.getBinary()
                #print("INSTANCE ID")
            #print    ( all_tlv_binary)
        return all_tlv_binary



# nterface,holdtime,level,int_type,system_id,area_id




def main():

    """
    LSP=b'\x01_\x04\xa0\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00*\xc7\xbe\x03\x07\x04\x00d\x00\x00\x01\x04\x03I\x00\x01\x81\x01\xcc\x84\x04\x02\x02\x02\x03\x86\x04\x02\x02\x02\x03\x87v\x00\x00\x00\x00`\x02\x02\x02\x03\x11\x03\x06p\x00\x00\x00\x00\x03\x04\x01 \x0b\x04\x02\x02\x02\x03\x00\x00\x00\x00`\x04\x04\x04\x02\x03\x04\x01\x80\x00\x00\x00\x00`\x17\x17\x17\x01\x11\x03\x06p\x00\x00\x00\x00r\x04\x01 \x0b\x04\x02\x02\x02\x03\x00\x00\x00\n^\xc0\xa8!\x04\x03\x04\x01\x00\x00\x00\x00\n^\xc0\xa8!\x0c\x03\x04\x01\x00\x00\x00\x00\n^\xc0\xa8!\x10\x03\x04\x01\x00\x00\x00\x00\nX\xc0\xa8M\x03\x04\x01\x00\x89\x05vsim3\xf2#\x02\x02\x02\x03\x00\x02\t\x80\x00\x07\xd1\x01\x03\x00>\x80\x16\t\x00\x00\x03\xe8\x01\x03\x00:\x98\x17\x02\x01\n\x13\x02\x00\x01\x16\x833333""\x00\x00\x00\nx\x04\x08\x00\x00\x00\x0e\x00\x00\x024\x06\x04\xc0\xa8M\x12\x08\x04\xc0\xa8M\x11\x03\x04\x00\x00\x00\x00\t\x04L\xeek(\n\x04\x00\x00\x00\x00\x0b \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x12\x03\x00\x00\n\xfc \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x050\x00\x00]\xc3'

    leftcounter=4
    rightcounter =6
    checksum =0
    print (LSP[4:6])
    while (rightcounter < len(LSP)):
        #if (leftcounter != 16 ):
        chunk = struct.unpack("H",LSP[leftcounter:rightcounter])[0]
        #else:
        #print (LSP[leftcounter:rightcounter])
        #chunk = 0
        checksum+=chunk
        if (checksum > 65535):

           b = (checksum & 983040) >> 16
           c = (checksum & 65535)
           checksum = b + c
        rightcounter+=2
        leftcounter +=2
    print (checksum)
    """
    #a=149404
    #b = (a & 983040) >> 16
    #c = (a & 65535)
    #print (c+b)




if __name__ == '__main__':
    main()