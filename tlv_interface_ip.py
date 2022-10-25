from tlvs import TLV
import struct
import re
class TLV_interface_ip(TLV):

    def __init__(self):
        self.value = None
        self.type = None
        self.len = None
        self.ip_bin = None
        self.packet_status ={'type': False , 'length' : False , 'value' : False}
    def setType(self,type):
        if (type != 132):
            raise ValueError("Wrong type")
        else:
            self.type = type
            self.packet_status['type'] = True
    def setValue(self,value):
        #print ("VALUE ",value)
        if (not re.match("[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+",value)):
            raise ValueError("Wrong IP value")
        else:
            self.value = value
            value_parts=value.split('.')

            firstoctect = int(value_parts[0])
            secondoctect = int(value_parts[1])
            thirdoctect = int(value_parts[2])
            fourthoctect = int(value_parts[3])

            combined = struct.pack(">BBBB",firstoctect,secondoctect,thirdoctect,fourthoctect)
            self.ip_bin=combined
            #var = struct.pack('iii', 9, 2, 3)
            #print(var)
            #print (self.value)
            self.packet_status['value'] = True
    def setLength(self,len):
        if (len != 4):
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
            return struct.pack(">BB",self.type,self.len) + self.ip_bin
    def setValuesFromBinary(self,stream):
        global first , second , third , fourth
        self.type, self.len, first, second, third, fourth = struct.unpack("BBBBBB",stream)
        self.value= str(first) +"." + str(second) + "." + str(third) +"." + str(fourth)
        #print (self.value)

        #print (self.type)
        #print (self.len)

def main():
    area_id = TLV_interface_ip()
    area_id.setValue("10.0.0.11")
    area_id.setType(132)
    area_id.setLength(4)
    #print(area_id.getBinary())

if __name__ == '__main__':
    main()