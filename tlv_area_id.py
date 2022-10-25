from tlvs import TLV
import struct
import re
import math
class TLV_Area_Id(TLV):

    def __init__(self):
        self.value = None
        self.type = None
        self.len = None
        self.area_id_1 = None
        self.area_id_2 = None
        self.area_id_3 = None
        self.number_of_areas=3
        self.packet_status ={'type': False , 'length' : False , 'value' : False}
    def setType(self,type):
        if (type != 1):
            raise ValueError("Wrong type")
        else:
            self.type = type
            self.packet_status['type'] = True
    def setValue(self,value):
        if (not re.match("\d{2}\.\d{4}", value)):
            raise ValueError("Wrong value")
        else:

            value_parts=value.split('.')
            value1 = value_parts[0] + value_parts[1]
            #self.value = self.value.encode('ascii')
            #self.value = number_of_areas +self.value
            self.convertAreaId(value1)
            self.value = value
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
        #print(self.area_id_1)
        #print(self.area_id_2)
       # print(self.area_id_3)
        if (False in self.packet_status.values()):
            raise ValueError("Some of  field(s) " + str(self.packet_status.keys()) + " is/are not set")
        else:
            return struct.pack(">BBBBBB",self.type,self.len,self.number_of_areas, self.area_id_1,self.area_id_2,self.area_id_3)
    def setValuesFromBinary(self,stream):
        streamlen = len(stream)
        self.type, self.len, value1,value2,value3,value4 = struct.unpack("!BBBBBB",stream)
        #print(self.len)
        #print(self.type)
        #print ("VALUE",value2)
        strvalue2=str("{0:0=2d}".format(int(str(hex(value2))[2:])))
        strvalue3=str("{0:0=2d}".format(int(str(hex(value3))[2:])))
        strvalue4 =str("{0:0=2d}".format(int(str(hex(value4))[2:])))
        self.value=strvalue2+"."+strvalue3+strvalue4
        #print (self.value)

        #print(value2)
        #print(value3)
        #print(value4)
        if (streamlen != self.len + 2):
            raise Exception("The length of the TLV is not matching the length field")

    def fromLetterReturnNumber(self, letter):
        if (letter.upper() == 'A'):
            return 10
        elif (letter.upper() == 'B'):
            return 11
        elif (letter.upper() == 'C'):
            return 12
        elif (letter.upper() == 'D'):
            return 13
        elif (letter.upper() == 'E'):
            return 14
        elif (letter.upper() == 'F'):
            return 15
        else:
            return -1

    def divideAreaIDIntoBytes(self, part):
        firstdigit = -1
        secondigit = 0
        decimal = 0
        exponent = 0
        global character
        while (firstdigit >= -2):
            if (secondigit == 0):
                character = part[firstdigit:]
            # print (character)
            else:
                character = part[firstdigit:secondigit]
            if (re.match("[A-Z]+", character)):
                # print("char")
                character = self.fromLetterReturnNumber(character)
            # print (character)
            dec_digit = int(int(character) * (math.pow(16, exponent)))
            decimal = decimal + dec_digit
            firstdigit -= 1
            secondigit -= 1
            exponent += 1
        return decimal
        # print (decimal,part)

    def convertAreaId(self, area_id):
        pass
        test = "222233331111"
        area_id_parts = []
        firstdigit = -2
        seconddigit = 0
        # print(test[-4: -2])
        while (firstdigit >= len(area_id) * (-1)):
            if (seconddigit == 0):
                # print (test[ firstdigit:])
                area_id_parts.append(self.divideAreaIDIntoBytes(area_id[firstdigit:]))

            else:
                area_id_parts.append(self.divideAreaIDIntoBytes(area_id[firstdigit:seconddigit]))
                # print(test[firstdigit: seconddigit])
            seconddigit -= 2
            firstdigit -= 2
        if (len(area_id_parts) == 3):
            self.area_id_1 = area_id_parts[2]
            self.area_id_2 = area_id_parts[1]
            self.area_id_3 = area_id_parts[0]

        else:
            raise Exception("Area ID length not matching")
        # print (len(test) *(-1))

def main():
    area_id = TLV_Area_Id()
    area_id.setValue("49.0001")
    area_id.setType(1)
    area_id.setLength(4)
   # print(area_id.getBinary())

if __name__ == '__main__':
    main()