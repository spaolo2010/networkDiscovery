from tlvs import TLV
import struct
import json
import re
from sub_TLV_Pref_Flags import SUB_TLV_Pref_Flags
from sub_TLV_Prefix_SID import SUB_TLV_Pref_SID

class TLV_Extended_IP_Reach(TLV):

    def __init__(self):
        self.hasSubTLV = None
        self.type = None
        self.len = None
        self.ip_bin =b''
        self.firstoctect = None
        self.secondoctect = None
        self.thirdoctect = None
        self.fourthoctect = None
        self.prefixes=[]


        self.packet_status ={
                        'type' : False,
                        'length' : False,
                        'metric' : False,
                        'prefix' : False

        }

    def setType(self,type):
        if (type != 135):
            raise ValueError("Type code is wrong")
        else:
            self.type = type
            self.packet_status['type'] = True
    def getType(self):
        pass

    def setMetric(self,cost):
        if ( not isinstance(cost,int)):
            raise Exception("Metric not an int")
        else:
            if (cost < 0 or cost > 4294967296):
                raise Exception ("Cost value out of range")
            else:
                self.metric = cost
                self.packet_status['metric'] =  True
    def setLength(self):
        pass
    def calcTLVLen(self):
        global sub_tlv_pres
        sub_tlvs_binary =b''
        sub_tlv_pres = False
        tlv_bin = self.getBinary()
        if len(self.sub_tlvs) != 0:
            sub_tlv_pres = True
            for sub_tlv in self.sub_tlvs:
                tlv_bin += sub_tlv.getBinary()


        else:
            raise Exception('Sub TLV(s) not present ')
        self.len =  len(tlv_bin)

    def add_sub_tlv(self,prefixes):
         for prefix in prefixes:
             if ('ipaddress' not in prefix or 'mask' not in prefix or 'metric' not in prefix or 'sub_tlv' not in prefix ):
                 raise Exception('One of the keys is not present')
             else:
                 # check IP
                 if (not re.match("[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+",prefix['ipaddress'])):
                    raise Exception('ip address format is wrong')
                 elif ( prefix['mask'] < 0  or prefix['mask'] > 32):
                     raise Exception ('MAsk out of range')
                 elif ( not isinstance (int, prefix['metric'])):
                     raise Exception ('Metric is not an integer')
                 else:
                      global found
                      found = False
                      for installed_prefix in self.prefixes:
                          if (prefix['ipaddress']  == installed_prefix['ipaddress']):
                              found = True
                              raise Exception('ipaddress already existing')
                      if (found == False):
                          tmp_prefix = {}
                          tmp_prefix['ipaddress'] = prefix['ipaddress']
                          tmp_prefix['mask'] = prefix['mask']
                          tmp_prefix['metric'] = prefix['metric']
                          tmp_prefix ['sub_tlv'] = prefix['sub_tlv']
                          self.prefixes.append(tmp_prefix)


    def isPrefixpresent(self,mask,ipaddress):
        for prefix in self.prefixes:
            if ( ipaddress == prefix['ipaddress'] and mask == prefix['mask']):
                return True
        return False

    def isTLVPresent(self,ipaddress,mask,type):
         for prefix in self.prefixes:
             if ( ipaddress == prefix['ipaddress'] and mask == prefix['mask']):
                  for sub_tlv in self.prefix['sub_tlv']:
                      if (sub_tlv.getType() == type):
                          return True


         return False


    def getSubTLVsBinary(self):
        self_tlv_binary = b''
        for sub_tlv in self.sub_tlvs:
            self_tlv_binary += sub_tlv.getBinary()
        if (len(self_tlv_binary) == 0):
            raise Exception('No TLVs present')

        return self_tlv_binary

    def setValuesFromBinary(self, stream):
        leftcounter = 0
        rightcounter = 1

        self.type=struct.unpack("!B",stream[:rightcounter])[0]
        rightcounter +=1
        leftcounter+=1
        self.len = struct.unpack("!B",stream[leftcounter:rightcounter])[0]
        #print(self.len)
        leftcounter += 1
        rightcounter += 4
        while (rightcounter <=len(stream)):

            prefixandsubtlvs={}
            metric = struct.unpack("!I",stream[leftcounter:rightcounter ])[0]

            leftcounter += 4
            rightcounter +=1


            maskandsub = struct.unpack("!B",stream[leftcounter:rightcounter])[0]
            mask = maskandsub & 63
            #print (mask)

            leftcounter += 1
            rightcounter += 4

            global oct4
            oct1,oct2,oct3,oct4 =  struct.unpack("!BBBB",stream[leftcounter:rightcounter ])
            if (oct4==3 and mask != 32):
                leftcounter-=1
                rightcounter-=1
                oct4=0
            #print(oct1,oct2,oct3,oct4)
            ipaddress = str(oct1) + '.' + str(oct2) + '.' + str(oct3) + '.' + str(oct4)

            prefixandsubtlvs['ipaddress'] = ipaddress
            prefixandsubtlvs['metric'] = metric
            prefixandsubtlvs['mask'] = mask

            leftcounter += 4
            rightcounter += 1
            sub_tlv_len =struct.unpack("!B",stream[leftcounter:rightcounter])[0]
            #print (leftcounter, rightcounter)

            print (ipaddress)
            if (sub_tlv_len != 0):
                leftcounter, rightcounter=   self.sub_tlv_processing(stream,leftcounter,rightcounter,sub_tlv_len,prefixandsubtlvs)

            self.prefixes.append(prefixandsubtlvs)
            rightcounter += 4
            #print(leftcounter, rightcounter)

    def getSubTLVsandTLVBinary(self):
        pass
    def separateMaskFromIsSubTLV(self):
        pass
    def getBinary(self):
        pass
    def getLen(self):
        pass
    def sub_tlv_processing(self, stream , leftindex , rightindex,sub_tlv_len,prefixandsubtlvs):


        endsubtlv_counter = rightindex + sub_tlv_len

        prefixandsubtlvs['sub_tlv'] =[]
        while (rightindex < endsubtlv_counter -1 ):
            leftindex += 1
            rightindex += 1
            sub_type = struct.unpack("!B", stream[leftindex:rightindex])[0]
            #print("TYPE " + str(sub_type))
            #print ("RIGHT " + str(rightindex))
            if (sub_type == 4):
               initchunk = leftindex
               leftindex += 1
               rightindex += 1
               sub_len = struct.unpack("!B",stream[leftindex:rightindex])[0]
               #print (sub_len)
               #leftindex += 1
               rightindex += sub_len
               leftindex = rightindex - 1
               endchunk = rightindex
               #rightindex+=1
               prefix_flag = SUB_TLV_Pref_Flags()
               #print (b"VALUESTRING: " + stream[initchunk:endchunk])
               prefix_flag.setValuesFromBinary(stream[initchunk:endchunk])

               prefixandsubtlvs['sub_tlv'].append(prefix_flag)
            elif(sub_type == 3):
                initchunk = leftindex
                leftindex += 1
                rightindex += 1
                sub_len = struct.unpack("!B", stream[leftindex:rightindex])[0]
                # print (sub_len)
                # leftindex += 1
                rightindex += sub_len
                leftindex = rightindex - 1
                endchunk = rightindex
                prefix_sid = SUB_TLV_Pref_SID()
                prefix_sid.setValuesFromBinary(stream[initchunk:endchunk])
                prefixandsubtlvs['sub_tlv'].append(prefix_sid)


            else:
                initchunk = leftindex
                leftindex += 1
                rightindex += 1
                sub_len = struct.unpack("!B", stream[leftindex:rightindex])[0]

                rightindex += sub_len
                endchunk = rightindex
                leftindex = rightindex - 1

                #print (b"BINARY: " + stream[initchunk:endchunk])

        print ("END SUB PROCESSING")
        leftindex=rightindex

        return leftindex, rightindex

    def setValue(self,prefix,metric):

        if (not re.match("[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", prefix)):
            raise ValueError("Wrong IP value")
        else:
            self.prefix = prefix
            value_parts = prefix.split('.')

            self.firstoctect = int(value_parts[0])
            self.secondoctect = int(value_parts[1])
            self.thirdoctect = int(value_parts[2])
            self.fourthoctect = int(value_parts[3])
            self.packet_status['prefix'] = True

            self.setMetric(metric)

            #combined = struct.pack(">BBBB", firstoctect, secondoctect, thirdoctect, fourthoctect)
            #self.ip_bin = combined

    def printTLVData(self):
        print (self.prefixes)
        #print ('TLV DATA')
        lst_tlvs=[v1.__dict__ for a in self.prefixes for k,v in a.items() if k == 'sub_tlv' for v1 in v]
        print (lst_tlvs)
    def getSubTLVLen(self):
        pass

def main():
    tlv = TLV_Extended_IP_Reach()
    # LSP b'\x00j\x04\xaa\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x1fpF\x03\x07\x04\x00\xc8\x00\x00\x01\x04\x03I\x00\x01\x81\x01\xcc\x89\x05vsim3\x84\x04\xc0\xa8!\x06\x87\x19\x00\x00\x00\n^\xc0\xa8!\x04\x03\x04\x01\x00\x00\x00\x00\nX\xc0\xa8M\x03\x04\x01\x00\x16\x16\x00\x00\x00\x00\x00\x01\x00\x00\x00\n\x003333""\x00\x00\x00\n\x00'
    #TLV =b'\x87\x19\x00\x00\x00\n^\xc0\xa8!\x04\x03\x04\x01\x00\x00\x00\x00\nX\xc0\xa8M\x03\x04\x01\x00'
    TLV =b'\x87]\x00\x00\x00\x00`\x02\x02\x02\x01\x11\x03\x06p\x00\x00\x00\x00\x01\x04\x01 \x0b\x04\x02\x02\x02\x01\x00\x00\x00\n`\x16\x16\x16\x01\x11\x03\x06p\x00\x00\x00\x00o\x04\x01 \x0b\x04\x02\x02\x02\x01\x00\x00\x00\n^\xc0\xa8!\x04\x03\x04\x01\x00'
    #l=0
    #r=1
    #while
    tlv.setValuesFromBinary(TLV)
    tlv.printTLVData()
    leftcounter = 0


if __name__ == '__main__':
    main()
