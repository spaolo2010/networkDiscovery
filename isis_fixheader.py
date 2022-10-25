
import struct
class ISIS_FixHeader:
    def __init__(self):
        self.protocolDiscriminator = None
        self.lengthIndicator =None
        self.protocol_ID_extension = None
        self.IDLength = None
        self.protocolType = None
        self.version = None
        self.reserved = None
        self.max_area_address = None
        self.binary =  None
        self.populated_fields_count= 0
    def populateFixFields(self,packetType):
        self.protocolDiscriminator = 131
        if (packetType ==  'hello'):
            self.lengthIndicator = 20
        elif (packetType ==  'lsp'):
            self.lengthIndicator = 27
        elif (packetType == 'psnp'):
            self.lengthIndicator = 17
        self.protocol_ID_extension = 1
        self.IDLength = 0
        self.protocolType = 17
        self.version = 1
        self.reserved = 0
        self.max_area_address = 0
        self.populated_fields_count = 9
    def setPacketType(self,packet_type):
        if (packet_type != 17 and packet_type != 20 and packet_type != 27):
            raise ValueError("IS-IS packet type is wrong")
        else:
            self.protocolType = packet_type
            self.populated_fields_count+=1
    def getBinary(self):
        if (self.populated_fields_count != 10):
            raise Exception("One or few  fields are not populated")
            return -1
        else:
            return struct.pack(">BBBBBBBB",self.protocolDiscriminator,self.lengthIndicator,self.protocol_ID_extension
                           ,self.IDLength,self.protocolType,self.version,self.reserved,self.max_area_address)
    def setValuesFromStream(self,stream):
        if (len(stream) != 8):
            raise Exception ("The fix header length is not 8 btyes")
        else:
            self.protocolDiscriminator, self.lengthIndicator, \
                    self.protocol_ID_extension, self.IDLength,self.protocolType, \
                    self.version, self.reserved,self.max_area_address = struct.unpack("BBBBBBBB",stream)

