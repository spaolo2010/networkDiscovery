from utils  import converter
import struct
class ETHERNET_Frame:
    def __init__(self):
       self.ssap =  254
       self.dsap = 254
       self.payload_length = None
       self.src_mac = None
       self.src_mac_binary=b''
       self.dst_mac_binary=b'\x01\x00\x5e\x90\x00\x02'
       self.control_field=3
    def setSourceMac(self,mac_address):
       if (":" in mac_address):
           parts_mac =mac_address.split(":")
           if (len(parts_mac) == 6):
               if (self.parse_MacAddress(parts_mac) == True):
                   raise Exception("some of the mac address characters are not correct")
               else:
                   self.src_mac=mac_address
                   self.convert_mac_to_binary(parts_mac)
           else:
               raise Exception ("The mac address length is wrong")

       elif ("-" in mac_address):
           parts_mac = mac_address.split("-")
           if (len(parts_mac) == 6):
               if (self.parse_MacAddress(parts_mac) == True):
                   raise Exception("some of the mac address characters are not correct")
               else:
                   self.src_mac = mac_address
                   self.convert_mac_to_binary(parts_mac)
           else:
               raise Exception("The mac address length is wrong")


       else:
           raise Exception ("The separation character is wrong")
    def setlLength(self,length : int):
        if (not isinstance(length , int)):
            raise Exception("The length is not integer")
        else:
            self.payload_length = length
    def getLength(self):
        if self.payload_length == None:
            raise Exception("Length not set")

        else:
            return self.payload_length
    def convert_mac_to_binary(self,mac_address_lst):
        self.src_mac_binary=converter.return_binary_from_hex_string(mac_address_lst)

    def parse_MacAddress(self,parts_mac):
        global incorrect
        incorrect = False
        for part in parts_mac:

            for character in part:
                if (not character.isdigit() and not character.upper() == 'A'
                                        and not character.upper() == 'B'
                                        and not character.upper() == 'C'
                                        and not character.upper() == 'D'
                                        and not character.upper() == 'E'):
                    incorrect = True

                    break
            else:
                print ("BREAK")
                break
        return incorrect
    def getBinary(self):
        if (len(self.src_mac_binary) > 0  and self.payload_length != None and self.src_mac_binary != None):
           eth_frame = self.dst_mac_binary + self.src_mac_binary + struct.pack(">HBBB",self.payload_length ,self.dsap, self.ssap,self.control_field)
        else:
            raise Exception("Missing parameters in the ethernet frame")
        return eth_frame




