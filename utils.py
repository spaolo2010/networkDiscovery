import math
import struct
import re
import traceback as tb
class converter:
  @classmethod
  def return_binary_from_hex_string(cls,lst_str : list):
      global digit
      global hexa
      binary=b''
      for ele in lst_str:
          hexa=0
          c=len(ele) - 1
          for chr in ele:
              digit=chr
              if (not chr.isdigit()):
                  digit=cls.returnNumberFromLetter(chr)
              hexa+=int(digit)*int(math.pow(16,c))
              c-=1
          binary+=struct.pack('B',hexa)
      return binary

      #print (cls.returnNumberFromLetter(lst_str))


  def returnNumberFromLetter(letter):
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


class SystemIdConverter:

    def fromLetterReturnNumber(letter):
        if (letter.upper() == 'A' ):
            return 10
        elif (letter.upper() == 'B' ):
            return 11
        elif (letter.upper() == 'C' ):
            return 12
        elif (letter.upper() == 'D' ):
            return 13
        elif (letter.upper() == 'E'):
            return 14
        elif (letter.upper() == 'F'):
            return 15
        else:
            return -1
    @classmethod
    def divideSystemIDIntoSixBytes(cls,part):
        firstdigit=-1
        secondigit= 0
        decimal=0
        exponent=0
        global character
        while (firstdigit >= -2 ):
            if (secondigit == 0):
                character = part[firstdigit:]
               #print (character)
            else:
                character = part[firstdigit:secondigit]
            if (re.match("[A-Z]+", character)):
                #print("char")
                character=cls.fromLetterReturnNumber(character)
                if (character == -1):
                    raise Exception("System ID contain unknown characters ")
            #print (character)
            dec_digit = int(int(character)*(math.pow(16,exponent)))
            decimal = decimal + dec_digit
            firstdigit-=1
            secondigit-=1
            exponent+=1
        return decimal
        #print (decimal,part)

    @classmethod
    def convertSystemId(cls,system_id):

        system_id_parts=[]
        firstdigit = -2
        seconddigit= 0
        #print(test[-4: -2])
        try:

            while ( firstdigit >= len(system_id) *(-1)):
                  if ( seconddigit== 0):
                      #print (test[ firstdigit:])
                      system_id_parts.append(cls.divideSystemIDIntoSixBytes(system_id[ firstdigit:]))

                  else:
                      system_id_parts.append(cls.divideSystemIDIntoSixBytes(system_id[firstdigit:seconddigit]))
                      #print(test[firstdigit: seconddigit])
                  seconddigit -= 2
                  firstdigit-=2
            if (len(system_id_parts) == 6):
                return system_id_parts[5], system_id_parts[4], system_id_parts[3],system_id_parts[2],system_id_parts[1],system_id_parts[0]

            else:
               raise Exception("System ID length not matching")
        except Exception as e:
            tb.print_exc()
        #print (len(test) *(-1))

class calcChecksum:
    @classmethod
    def calculate (cls, LSP):
        leftcounter = 4
        rightcounter = 5
        global firstoctet
        global secondoctet
        firstoctet = 0
        secondoctet= 0
        #print (LSP)
        global C0

        C0 = 0
        C1 = 0
        L = len(LSP)
        print (L)
        global Octet
        Octet = None
        while (rightcounter <= L ):

            # print (Octet)
            # if the Octets are referring to the checksum set Octet variable to 0
            if (leftcounter >= 16 and leftcounter <= 17):

                Octet = 0

            else:
                #print(LSP[leftcounter:rightcounter])
                Octet = struct.unpack("B", LSP[leftcounter:rightcounter])[0]

            C0 = C0 + Octet
            C1 = C1 + C0

            leftcounter += 1
            rightcounter += 1


        X = ((L - 17) * C0 - C1) % 255
        Y = ((L - 16) * (-C0) + C1) % 255
        print (hex(X))
        print (hex(Y))
        if (X == 0):
            X = 255
        if (Y == 0):
            Y = 255


        return (Y & 65535) | (X & 65535) << 8
        #return (X & 65535) | (Y & 65535) << 8

