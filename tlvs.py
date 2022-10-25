from abc import ABC, abstractmethod
class TLV (ABC):

        @abstractmethod
        def setLength(self,len):
            pass

        @abstractmethod
        def setValue(self,value):
            pass

        @abstractmethod
        def setType(self,type):
            pass

        @abstractmethod
        def getLen(self):
            pass

        @abstractmethod
        def getBinary(self):
            pass

        @abstractmethod
        def getType(self):
            pass