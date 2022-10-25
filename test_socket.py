from scapy.all import *

def main():

    IFACES.show()  # let’s see what interfaces are available. Windows only
    iface = "Intel(R) Wi-Fi 6 AX201 160MHz"
   # iface = << "full iface name" >> or << IFACES.dev_from_index(12) >> or << IFACES.dev_from_pcapname(
    #    r"\\Device_stuff") >>
    socket = conf.L2socket(iface=iface)
    # socket is now an Ethernet socket
    ### RECV
    #packet_raw = socket.recv_raw()[0]  # Raw data
    #print (packet_raw)
    a = True
    while (a == True):

        packet_decoded = socket.recv(1000)  # Using the library (also contains things like sent time...)
        if (packet_decoded != None):
            a = False
    print (packet_decoded)
    ### SEND
    socket.send(b"\x00......") # send raw data
    #socket.send(Ether() / IP(dst="www.google.com") / TCP() / Raw(load=b"data"))  # use library


if __name__ == '__main__':
    main()