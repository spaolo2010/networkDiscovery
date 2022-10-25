# This is a sample Python script.
from socket import socket ,AF_INET, SOCK_RAW
# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import psutil

def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    print(f'Hi, {name}')  # Press Ctrl+F8 to toggle the breakpoint.

    addrs = psutil.net_if_addrs()
    print(list(addrs.keys()))

    s = socket(AF_INET,SOCK_RAW)
    s.bind(("Local Area Connection", 0))
    """
    # We're putting together an ethernet frame here,
    # but you could have anything you want instead
    # Have a look at the 'struct' module for more
    # flexible packing/unpacking of binary data
    # and 'binascii' for 32 bit CRC
    src_addr = "\x01\x02\x03\x04\x05\x06"
    dst_addr = "\x01\x02\x03\x04\x05\x06"
    payload = ("[" * 30) + "PAYLOAD" + ("]" * 30)
    checksum = "\x1a\x2b\x3c\x4d"
    ethertype = "\x08\x01"

    s.send(dst_addr + src_addr + ethertype + payload + checksum)
    """
# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    print_hi('PyCharm')

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
