#!/usr/bin/python

import struct
import socket
import binascii

def parseETH(header):
    ethernetHeader = pkt[0][0:14]       #ethernet header is 14 bytes
    #First 6 bytes are the Destination MAC address
    #2nd 6 bytes are the Source MAC Address
    #last 2 bytes is the ethernet type 
    # 6 + 6 + 2 = 14 total bytes

    eth_hdr = struct.unpack("!6s6s2s", ethernetHeader)
    #6s6s2s is the bytes listed above
    #this also breaks the ethernetHeader value into 3 parts
    #the 6 bytes, 6 bytes and 2 bytes
    #convert the 3 parts into Hex values which are the SRC and DST MAC addresses and the ethernet type 0x0800 which is IP
    print "Source MAC address: " + binascii.hexlify(eth_hdr[0])
    print "Destination MAC address: " + binascii.hexlify(eth_hdr[1])

def parseIP(header):
    ipHeader = pkt[0][14:34]        #IP header is the 20 bytes folowing the ethernet header
    ip_hdr = struct.unpack("!12s4s4s", ipHeader)   
    #1st 12 bytes is the Version, IHL, Type os Service, Total Length, Flags, TTL, Protocol, etc.
    #next 4 bytps is the Source IP
    #next 4 bytes is the Desintaion IP

    print "Source IP address: " + socket.inet_ntoa(ip_hdr[1])
    print "Destination IP address: " + socket.inet_ntoa(ip_hdr[2])
    #inet_ntoa is inet to ascii

def TCPflags(value):
    if value == '00':
        return "NULL"
    elif value == '01':
        return "FIN"
    elif value == '02':
        return "SYN"
    elif value == '04':
        return "RST"
    elif value == '08':
        return "PSH"
    elif value == '10':
        return "ACK"
    elif value == '11':
        return "FYN-ACK"
    elif value == '12':
        return "SYN-ACK"
    elif value == '14':
        return "RST-ACK"
    elif value == '18':
        return "PSH-ACK"
    elif value == '20':
        return "URG"
    elif value == '40':
        return "ECE"
    elif value == '80':
        return "CWR"
    elif value == '100':
        return "NS"
    else:
        return "WTF"


def parseTCP(header):
    tcpHeader = pkt[0][34:54]       #TCP header is the 20 bytes following the IP header
    tcp_hdr = struct.unpack("!HH9s1s6s", tcpHeader)
    #H stand for integer 2 bytes of type integer - Source Port
    #2nd H takes the next 2 bytes of type integer - Destination Port
    #skip the next 9 bytes (Seq number, Ack number, offset and Reservered)
    #Grab the TCP flag 1 byte  
    #ignroe the remain 6 bytes


    print "Source TCP Port: " + str(tcp_hdr[0])
    print "Destination TCP Port: " + str(tcp_hdr[1])
#    print "TCP Flags: " + str(tcp_hdr[3])
    print "TCP Flags: " + TCPflags(binascii.hexlify(tcp_hdr[3]))

def parseData(header):
    remainData = pkt[0][54:]
    hexout = binascii.hexlify(remainData)
    asciiout = hexout.decode("hex")
    print " " 
    print "Data portion in Hex:\n" + hexout 
    print " "
    print "Data Portion in Ascii:\n" + asciiout

rawSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
#rawSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.htons(0x0800))
#the 0x0800 means IP protocol
#/usr/include/linux/if_ether.h will show you the defined Ethernet Protocol ID's / Numbers
# PF_PACKET is used on linux, AF_INET is used on Mac

while True:
    pkt = rawSocket.recvfrom(65565)
    print "Received packet: "
    parseETH(pkt)
    parseIP(pkt)
    parseTCP(pkt)
    parseData(pkt)
    print "\n******************************************************************\n\n"





