import socket
import struct


class IPPacket:
 def __init__(self, dst, src):
  self.dst = dst
  self.src = src
  self.header = None
  self.create_ipv4_fields_list()

 def assemble_ipv4_fields(self):
  self.header = struct.pack('!BBHHHBBH4s4s',
   self.ip_version,   # IP Version
   self.ip_dfc,   # Differentiate Service Feild
   self.ip_totalLen,   # Total Length
   self.ip_id,   # Identification
   self.ip_flag,   # Flags
   self.ip_ttl,   # Time to leave
   self.ip_proto,  # protocol
   self.ip_checksum,   # Checksum
   self.ip_srcAddr,  # Source IP
   self.ip_destAddr  # Destination IP
   )
  return self.header

 def create_ipv4_fields_list(self):

  #Internet Protocol Version
  ip_version = 4
  ip_headerlen = 5

  self.ip_version = (ip_version << 4) + ip_headerlen

  #Differentiate Service Field
  ip_service1 = 0
  ip_service2 = 0

  self.ip_dfc = (ip_service1 << 2) + ip_service2

  #Total Length
  self.ip_totalLen = 0

  #Identification
  self.ip_id = 54321

  #Flags
  ip_rsv = 0
  ip_dtf = 0
  ip_mrf = 0
  ip_frag_offset = 0

  self.ip_flag = (ip_rsv << 7) + (ip_dtf << 6) + (ip_mrf << 5) + (ip_frag_offset)

  #Total Length
  self.ip_ttl = 255

  #Protocol
  self.ip_proto = socket.IPPROTO_TCP

  #Check Sum
  self.ip_checksum = 0

  #Source Address
  self.ip_srcAddr = socket.inet_aton(self.src)

  #Destination Address
  self.ip_destAddr = socket.inet_aton(self.dst)

  return


class TCPPacket:
    def __init__(self, destPort, srcPort, dst, src, seqNo, ackNo, fin ,data):
        self.destPort = destPort
        self.srcPort = srcPort
        self.src_ip = src
        self.dst_ip = dst
        self.data = data
        self.seqNo = seqNo
        self.ackNo = ackNo
        self.fin = fin
        self.push = 1
        self.acknowledge = 1
        self.header = None
        self.create_tcp_feilds()

    def assemble_tcp_fields(self):
        self.header = struct.pack('!HHLLBBHHH',  # Data Structure Representation
                               self.tcp_src,   # Source port
                               self.tcp_dst,    # Destination port
                               self.tcp_seq,    # Sequence
                               self.tcp_ack_seq,  # Acknownlegment Sequence
                               self.tcp_hdr_len,   # Header Length
                               self.tcp_flags,    # TCP Flags
                               self.tcp_windowsize,   # TCP Windows
                               self.tcp_checksum,  # TCP cheksum
                               self.tcp_urg_ptr  # TCP Urgent Pointer
                               )

        self.calculate_checksumCreation()  # Call Calculate CheckSum
        return

    def reassemble_tcp_fields(self):
        self.header = struct.pack('!HHLLBBH',
                               self.tcp_src,
                               self.tcp_dst,
                               self.tcp_seq,
                               self.tcp_ack_seq,
                               self.tcp_hdr_len,
                               self.tcp_flags,
                               self.tcp_windowsize
                               )+struct.pack("H",
                               self.tcp_checksum
                               )+struct.pack('!H',
                               self.tcp_urg_ptr)
        return

    def calculate_checksumCreation(self):
        src_addr = socket.inet_aton(self.src_ip)
        dest_addr = socket.inet_aton(self.dst_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_len = len(self.header) + len(self.data)

        psh = struct.pack('!4s4sBBH',
                          src_addr,
                          dest_addr,
                          placeholder,
                          protocol,
                          tcp_len
                          )

        psh = psh + self.header + self.data

        self.tcp_checksum = self.checksumCreation(psh)

        self.reassemble_tcp_fields()

        return

    def checksumCreation(self, msg):
        s = 0  # Binary Sum

        # loop taking 2 characters at a time
        for i in range(0, len(msg), 2):

            a = ord(msg[i])
            b = ord(msg[i+1])
            s = s + (a+(b << 8))

        # One's Complement
        s = s + (s >> 16)
        s = ~s & 0xffff
        return s

    def create_tcp_feilds(self):

        #Source Port
        self.tcp_src = self.srcPort

        #Destination Port
        self.tcp_dst = self.destPort

        #TCP Sequence Number
        self.tcp_seq = self.seqNo

        #TCP Acknowledgement Number
        self.tcp_ack_seq = self.ackNo

        #Header Length
        self.tcp_hdr_len = 80

        #TCP Flags
        tcp_flags_rsv = (0 << 9)
        tcp_flags_rsv2 = (0 << 8)
        tcp_flags_rsv3 = (0 << 7)
        tcp_flags_rsv4 = (0 << 6)
        tcp_flags_urg = (0 << 5)
        tcp_flags_ack = (self.acknowledge << 4)
        tcp_flags_psh = (self.push << 3)
        tcp_flags_rst = (0 << 2)
        tcp_flags_syn = (0 << 1)
        tcp_flags_fin = (self.fin)

        self.tcp_flags = tcp_flags_rsv + tcp_flags_rsv2 + tcp_flags_rsv3 + tcp_flags_rsv4 + tcp_flags_urg + tcp_flags_ack + \
            tcp_flags_psh + tcp_flags_rst + tcp_flags_syn + tcp_flags_fin

        #TCP Window Size
        self.tcp_windowsize = socket.htons(5840)

        #TCP CheckSum
        self.tcp_checksum = 0

        #TCP Urgent Pointer
        self.tcp_urg_ptr = 0

        return

