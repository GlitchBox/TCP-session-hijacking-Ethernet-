python poisonServer.py 192.168.1.102 192.168.1.103 &
python poisonClient.py 192.168.1.103 192.168.1.102 &
python sniffing.py 192.168.1.103 192.168.1.102