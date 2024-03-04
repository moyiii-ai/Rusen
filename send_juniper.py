from scapy.all import *

#p = Ether(src="00:1b:21:94:d8:14",dst="00:1b:21:94:d8:15")/IP(src="250.250.250.250",dst="250.250.250.251")/TCP()
#p = Ether(src="e0:07:1b:7b:98:a2",dst="9c:dc:71:55:7c:e1")/IP(src="250.250.250.250",dst="250.250.250.251")/TCP()
p = Ether(src="90:e2:ba:6d:30:59",dst="00:1b:21:94:d8:14")/IP(src="250.250.250.250",dst="250.250.250.251")/TCP()

#sendpfast(p,iface="enp193s0f0",pps=100,loop=1000000)
sendpfast(p,iface="enp1s0d1",pps=1000,loop=200000000)
# sendpfast(p,iface="enp65s0",pps=10,loop=1000000)

# enp1s0 44938
# enp66s0 40581