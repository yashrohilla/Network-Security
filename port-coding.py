# -*- coding: utf-8 -*-

from scapy.all import *    #import scapy module to python


secret_message = raw_input("Enter your secret message: ")
type(secret_message)

msg_to_send = secret_message.encode('hex')

destination = '131.246.229.83'
source = '127.0.0.1'



def main():


	for x in msg_to_send:
		if x == '0':
			send_packet = Ether()/IP(dst=destination, src=source)/UDP(sport=30000, dport=20000)
			sendp(send_packet, iface='wlp3s0')
		if x == '1':
			send_packet = Ether()/IP(dst=destination, src=source)/UDP(sport=30001, dport=20001)
			sendp(send_packet, iface='wlp3s0')
		if x == '2':
			send_packet = Ether()/IP(dst=destination, src=source)/UDP(sport=30002, dport=20002)
			sendp(send_packet, iface='wlp3s0')
		if x == '3':
			send_packet = Ether()/IP(dst=destination, src=source)/UDP(sport=30003, dport=20003)
			sendp(send_packet, iface='wlp3s0')
		if x == '4':
			send_packet = Ether()/IP(dst=destination, src=source)/UDP(sport=30004, dport=20004)
			sendp(send_packet, iface='wlp3s0')
		if x == '5':
			send_packet = Ether()/IP(dst=destination, src=source)/UDP(sport=30005, dport=20005)
			sendp(send_packet, iface='wlp3s0')
		if x == '6':
			send_packet = Ether()/IP(dst=destination, src=source)/UDP(sport=30006, dport=20006)
			sendp(send_packet, iface='wlp3s0')
		if x == '7':
			send_packet = Ether()/IP(dst=destination, src=source)/UDP(sport=30007, dport=20007)
			sendp(send_packet, iface='wlp3s0')
		if x == '8':
			send_packet = Ether()/IP(dst=destination, src=source)/UDP(sport=30008, dport=20008)
			sendp(send_packet, iface='wlp3s0')
		if x == '9':
			send_packet = Ether()/IP(dst=destination, src=source)/UDP(sport=30009, dport=20009)
			sendp(send_packet, iface='wlp3s0')
		if x == 'a':
			send_packet = Ether()/IP(dst=destination, src=source)/UDP(sport=30010, dport=20010)
			sendp(send_packet, iface='wlp3s0')
		if x == 'b':
			send_packet = Ether()/IP(dst=destination, src=source)/UDP(sport=30011, dport=20011)
			sendp(send_packet, iface='wlp3s0')
		if x == 'c':
			send_packet = Ether()/IP(dst=destination, src=source)/UDP(sport=30012, dport=20012)
			sendp(send_packet, iface='wlp3s0')
		if x == 'd':
			send_packet = Ether()/IP(dst=destination, src=source)/UDP(sport=30013, dport=20013)
			sendp(send_packet, iface='wlp3s0')
		if x == 'e':
			send_packet = Ether()/IP(dst=destination, src=source)/UDP(sport=30014, dport=20014)
			sendp(send_packet, iface='wlp3s0')
		if x == 'f':
			send_packet = Ether()/IP(dst=destination, src=source)/UDP(sport=30015, dport=20015)
			sendp(send_packet, iface='wlp3s0')
    

if __name__ == '__main__':
    main()
