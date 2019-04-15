# -*- coding: utf-8 -*-

from scapy.all import *    #import scapy module to python

received_msg = [] 

def sniffPackets(packet):         
    if packet.haslayer(IP) and packet[IP].src == '127.0.0.1':
        if packet[UDP].sport == 30000:
        	received_msg.append('0')
        if packet[UDP].sport == 30001:
        	received_msg.append('1')
        if packet[UDP].sport == 30002:
        	received_msg.append('2')
        if packet[UDP].sport == 30003:
        	received_msg.append('3')	
        if packet[UDP].sport == 30004:
        	received_msg.append('4')
       	if packet[UDP].sport == 30005:
        	received_msg.append('5')
        if packet[UDP].sport == 30006:
        	received_msg.append('6')
        if packet[UDP].sport == 30007:
        	received_msg.append('7')
        if packet[UDP].sport == 30008:
        	received_msg.append('8')
        if packet[UDP].sport == 30009:
        	received_msg.append('9')
        if packet[UDP].sport == 30010:
        	received_msg.append('a')
        if packet[UDP].sport == 30011:
        	received_msg.append('b')
        if packet[UDP].sport == 30012:
        	received_msg.append('c')
        if packet[UDP].sport == 30013:
        	received_msg.append('d')
        if packet[UDP].sport == 30014:
        	received_msg.append('e')
        if packet[UDP].sport == 30015:
        	received_msg.append('f')

def main():
    print 'custom packet sniffer'
    sniff(filter='ip',iface='wlp3s0',prn=sniffPackets)   #call scapy's inbuilt sniff method
    msg_to_decode = ''.join(received_msg)
    secret_msg = msg_to_decode.decode('hex')
    print "\n"
    print secret_msg

if __name__ == '__main__':
    main()