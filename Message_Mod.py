# -*- coding: utf-8 -*-

from scapy.all import * 
from rc4 import *
import numpy as np

destination = '192.168.0.101'
source = '127.0.0.1'

# Get user input for new message
delta_message = raw_input("Enter delta message to send: ")
type(delta_message)

# Compute Checksum
chksum = calcChecksum(delta_message)

# Convert message to Numpy Array
binaryString = np.fromstring(" ".join(delta_message), sep=' ', dtype=np.int8)

# Append Message + Checksum
completeMessage = np.append(binaryString, chksum)

# Create listen function that is passed to the in-built sniff function in Scapy
def listen(packet): 
        # Filter by packet that has destination = 127.0.0.1
        if packet.haslayer(IP) and packet[IP].src == source:
            # Get payload from packet
            raw_packet_payload = np.fromstring(" ".join(packet[Raw].load), sep=' ', dtype=np.int8)
            # Convert payload to Integer values
            intArray = np.packbits(raw_packet_payload)
            print "Integer Array =", intArray
            delta_cipher_text = []

            # Compute XOR of Cipher text retrieved from Payload and Delta message that we got from user
            for i in range(len(completeMessage)):
                delta_cipher_text.append(completeMessage[i] ^ intArray[i])

            print "Delta Cipher Text: ", delta_cipher_text

            msg = []

            # Convert Cipher Text to Binary for sending
            for i in range(len(delta_cipher_text)):
                msg.append(np.binary_repr(delta_cipher_text[i],width=8))

            # Join Binary Message to string since send function in Scapy only takes string as input
            msg = ''.join(msg)
            print "Msg = ", msg

            print len(msg)

            
            # Send function
            send_packet = Ether()/IP(dst=destination, src=source)/UDP(sport=30000, dport=30001)/msg
            sendp(send_packet)
        	

def main():
    # In-built Scapy function to sniff packets and stop sniffing if a packet with src IP = 127.0.0.1
    sniff(prn=listen, filter='ip',iface='wlan0', stop_filter=lambda x: x[IP].src=='127.0.0.1')

if __name__ == '__main__':
    main()
