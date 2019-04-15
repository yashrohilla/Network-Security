# -*- coding: utf-8 -*-

from scapy.all import * 
from rc4 import *
import numpy as np

source = '192.168.0.101'
destination = '127.0.0.1'

def listen(packet):  
# Filter by packet that has destination = 127.0.0.1
  if packet.haslayer(IP) and packet[IP].src == '127.0.0.1':
    # Get user to input secret key
    get_key = raw_input("Enter the secret key to decrypt the data: ")
    type(get_key)

    # Using RC4 algorith defined in rc4 to get Keystream
    key = convert_key(get_key)
    keystream = RC4(key)

    # Get payload from packet
    raw_packet_payload = np.fromstring(" ".join(packet[Raw].load), sep=' ', dtype=np.int8)

    # Convert payload to Integer values
    intArray = np.packbits(raw_packet_payload)

    plain_text = []

    # Compute XOR of Cipher text retrieved from Payload and Keystream
    for i in range(len(intArray)):
         plain_text.append(intArray[i] ^ keystream.next())

    print plain_text

    # Compute string of Plain Text since Checksum function defined in rc4.py only takes string as input
    strOfPlainText = ''.join(map(str, plain_text))
    print "String of PlainText =", strOfPlainText

    # Calculate Checksum of Plain Text
    chksum = calcChecksum(strOfPlainText)

    # Store any non zero values of Checksum in np.array 'a'
    a = np.nonzero(chksum)

    # If size of 'a' is zero, checksum matched, else print not matched
    if (np.size(a) == 0):
        print "Checksum matched"
    else:
        print "Checksum did not match"

def main():
    
    # Sniff for any packets reaching our wlan interface
    sniff(prn=listen, filter='ip',iface='wlan0')



if __name__ == '__main__':
    main()
