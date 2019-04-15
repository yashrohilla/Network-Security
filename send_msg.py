# -*- coding: utf-8 -*-

from scapy.all import * 
import numpy as np
from rc4 import *

destination = '192.168.0.101'
source = '127.0.0.1'

def main():
	
	# Get user to input message
	create_message = raw_input("Enter a binary message to send: ")
	type(create_message)

	# Only proceed with program if message length is a multiple of 8
	if len(create_message)%8 != 0:
		print "Message length must be a multiple of 8, exiting..."
		exit()

	# Get user to input secret key
	get_key = raw_input("Enter the secret key to encrypt the data: ")
	type(get_key)

	# Using RC4 algorith defined in rc4 to get Keystream
	key = convert_key(get_key)
	keystream = RC4(key)

	# Compute Checksum
	chksum = calcChecksum(create_message)

	# Convert message to Numpy Array
	binaryString = np.fromstring(" ".join(create_message), sep=' ', dtype=np.int8)

	# Append Message + Checksum
	completeMessage = np.append(binaryString, chksum)

	cipher_text = []

	# Compute Cipher Text by XORing Message+Checksum and Keystream
	for i in range(len(completeMessage)):
		cipher_text.append(completeMessage[i] ^ keystream.next())

	print "Cipher Text =", cipher_text

	msg = []

	# Convert Cipher Text to Binary for sending
	for i in range(len(cipher_text)):
		msg.append(np.binary_repr(cipher_text[i],width=8))

	# Join Binary Message to string since send function in Scapy only takes string as input
	msg = ''.join(msg)
	print "Complete Message =", msg

	# Send function
	send_packet = Ether()/IP(dst=destination, src=source)/UDP(sport=30000, dport=30001)/msg
	sendp(send_packet)

if __name__ == '__main__':
    main()
