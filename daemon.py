#!/usr/bin/env python

import socket
import SocketServer
import ssl
import threading
import sys

PUBLIC_ENDPOINT = ('', 4747)

INTERNAL_SSL_ENDPOINT = ('127.0.0.1', 65186)
RECV_BUFFER = 4096
KILL_THREADS_WHEN_MAIN_ENDS = True

SSL_VERSION = ssl.PROTOCOL_SSLv3


class ThreadedTCPServer(SocketServer.ThreadingTCPServer):
	daemon_threads = KILL_THREADS_WHEN_MAIN_ENDS
	
	def start_background(self):
		ssl_server_thread = threading.Thread(target=self.serve_forever)
		ssl_server_thread.daemon = self.daemon_threads
		ssl_server_thread.start()
	
	def start_foreground(self):
		self.serve_forever()


class SslServerRequestHandler(SocketServer.BaseRequestHandler):
	def handle(self):
		self.ssl_socket = self.wrap_with_ssl_socket(self.request)
		handshake_completed = self.handle_ssl_handshake(self.ssl_socket)
		if handshake_completed:
			self.handle_http_request(self.ssl_socket)
	
	def wrap_with_ssl_socket(self, socket):
		return ssl.wrap_socket(socket, keyfile="certkey.pem", certfile="cert.pem", server_side=True, cert_reqs=ssl.CERT_NONE, ssl_version=SSL_VERSION, do_handshake_on_connect=False) # TODO force cbc block cipher
	
	def handle_ssl_handshake(self, ssl_socket):
		try:
			ssl_socket.do_handshake()
			return True
		except:
			return False
	
	def handle_http_request(self, socket):
		request = self.get_http_request(socket)
		has_valid_authentication = self.check_authentication(request)
		if has_valid_authentication:
			self.send_ok_response(socket)
		else:
			self.send_failure_response(socket)
	
	def get_http_request(self, socket):
		return socket.recv(RECV_BUFFER) # TODO
	
	def check_authentication(self, request):
		return self.check_http_authentication(request) and self.check_csrf_in_body(request)
	
	def check_http_authentication(self, request):
		return True # TODO
	
	def check_csrf_in_body(self, request):
		return True # TODO
	
	def send_ok_response(self, socket):
		socket.send("ok\n") # TODO
	
	def send_failure_response(self, socket):
		socket.send("error\n") # TODO


class PublicServerRequestHandler(SocketServer.StreamRequestHandler):
	def handle(self):
		path, credentials, body = self.handle_initial_request()
		self.perform_https_connection(path, credentials, body)
	
	def handle_initial_request(self):
		request = self.rfile.readline()
		self.sanity_checks(request)
		path, body = self.split_request(request)
		csrf = self.get_csrf(body)
		credentials = self.get_credentials(csrf)
		return path, credentials, body
	
	def perform_https_connection(self, path, credentials, body):
		ssl_client = SslClientRequest(path, credentials, body)
		ssl_client.run()
		self.wfile.write(ssl_client.response)
	
	def sanity_checks(self, request):
		pass # TODO check post("[^"]", "[^"]");\n and raise exceptions if not match
	
	def split_request(self, request):
		path, end_position = self.get_substring_and_end_position(request, '"', '"', 0)
		body = self.get_substring(request, '"', '"', end_position)
		return path, body
	
	def get_csrf(self, body):
		return self.get_substring(body, "csrf=", "&")
	
	def get_credentials(self, csrf):
		return "pepe:pito" # TODO read from a file using the csrf
	
	def get_substring(self, string, before_start, after_end, offset = 0):
		return self.get_substring_and_end_position(string, before_start, after_end, offset)[0]
	
	def get_substring_and_end_position(self, string, before_start, after_end, offset):
		start_position = string.find(before_start, offset)
		if start_position == -1:
			pass # TODO raise?
		start_position += len(before_start)
		end_position = string.find(after_end, start_position)
		if end_position == -1:
			pass # TODO raise?
		return string[start_position:end_position], end_position + len(after_end)


class SslClientRequest:
	def __init__(self, path, credentials, body):
		self.http_request = self.build_http_request(path, credentials, body)
		self.response = None
	
	def run(self):
		socket = self.connect_to_server()
		ssl_socket = self.wrap_with_ssl_socket(socket)
		valid_handshake = self.perform_ssl_handshake(ssl_socket)
		if valid_handshake:
			self.send_request(ssl_socket)
			self.response = self.get_response(ssl_socket)
		self.shutdown_socket(ssl_socket)
	
	def build_http_request(self, path, credentials, body):
		return "GET %s HTTP/1.0\r\nAuthorization: Basic %s\r\n\r\n%s"""
	
	def connect_to_server(self):
		return socket.create_connection(INTERNAL_SSL_ENDPOINT)
	
	def wrap_with_ssl_socket(self, socket):
		return ssl.wrap_socket(socket, server_side=False, cert_reqs=ssl.CERT_REQUIRED, ca_certs="file", ssl_version=SSL_VERSION, do_handshake_on_connect=False) # TODO include certificate file in ca_certs param, force cbc block cipher
	
	def perform_ssl_handshake(self, ssl_socket):
		try:
			ssl_socket.do_handshake()
			return True
		except:
			return False
	
	def send_request(self, socket):
		socket.sendall(self.http_request)
	
	def get_response(self, socket):
		return socket.recv(RECV_BUFFER) # TODO?
	
	def shutdown_socket(self, socket):
		socket.close()


if __name__ == "__main__":
	ssl_server = ThreadedTCPServer(INTERNAL_SSL_ENDPOINT, SslServerRequestHandler)
	ssl_server.start_background()
	
	public_server = ThreadedTCPServer(PUBLIC_ENDPOINT, PublicServerRequestHandler)
	public_server.start_foreground()
	
	# TODO
	
	ssl_server.shutdown()

