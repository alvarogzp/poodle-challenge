#!/usr/bin/env python
################# TODO STATUS: ahora mismo se conecta el cliente directamente al servidor, hay que crear un servidor que haga el MITM, reenviando el trafico SSL recibido por ambos sockets y enviando el que el cliente del MITM decida
import socket
import SocketServer
import ssl
import threading
import sys

PUBLIC_ENDPOINT = ('', 4747)

INTERNAL_SSL_ENDPOINT = ('127.0.0.1', 65186)
INTERNAL_FORWARD_ENDPOINT = ('127.0.0.1', 65187)
RECV_BUFFER = 4096
KILL_THREADS_WHEN_MAIN_ENDS = True

SSL_VERSION = ssl.PROTOCOL_SSLv3

MITM_KEY_RECEIVED = "ok"
ENDPOINT_SERVER = 'S'
ENDPOINT_CLIENT = 'C'
MESSAGE_ENDPOINT_SEPARATOR = '-'


class MitmExchanger:
	instance = None
	
	def __init__(self):
		self.mitms = {}
		self.counter = 0
		self.lock = threading.Lock()
	
	def instance(cls):
		if not cls.instance:
			cls.instance = cls()
		return cls.instance
	
	def put(self, mitm):
		with self.lock:
			key = self.counter
			self.counter += 1
		self.mitms[key] = mitm
		return key
	
	def pop(self, key):
		mitm = self.mitms[key]
		del self.mitms[key]


class Thread(threading.Thread):
	def __init__(self, *args, **dargs):
		super(Thread, self).__init__(*args, **dargs)
		self.daemon = KILL_THREADS_WHEN_MAIN_ENDS


class ThreadedTCPServer(SocketServer.ThreadingTCPServer):
	def start_background(self):
		Thread(target=self.serve_forever).start()
	
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


class MitmServerRequestHandler(SocketServer.BaseRequestHandler):
	def handle(self):
		mitm_key = self.get_mitm_key(self.request)
		mitm = self.get_mitm(mitm_key)
		client_socket = self.connect_client_socket()
		self.forward(self.request, client_socket, mitm)
	
	def connect_client_socket(self):
		return socket.create_connection(INTERNAL_SSL_ENDPOINT)
	
	def get_mitm_key(self, socket):
		mitm_key = socket.recv(RECV_BUFFER)
		socket.send(MITM_KEY_RECEIVED)
		return mitm_key
	
	def get_mitm(self, mitm_key):
		return MitmExchanger.instance().pop(mitm_key)
	
	def forward(self, server_socket, client_socket, mitm):
		forwarder_from_server = SocketStreamForwarder(server_socket, mitm.server_out_socket).forward()
		forwarder_from_client = SocketStreamForwarder(client_socket, mitm.client_out_socket).forward()
		forwarder_from_mitm = SocketStreamForwarder(mitm.recv_socket, mitm.send_socket(server_socket, client_socket)).forward()
		forwarder_from_server.wait()
		forwarder_from_client.wait()
		forwarder_from_mitm.wait()


class SocketStreamForwarder:
	def __init__(self, in_socket, out_socket):
		self.in_socket = in_socket
		self.out_socket = out_socket
	
	def forward(self):
		self.thread = Thread(target=self.forward_loop)
		self.thread.start()
		return self
	
	def forward_loop(self):
		read = self.in_socket.recv(RECV_BUFFER)
		while read:
			self.out_socket.sendall(read)
			read = self.in_socket.recv(RECV_BUFFER)
	
	def wait(self):
		self.thread.join()


class SslClientRequest:
	def __init__(self, initial_payload, path, credentials, body):
		self.initial_payload = initial_payload
		self.http_request = self.build_http_request(path, credentials, body)
		self.response = '' # TODO error?
	
	def run(self):
		socket = self.connect_to_server()
		self.send_initial_payload(socket, self.initial_payload)
		ssl_socket = self.wrap_with_ssl_socket(socket)
		valid_handshake = self.perform_ssl_handshake(ssl_socket)
		if valid_handshake:
			self.send_request(ssl_socket)
			self.response = self.get_response(ssl_socket)
		self.shutdown_socket(ssl_socket)
	
	def build_http_request(self, path, credentials, body):
		return "GET %s HTTP/1.0\r\nAuthorization: Basic %s\r\n\r\n%s""" % (path, credentials, body)
	
	def connect_to_server(self):
		return socket.create_connection(INTERNAL_FORWARD_ENDPOINT)
	
	def send_initial_payload(self, socket, initial_payload):
		socket.sendall(initial_payload)
		ack = socket.recv(RECV_BUFFER)
		assert ack == MITM_KEY_RECEIVED
	
	def wrap_with_ssl_socket(self, socket):
		return ssl.wrap_socket(socket, server_side=False, cert_reqs=ssl.CERT_REQUIRED, ca_certs="cert.pem", ssl_version=SSL_VERSION, do_handshake_on_connect=False) # TODO include certificate file in ca_certs param, force cbc block cipher
	
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


class MitmSocketAggregator:
	def __init__(self, server_socket, client_socket, recv_socket, send_socket):
		self.server_out_socket = server_socket
		self.client_out_socket = client_socket
		self.recv_socket = recv_socket
		self._send_socket = send_socket
	
	def send_socket(self, server_socket, client_socket):
		return self._send_socket.processor.set_router(EndpointRouter(server_socket, client_socket))


class MitmInSocket:
	def __init__(self, rfile):
		self.rfile = rfile
	
	def recv(self, bufsize):
		return self.rfile.readline()


class MitmOutSocket:
	def __init__(self, processor):
		self.processor = processor
	
	def send(self, string):
		self.processor.process(string)


class FormatDataProcessor:
	def __init__(self, formatter, action):
		self.formatter = formatter
		self.action = action
	
	def process(self, string):
		formatted_data = self.formatter.format(string)
		self.action(formatted_data)


class Base64WithEndpointFormatter:
	def __init__(self, endpoint):
		self.endpoint = endpoint
	
	def format(self, string):
		return self.endpoint + MESSAGE_ENDPOINT_SEPARATOR + string.encode("base64") + '\n'
	
	def unformat(cls, string):
		return (endpoint, string) # TODO


class UnformatDataProcessor:
	def __init__(self, formatter):
		self.formatter = formatter
	
	def set_router(self, router):
		self.router = router
	
	def process(self, string):
		endpoint, text = self.formatter.unformat(string)
		self.router.get(endpoint).sendall(text)


class EndpointRouter:
	def __init__(self, server_socket, client_socket):
		self.server_socket = server_socket
		self.client_socket = client_socket
	
	def get(self, endpoint):
		if endpoint == ENDPOINT_SERVER:
			return self.server_socket
		elif endpoint == ENDPOINT_CLIENT:
			return self.client_socket


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
		server_socket_formatter = Base64WithEndpointFormatter(ENDPOINT_SERVER)
		server_socket_action = self.wfile.write
		server_socket_processor = FormatDataProcessor(server_socket_formatter, server_socket_action)
		server_socket = MitmOutSocket(server_socket_processor)
		
		client_socket_formatter = Base64WithEndpointFormatter(ENDPOINT_CLIENT)
		client_socket_action = self.wfile.write
		client_socket_processor = FormatDataProcessor(client_socket_formatter, client_socket_action)
		client_socket = MitmOutSocket(client_socket_processor)
		
		recv_socket = MitmInSocket(self.rfile)
		
		send_socket_formatter = Base64WithEndpointFormatter
		send_socket_processor = UnformatDataProcessor(send_socket_formatter)
		send_socket = MitmOutSocket(send_socket_processor)
		
		mitm_socket = MitmSocketAggregator(server_socket, client_socket, recv_socket, send_socket)
		
		mitm_socket_key = MitmExchanger.put(mitm_socket)
		
		ssl_client = SslClientRequest(str(mitm_socket_key), path, credentials, body)
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


if __name__ == "__main__":
	ssl_server = ThreadedTCPServer(INTERNAL_SSL_ENDPOINT, SslServerRequestHandler)
	ssl_server.start_background()
	
	forward_server = ThreadedTCPServer(INTERNAL_FORWARD_ENDPOINT, ForwardServerRequestHandler)
	forward_server.start_background()
	
	public_server = ThreadedTCPServer(PUBLIC_ENDPOINT, PublicServerRequestHandler)
	public_server.start_foreground()
	
	# TODO
	
	forward_server.shutdown()
	ssl_server.shutdown()

