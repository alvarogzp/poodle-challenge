#!/usr/bin/env python

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
CIPHER_ALGORITHM = "AES256-SHA"

MITM_KEY_RECEIVED = "ok"
ENDPOINT_SERVER = 'S'
ENDPOINT_CLIENT = 'C'
MESSAGE_ENDPOINT_SEPARATOR = '-'

KEYS_FILE = "keys"


class StringUtils:
	def __init__(self, string):
		self.string = string
	
	def get_substring(self, before_start, after_end, offset = 0):
		return self.get_substring_and_end_position(before_start, after_end, offset)[0]
	
	def get_substring_and_end_position(self, before_start, after_end, offset):
		start_position = self.string.find(before_start, offset)
		start_position += len(before_start)
		end_position = self.string.find(after_end, start_position)
		return self.string[start_position:end_position], end_position + len(after_end)


class KeysStorage:
	__instance = None
	
	def __init__(self):
		self.keys = eval(open(KEYS_FILE).read())
	
	@classmethod
	def instance(cls):
		if not cls.__instance:
			cls.__instance = cls()
		return cls.__instance
	
	def get(self, key):
		return self.keys.get(key)
	
	def check(self, key, value):
		return self.keys.has_key(key) and self.keys[key] == value


class MitmExchanger:
	__instance = None
	
	def __init__(self):
		self.mitms = {}
		self.counter = 0
		self.lock = threading.Lock()
	
	@classmethod
	def instance(cls):
		if not cls.__instance:
			cls.__instance = cls()
		return cls.__instance
	
	def put(self, mitm):
		with self.lock:
			key = self.counter
			self.counter += 1
		self.mitms[key] = mitm
		return key
	
	def pop(self, key):
		mitm = self.mitms[key]
		del self.mitms[key]
		return mitm


class Thread(threading.Thread):
	def __init__(self, *args, **dargs):
		super(Thread, self).__init__(*args, **dargs)
		self.daemon = KILL_THREADS_WHEN_MAIN_ENDS


class ThreadedTCPServer(SocketServer.ThreadingTCPServer):
	daemon_threads = KILL_THREADS_WHEN_MAIN_ENDS
	
	def start_background(self):
		Thread(target=self.serve_forever).start()
	
	def start_foreground(self):
		self.serve_forever()


class SslServerRequestHandler(SocketServer.BaseRequestHandler):
	def handle(self):
		try:
			self.ssl_socket = self.wrap_with_ssl_socket(self.request)
			self.handle_ssl_handshake(self.ssl_socket)
			self.handle_http_request(self.ssl_socket)
		except:
			pass
	
	def wrap_with_ssl_socket(self, socket):
		return ssl.wrap_socket(socket, keyfile="certkey.pem", certfile="cert.pem", server_side=True, cert_reqs=ssl.CERT_NONE, ssl_version=SSL_VERSION, do_handshake_on_connect=False, ciphers=CIPHER_ALGORITHM)
	
	def handle_ssl_handshake(self, ssl_socket):
		ssl_socket.do_handshake()
	
	def handle_http_request(self, socket):
		request = self.get_http_request(socket)
		has_valid_authentication = self.check_authentication(request)
		if has_valid_authentication:
			self.send_ok_response(socket)
		else:
			self.send_failure_response(socket)
	
	def get_http_request(self, socket):
		read = socket.recv(RECV_BUFFER)
		request = read
		while "\r\n\r\n" not in request and read:
			read = socket.recv(RECV_BUFFER)
			request += read
		return request
	
	def check_authentication(self, request):
		request_string = StringUtils(request)
		csrf = request_string.get_substring("csrf=", "&")
		password = request_string.get_substring("\r\nAuthorization: Basic ", "\r\n")
		return KeysStorage.instance().check(csrf, password)
	
	def send_ok_response(self, socket):
		socket.send("ok\n")
	
	def send_failure_response(self, socket):
		socket.send("error\n")


class MitmServerRequestHandler(SocketServer.BaseRequestHandler):
	def handle(self):
		mitm_key = self.get_mitm_key(self.request)
		mitm = self.get_mitm(mitm_key)
		server_socket = self.connect_to_server_socket()
		self.forward(server_socket, self.request, mitm)
	
	def get_mitm_key(self, socket):
		mitm_key = int(socket.recv(RECV_BUFFER))
		socket.send(MITM_KEY_RECEIVED)
		return mitm_key
	
	def get_mitm(self, mitm_key):
		return MitmExchanger.instance().pop(mitm_key)
	
	def connect_to_server_socket(self):
		return socket.create_connection(INTERNAL_SSL_ENDPOINT)
	
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
		try:
			read = self.in_socket.recv(RECV_BUFFER)
			while read:
				self.out_socket.sendall(read)
				read = self.in_socket.recv(RECV_BUFFER)
		except:
			pass
	
	def wait(self):
		self.thread.join()


class SslClientRequest:
	def __init__(self, initial_payload, path, credentials, body):
		self.initial_payload = initial_payload
		self.http_request = self.build_http_request(path, credentials, body)
		self.response = 'client-error'
	
	def run(self):
		try:
			socket = self.connect_to_server()
			self.send_initial_payload(socket, self.initial_payload)
			ssl_socket = self.wrap_with_ssl_socket(socket)
			self.perform_ssl_handshake(ssl_socket)
			self.send_request(ssl_socket)
			self.response = self.get_response(ssl_socket)
			self.shutdown_socket(ssl_socket)
		except:
			pass
	
	def build_http_request(self, path, credentials, body):
		return "GET %s HTTP/1.0\r\nAuthorization: Basic %s\r\n\r\n%s" % (path, credentials, body)
	
	def connect_to_server(self):
		return socket.create_connection(INTERNAL_FORWARD_ENDPOINT)
	
	def send_initial_payload(self, socket, initial_payload):
		socket.sendall(initial_payload)
		ack = socket.recv(RECV_BUFFER)
		assert ack == MITM_KEY_RECEIVED
	
	def wrap_with_ssl_socket(self, socket):
		return ssl.wrap_socket(socket, server_side=False, cert_reqs=ssl.CERT_REQUIRED, ca_certs="cert.pem", ssl_version=SSL_VERSION, do_handshake_on_connect=False, ciphers=CIPHER_ALGORITHM)
	
	def perform_ssl_handshake(self, ssl_socket):
		ssl_socket.do_handshake()
	
	def send_request(self, socket):
		socket.sendall(self.http_request)
	
	def get_response(self, socket):
		return socket.recv(RECV_BUFFER)
	
	def shutdown_socket(self, socket):
		socket.close()


class MitmSocketAggregator:
	def __init__(self, server_socket, client_socket, recv_socket, send_socket):
		self.server_out_socket = server_socket
		self.client_out_socket = client_socket
		self.recv_socket = recv_socket
		self._send_socket = send_socket
	
	def send_socket(self, server_socket, client_socket):
		self._send_socket.processor.set_router(EndpointRouter(server_socket, client_socket))
		return self._send_socket


class MitmInSocket:
	def __init__(self, rfile):
		self.rfile = rfile
	
	def recv(self, bufsize):
		return self.rfile.readline()


class MitmOutSocket:
	def __init__(self, processor):
		self.processor = processor
	
	def sendall(self, string):
		self.processor.process(string)


class FormatDataProcessor:
	def __init__(self, formatter, action):
		self.formatter = formatter
		self.action = action
	
	def process(self, string):
		formatted_data = self.formatter.format(string)
		self.action(formatted_data)


class EncodeAndEndpointFormatter:
	def __init__(self, endpoint, codec):
		self.endpoint = endpoint
		self.codec = codec
	
	def format(self, string):
		return self.endpoint + MESSAGE_ENDPOINT_SEPARATOR + self.codec.encode(string) + '\n'


class DecodeAndEndpointUnformatter:
	def __init__(self, codec):
		self.codec = codec
	
	def unformat(self, string):
		string = self.remove_trailing_newline(string)
		endpoint, encoded_string = self.split_by_separator(string)
		decoded_string = self.codec.decode(encoded_string)
		return (endpoint, decoded_string)
	
	def remove_trailing_newline(self, string):
		if string[-1] == '\n':
			string = string[:-1]
		return string
	
	def split_by_separator(self, string):
		return string.split(MESSAGE_ENDPOINT_SEPARATOR, 1)


class Base64Codec:
	def encode(self, string):
		return string.encode("base64").replace("\n", "")
	
	def decode(self, string):
		return string.decode("base64")


class UnformatAndRouteByEndpointDataProcessor:
	def __init__(self, unformatter):
		self.unformatter = unformatter
	
	def set_router(self, router):
		self.router = router
	
	def process(self, string):
		endpoint, text = self.unformatter.unformat(string)
		self.router.get(endpoint).sendall(text)


class EndpointRouter:
	def __init__(self, server_socket, client_socket):
		self.server_socket = server_socket
		self.client_socket = client_socket
	
	def get(self, endpoint):
		if endpoint == ENDPOINT_SERVER:
			return self.client_socket
		elif endpoint == ENDPOINT_CLIENT:
			return self.server_socket


class PublicServerRequestHandler(SocketServer.StreamRequestHandler):
	def handle(self):
		try:
			path, credentials, body = self.handle_initial_request()
			self.perform_https_connection(path, credentials, body)
		except:
			pass
	
	def handle_initial_request(self):
		request = self.rfile.readline()
		self.sanity_checks(request)
		path, body = self.split_request(request)
		csrf = self.get_csrf(body)
		credentials = self.get_credentials(csrf)
		if not credentials:
			self.send_error("no valid csrf found")
			raise
		return path, credentials, body
	
	def perform_https_connection(self, path, credentials, body):
		# TODO create a factory for this
		
		server_socket_codec = Base64Codec()
		server_socket_formatter = EncodeAndEndpointFormatter(ENDPOINT_SERVER, server_socket_codec)
		server_socket_action = self.wfile.write
		server_socket_processor = FormatDataProcessor(server_socket_formatter, server_socket_action)
		server_socket = MitmOutSocket(server_socket_processor)
		
		client_socket_codec = Base64Codec()
		client_socket_formatter = EncodeAndEndpointFormatter(ENDPOINT_CLIENT, client_socket_codec)
		client_socket_action = self.wfile.write
		client_socket_processor = FormatDataProcessor(client_socket_formatter, client_socket_action)
		client_socket = MitmOutSocket(client_socket_processor)
		
		recv_socket = MitmInSocket(self.rfile)
		
		send_socket_codec = Base64Codec()
		send_socket_unformatter = DecodeAndEndpointUnformatter(send_socket_codec)
		send_socket_processor = UnformatAndRouteByEndpointDataProcessor(send_socket_unformatter)
		send_socket = MitmOutSocket(send_socket_processor)
		
		mitm_socket = MitmSocketAggregator(server_socket, client_socket, recv_socket, send_socket)
		
		mitm_socket_key = MitmExchanger.instance().put(mitm_socket)
		
		ssl_client = SslClientRequest(str(mitm_socket_key), path, credentials, body)
		ssl_client.run()
		self.wfile.write(ssl_client.response)
	
	def sanity_checks(self, request):
		pass # TODO check post("[^"]", "[^"]");\n and raise exceptions if not match
	
	def split_request(self, request):
		request_string = StringUtils(request)
		path, end_position = request_string.get_substring_and_end_position('"', '"', 0)
		body = request_string.get_substring('"', '"', end_position)
		return path, body
	
	def get_csrf(self, body):
		return StringUtils(body).get_substring("csrf=", "&")
	
	def get_credentials(self, csrf):
		return KeysStorage.instance().get(csrf)
	
	def send_error(self, message):
		self.wfile.write(message + "\n")


if __name__ == "__main__":
	ssl_server = ThreadedTCPServer(INTERNAL_SSL_ENDPOINT, SslServerRequestHandler)
	ssl_server.start_background()
	
	forward_server = ThreadedTCPServer(INTERNAL_FORWARD_ENDPOINT, MitmServerRequestHandler)
	forward_server.start_background()
	
	public_server = ThreadedTCPServer(PUBLIC_ENDPOINT, PublicServerRequestHandler)
	public_server.start_foreground()
	
	public_server.shutdown()
	forward_server.shutdown()
	ssl_server.shutdown()

