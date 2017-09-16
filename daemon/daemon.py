#!/usr/bin/env python

import socket
import SocketServer
import ssl
import threading
import sys
import re

sys.path.append("mitm")

import mitm


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

TOKENS_FILE = "tokens"


class StringUtils:
    def __init__(self, string):
        self.string = string

    def get_substring(self, before_start, after_end, offset=0):
        return self.get_substring_and_end_position(before_start, after_end, offset)[0]

    def get_substring_and_end_position(self, before_start, after_end, offset):
        start_position = self.string.find(before_start, offset)
        start_position += len(before_start)
        end_position = self.string.find(after_end, start_position)
        return self.string[start_position:end_position], end_position + len(after_end)


class TokensStorage:
    __instance = None

    def __init__(self):
        self.tokens = eval(open(TOKENS_FILE).read())

    @classmethod
    def instance(cls):
        if not cls.__instance:
            cls.__instance = cls()
        return cls.__instance

    def get(self, key):
        return self.tokens.get(key)

    def check(self, key, value):
        return self.tokens.has_key(key) and self.tokens[key] == value


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
        ssl_socket = ssl.wrap_socket(socket, keyfile="certkey.pem", certfile="cert.pem", server_side=True,
                                     cert_reqs=ssl.CERT_NONE, ssl_version=SSL_VERSION, do_handshake_on_connect=False,
                                     ciphers=CIPHER_ALGORITHM)
        # Fix: disable compression to have predictable ciphered output (works only on python 2.7.9+)
        ssl_socket.context.options |= getattr(ssl, "OP_NO_COMPRESSION", 0)
        return ssl_socket

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
        return TokensStorage.instance().check(csrf, password)

    def send_ok_response(self, socket):
        socket.send("ok\n")

    def send_failure_response(self, socket):
        socket.send("error\n")


mitm.set_destination_endpoint(INTERNAL_SSL_ENDPOINT)


class MitmServerRequestHandler(mitm.BaseAggregatorMitmRequestHandler):
    def get_mitm_socket_aggregator(self):
        mitm_key = self.get_mitm_key(self.request)
        return self.get_mitm(mitm_key)

    def get_mitm_key(self, socket):
        mitm_key = int(socket.recv(RECV_BUFFER))
        socket.send(MITM_KEY_RECEIVED)
        return mitm_key

    def get_mitm(self, mitm_key):
        return MitmExchanger.instance().pop(mitm_key)


class SslClientRequest:
    def __init__(self, initial_payload, path, credentials, body):
        self.initial_payload = initial_payload
        self.http_request = self.build_http_request(path, credentials, body)
        self.response = 'client-error\n'

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
        return ssl.wrap_socket(socket, server_side=False, cert_reqs=ssl.CERT_REQUIRED, ca_certs="cert.pem",
                               ssl_version=SSL_VERSION, do_handshake_on_connect=False, ciphers=CIPHER_ALGORITHM)

    def perform_ssl_handshake(self, ssl_socket):
        ssl_socket.do_handshake()

    def send_request(self, socket):
        socket.sendall(self.http_request)

    def get_response(self, socket):
        return socket.recv(RECV_BUFFER)

    def shutdown_socket(self, socket):
        socket.close()


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
        server_socket_formatter = mitm.server_base64_formatter
        server_socket_action = self.wfile.write
        server_socket_processor = mitm.FormatAndDoDataProcessor(server_socket_formatter, server_socket_action)
        server_socket = mitm.DataProcessorOutSocket(server_socket_processor)

        client_socket_formatter = mitm.client_base64_formatter
        client_socket_action = self.wfile.write
        client_socket_processor = mitm.FormatAndDoDataProcessor(client_socket_formatter, client_socket_action)
        client_socket = mitm.DataProcessorOutSocket(client_socket_processor)

        recv_socket = mitm.FileInSocket(self.rfile)

        send_socket_unformatter = mitm.base64_decode_and_endpoint_unformatter
        send_socket_processor = mitm.UnformatAndRouteByEndpointDataProcessor(send_socket_unformatter)
        send_socket = mitm.DataProcessorOutSocket(send_socket_processor)

        mitm_socket = mitm.MitmSocketAggregator(server_socket, client_socket, recv_socket, send_socket)
        mitm_socket_key = MitmExchanger.instance().put(mitm_socket)

        ssl_client = SslClientRequest(str(mitm_socket_key), path, credentials, body)
        ssl_client.run()
        self.wfile.write(ssl_client.response)

    def sanity_checks(self, request):
        if not re.compile('^post\("[^"]+", ?"[^"]+"\);$').match(request):
            self.send_error("invalid request")
            raise

    def split_request(self, request):
        request_string = StringUtils(request)
        path, end_position = request_string.get_substring_and_end_position('"', '"', 0)
        body = request_string.get_substring('"', '"', end_position)
        return path, body

    def get_csrf(self, body):
        return StringUtils(body).get_substring("csrf=", "&")

    def get_credentials(self, csrf):
        return TokensStorage.instance().get(csrf)

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
