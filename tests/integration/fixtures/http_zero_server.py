"""Serve owned zero-timeout request observations on an ephemeral loopback port."""

# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import ctypes
import http.server
import json
import os
import socket
import socketserver
import ssl
import sys
import threading
import time
from urllib.parse import urlsplit

ROOT, TOKEN = sys.argv[1:3]
PAYLOAD = b"legacy download fixture\x00\xff\n"
LOCK = threading.Lock()


# These standalone servers use the same standard HTTP handler contract.
# pylint: disable=duplicate-code
class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Retain no handler thread after an abandoned owned client."""

    daemon_threads = True


class Handler(http.server.BaseHTTPRequestHandler):
    """Journal parsed headers/body bytes and expose bounded response delays."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *_arguments):
        pass

    def date_time_string(self, _timestamp=None):
        """Keep the server-generated response clock literal between paired calls.

        :returns: Fixed HTTP date text.
        :rtype: str
        """
        return "Sat, 01 Jan 2000 00:00:00 GMT"

    def handle_expect_100(self):
        """Retain canceled upload headers even when sending 100 is reset.

        :returns: Whether request handling should continue to the body journal.
        :rtype: bool
        """
        try:
            return http.server.BaseHTTPRequestHandler.handle_expect_100(self)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            # The request headers are already parsed; respond records them and
            # the reset body instead of discarding that received request.
            return True

    # pylint: enable=duplicate-code

    def respond(self):
        """Record parsed method/path/headers and body before a delayed response."""
        length = int(self.headers.get("Content-Length", 0))
        assert 0 <= length <= 65536
        request_body = bytearray()
        peer_closed = False
        try:
            while len(request_body) < length:
                block = self.rfile.read1(length - len(request_body))
                if not block:
                    peer_closed = True
                    break
                request_body.extend(block)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            # A reset can precede every upload byte; retain the received headers
            # and every already-read body byte instead of losing this request.
            peer_closed = True
        record = {
            "method": self.command,
            "path": self.path,
            "headers": dict(self.headers),
            "header_pairs": list(self.headers.items()),
            "body_base64": base64.b64encode(request_body).decode("ascii"),
            "body_complete": len(request_body) == length,
            "peer_closed": peer_closed,
        }
        with LOCK:
            with open(
                os.path.join(ROOT, "requests.jsonl"), "a", encoding="utf-8"
            ) as stream:
                stream.write(json.dumps(record, sort_keys=True) + "\n")
        path = urlsplit(self.path).path
        body, status, location = PAYLOAD, 200, None
        if path == "/health/" + TOKEN:
            body = TOKEN.encode("ascii")
        elif path.startswith("/delay/"):
            time.sleep(float(path.rsplit("/", 1)[-1]))
        elif path.startswith("/redirect/"):
            time.sleep(float(path.rsplit("/", 1)[-1]))
            body, status, location = b"", 302, "/payload.bin"
        elif path == "/status/404":
            body, status = b"fixture status", 404
        elif path == "/echo":
            body = json.dumps(
                {name: record[name] for name in ("method", "headers", "body_base64")},
                sort_keys=True,
            ).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Last-Modified", "Sat, 01 Jan 2000 00:00:00 GMT")
        if path == "/echo":
            self.send_header("Content-Type", "application/json")
        if location is not None:
            self.send_header("Location", location)
        self.end_headers()
        # Standard HTTP framing is explicit in each independently staged server.
        # pylint: disable=duplicate-code
        if self.command != "HEAD":
            self.wfile.write(body)

    def handle(self):
        """A deliberately canceled owned request is not an unhandled server error."""
        try:
            http.server.BaseHTTPRequestHandler.handle(self)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass

    do_GET = do_HEAD = do_POST = do_PUT = respond
    # pylint: enable=duplicate-code


def main():
    """Publish the exact native process birth and expire abandoned fixture work."""
    # Own process-birth bindings avoid importing the payload under observation.
    # pylint: disable=duplicate-code
    assert sys.version_info[:3] == (3, 4, 4)
    library = ctypes.WinDLL("kernel32", use_last_error=True)
    library.GetCurrentProcess.restype = ctypes.c_void_p
    library.GetProcessTimes.argtypes = [ctypes.c_void_p] * 5
    library.GetProcessTimes.restype = ctypes.c_int32
    clocks = [ctypes.c_uint64() for _index in range(4)]
    assert library.GetProcessTimes(
        library.GetCurrentProcess(), *[ctypes.byref(value) for value in clocks]
    )
    # pylint: enable=duplicate-code
    server = Server(("127.0.0.1", 0), Handler)
    tls_server, tls_started = None, False
    try:
        # Windows treats a bound, non-listening socket as a timeout. Allocate
        # then close this endpoint; probes require refusal around every call.
        with socket.socket() as refused:
            refused.bind(("127.0.0.1", 0))
            refused_port = refused.getsockname()[1]
        info = {
            "pid": os.getpid(),
            "creation": clocks[0].value,
            "token": TOKEN,
            "port": server.server_address[1],
            "refused_port": refused_port,
        }
        certificate = os.path.join(ROOT, "server-cert.pem")
        key = os.path.join(ROOT, "server-key.pem")
        if os.path.exists(certificate) or os.path.exists(key):
            assert os.path.isfile(certificate) and os.path.isfile(key)
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            context.load_cert_chain(certificate, key)
            tls_server = Server(("127.0.0.1", 0), Handler)
            tls_server.socket = context.wrap_socket(tls_server.socket, server_side=True)
            tls_thread = threading.Thread(
                target=tls_server.serve_forever, kwargs={"poll_interval": 0.1}
            )
            tls_thread.daemon = True
            tls_thread.start()
            tls_started = True
            info["tls_port"] = tls_server.server_address[1]
        temporary = os.path.join(ROOT, "server.json.tmp")
        with open(temporary, "w", encoding="utf-8") as stream:
            json.dump(info, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, os.path.join(ROOT, "server.json"))
        timer = threading.Timer(1200, server.shutdown)
        # Each standalone server must bound and close its own lifetime.
        # pylint: disable=duplicate-code
        timer.daemon = True
        timer.start()
        server.serve_forever(poll_interval=0.1)
    finally:
        if tls_server is not None:
            if tls_started:
                tls_server.shutdown()
            tls_server.server_close()
        server.server_close()
        # pylint: enable=duplicate-code


if __name__ == "__main__":
    main()
