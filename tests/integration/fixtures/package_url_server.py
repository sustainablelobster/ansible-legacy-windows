"""Serve only the owned official package bytes on an ephemeral loopback port."""

# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import ctypes
import glob
import http.server
import json
import os
import socketserver
import sys
import tempfile
import threading
import time

ROOT, TOKEN = sys.argv[1:3]
LOCK = threading.Lock()


def _directory_monitor(stop):
    with open(os.path.join(ROOT, "msp-journal.json"), encoding="utf-8") as stream:
        before = json.load(stream)["url"]["temporary_directories"]
    library = ctypes.WinDLL("kernel32", use_last_error=True)
    library.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
    library.GetFileAttributesW.restype = ctypes.c_uint32
    seen, records = set(), []
    metadata = os.path.join(ROOT, "directories.json")
    while not stop.is_set():
        paths = glob.glob(
            os.path.join(tempfile.gettempdir(), "legacy-windows-package-url-*")
        )
        paths += glob.glob(os.path.join(ROOT, "ansible-moduletmp-*"))
        changed = not os.path.exists(metadata)
        for path in paths:
            if path in before:
                continue
            try:
                creation = os.stat(path).st_ctime
                attributes = library.GetFileAttributesW(path)
            except FileNotFoundError:
                continue
            if attributes == 0xFFFFFFFF:
                continue
            identity = (path, creation)
            if identity not in seen:
                seen.add(identity)
                records.append(
                    {
                        "path": path,
                        "creation": creation,
                        "attributes": attributes,
                        "observed": time.time(),
                    }
                )
                changed = True
        if changed:
            with open(metadata + ".tmp", "w", encoding="utf-8") as stream:
                json.dump(records, stream)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(metadata + ".tmp", metadata)
        stop.wait(0.005)


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Do not keep the server alive for an abandoned HTTP client."""

    daemon_threads = True


class Handler(http.server.BaseHTTPRequestHandler):
    """Expose package, redirect, authentication and error fixture endpoints."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *_arguments):
        pass

    def do_GET(self):  # pylint: disable=invalid-name
        """Record exact request headers and return only the scoped fixture body."""
        if self.path == "/health/" + TOKEN:
            body, status, headers = TOKEN.encode("ascii"), 200, {}
        else:
            with LOCK:
                with open(
                    os.path.join(ROOT, "requests.jsonl"), "a", encoding="utf-8"
                ) as stream:
                    stream.write(
                        json.dumps(
                            {
                                "method": self.command,
                                "path": self.path,
                                "headers": dict(self.headers),
                            }
                        )
                        + "\n"
                    )
            headers = {}
            if self.path == "/missing.msi":
                body, status = b"", 404
            elif self.path == "/redirect.msi":
                body, status, headers = b"", 302, {"Location": "/patch.msi"}
            elif self.path == "/auth.msi" and self.headers.get(
                "Authorization"
            ) != "Basic " + base64.b64encode(b"fixture:secret").decode("ascii"):
                body, status = b"", 401
                headers["WWW-Authenticate"] = 'Basic realm="package-fixture"'
            else:
                with open(os.path.join(ROOT, "patch.msi"), "rb") as stream:
                    body = stream.read()
                status = 200
                if self.path == "/disposition.bin":
                    headers["Content-Disposition"] = (
                        'attachment; filename="downloaded installer.msi"'
                    )
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        for name, value in headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)


def main():
    """Publish owned process identity and expire after twenty minutes."""
    assert sys.version_info[:3] == (3, 4, 4)
    library = ctypes.WinDLL("kernel32", use_last_error=True)
    library.GetCurrentProcess.restype = ctypes.c_void_p
    library.GetProcessTimes.argtypes = [ctypes.c_void_p] * 5
    library.GetProcessTimes.restype = ctypes.c_int32
    times = [ctypes.c_uint64() for _index in range(4)]
    assert library.GetProcessTimes(
        library.GetCurrentProcess(), *[ctypes.byref(value) for value in times]
    )
    server = Server(("127.0.0.1", 0), Handler)
    stop = threading.Event()
    monitor = threading.Thread(target=_directory_monitor, args=(stop,))
    monitor.daemon = True
    monitor.start()
    try:
        metadata = os.path.join(ROOT, "server.json")
        with open(metadata + ".tmp", "w", encoding="utf-8") as stream:
            json.dump(
                {
                    "pid": os.getpid(),
                    "creation": times[0].value,
                    "token": TOKEN,
                    "port": server.server_address[1],
                },
                stream,
            )
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(metadata + ".tmp", metadata)
        timer = threading.Timer(1200, server.shutdown)
        timer.daemon = True
        timer.start()
        server.serve_forever(poll_interval=0.1)
    finally:
        stop.set()
        monitor.join()
        server.server_close()


if __name__ == "__main__":
    main()
