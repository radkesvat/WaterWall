"""Reuse the upload-close wire assertions with a real TLS carrier peer."""

import importlib.util
import os
from pathlib import Path
import socket
import ssl
import sys

sys.dont_write_bytecode = True
support = Path(os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                             str(Path(__file__).resolve().parents[2] / "support" / "python")))
source = support.resolve().parents[1] / "cases" / "http2_upload_close_probe" / "probe.py"
spec = importlib.util.spec_from_file_location("httpclient_upload_probe", source)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("server.crt", "server.key")
context.set_alpn_protocols(["h2"])
with socket.socket() as listener:
    probe.configure_listener(listener, (probe.HOST, probe.PEER_PORT), timeout=10)
    probe.run_complete_upload(listener, tls_context=context)
print("HttpClient upload drain over TlsClient: exact body, END_STREAM, and EOF", flush=True)
