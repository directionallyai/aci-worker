# Fake object store for the pyc simulation: serves /srv files over plain HTTP and two
# HTTPS listeners (P-256 and RSA-2048 certificates), HTTP/1.1 keep-alive.
import http.server, ssl, threading, os, functools

class H(http.server.SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def end_headers(self):
        self.send_header("Cache-Control", "no-store"); super().end_headers()

def serve(port, cert=None, key=None):
    handler = functools.partial(H, directory="/srv")
    srv = http.server.ThreadingHTTPServer(("0.0.0.0", port), handler)
    if cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert, key)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    srv.serve_forever()

for args in ((8080,), (8443, "/srv/ec.pem", "/srv/ec.key"), (8444, "/srv/rsa.pem", "/srv/rsa.key")):
    threading.Thread(target=serve, args=args, daemon=True).start()
print("ready", flush=True)
threading.Event().wait()
