"""Local lab server for Phase 0 and 1. Real sockets on 127.0.0.1 only."""
import http.server
import ssl
import threading

LAB_HTTP_PORT = 18080

PAGES = {
  "/admin": (200, b"admin panel lab"),
  "/login": (200, b"login lab"),
  "/api/v1/users": (200, b'{"users": []}'),
}

class H(http.server.BaseHTTPRequestHandler):
  def do_GET(self):
    code, body = PAGES.get(self.path, (404, b"not found page body lab"))
    self.send_response(code)
    self.send_header("Content-Length", str(len(body)))
    self.send_header("Server", "ClopsLab/0.1")
    self.end_headers()
    self.wfile.write(body)
  def log_message(self, *a):
    pass

def main():
  srv = http.server.HTTPServer(("127.0.0.1", LAB_HTTP_PORT), H)
  print(f"lab http on 127.0.0.1:{LAB_HTTP_PORT}", flush=True)
  srv.serve_forever()

if __name__ == "__main__":
  main()
