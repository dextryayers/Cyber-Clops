"""Local lab server for Phase 2 and 3. Real sockets on 127.0.0.1 only."""
import http.server

LAB_HTTP_PORT = 18080

JS_APP = b"""
// lab js with endpoints and one documented fake secret
const API = \"/api/v1/users\";
const LOGIN = \"/login\";
const AWS_EXAMPLE = \"AKIAIOSFODNN7EXAMPLE\";
fetch(API).then(r => r.json());
"""

PAGES = {
  "/": (200, b"<html><head><title>Lab Home</title></head><body><a href=\"/admin\">admin</a><a href=\"/login\">login</a><script src=\"/static/app.js\"></script><form method=\"POST\" action=\"/login\"><input name=\"user\"/><input name=\"pass\"/></form></body></html>"),
  "/admin": (200, b"admin panel lab"),
  "/login": (200, b"<html><body><form method=\"POST\"><input name=\"user\"/><input name=\"pass\"/></form></body></html>"),
  "/api/v1/users": (200, b'{"users": []}'),
  "/static/app.js": (200, JS_APP),
  "/sitemap.xml": (200, b"<?xml version=\"1.0\"?><urlset><url><loc>http://127.0.0.1:18080/</loc></url><url><loc>http://127.0.0.1:18080/admin</loc></url></urlset>"),
  "/robots.txt": (200, b"User-agent: *\nAllow: /\nSitemap: http://127.0.0.1:18080/sitemap.xml\n"),
}

class H(http.server.BaseHTTPRequestHandler):
  def do_GET(self):
    code, body = PAGES.get(self.path, (404, b"not found page body lab"))
    ctype = "application/javascript" if self.path.endswith(".js") else "text/html"
    if self.path in ("/sitemap.xml",):
      ctype = "application/xml"
    if self.path == "/robots.txt":
      ctype = "text/plain"
    self.send_response(code)
    self.send_header("Content-Length", str(len(body)))
    self.send_header("Content-Type", ctype)
    self.send_header("Server", "ClopsLab/0.2")
    if self.path == "/":
      self.send_header("Set-Cookie", "sess=abc; Path=/")
    self.end_headers()
    self.wfile.write(body)
  def do_POST(self):
    length = int(self.headers.get("Content-Length", 0))
    _ = self.rfile.read(length) if length else b""
    body = b"ok"
    self.send_response(200)
    self.send_header("Content-Length", str(len(body)))
    self.send_header("Server", "ClopsLab/0.2")
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
