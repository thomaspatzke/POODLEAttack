#!/usr/bin/python3

import http.server

class HTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.do_POST()

    def do_POST(self):
        self.send_response(200);
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Set-Cookie", "sessionid=supersecret;")
        self.end_headers()
        self.wfile.write(b"<h1>Testserver</h1>")

httpd = http.server.HTTPServer(("", 4080), HTTPRequestHandler)
httpd.serve_forever()
