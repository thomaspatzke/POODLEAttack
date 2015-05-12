#!/bin/bash

if [ -z $1 ]
then
    cat <<HELPMSG
What do you need to start?
- httpserver: target http server
- sslserver: sslv3 forwarder to httpd
- attacker: POODLE attack script configured for localhost
HELPMSG
elif [ "$1" == "httpserver" ]
then
    ./TestHTTPServer.py
elif [ "$1" == "sslserver" ]
then
    socat -v -x OPENSSL-LISTEN:4433,verify=0,method=SSLv3,cert=cert-poodle.pem,key=key-poodle.pem,reuseaddr,fork TCP:localhost:4080
elif [ "$1" == "attacker" ]
then
    ./poodle.py -d --target-port 4433 https://localhost:8443
elif [ "$1" == "attacker-nondebug" ]
then
    ./poodle.py --target-port 4433 https://localhost:8443
fi
