#!/bin/bash

if [ -z $1 ]
then
    cat <<HELPMSG
What do you need to start?
- sslserver: openssl with dummy certs + sslv3
- attacker: POODLE attack script configured for localhost
HELPMSG
elif [ "$1" == "sslserver" ]
then
    socat -v -x OPENSSL-LISTEN:4433,verify=0,method=SSLv3,cert=cert-poodle.pem,key=key-poodle.pem,reuseaddr,fork OPEN:response.http,rdonly
elif [ "$1" == "attacker" ]
then
    ./poodle.py -d --target-port 4433 https://localhost:8443
fi
