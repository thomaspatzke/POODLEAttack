# Implementation of the POODLE Attack

This is a PoC implementation of the [POODLE attack](https://www.openssl.org/~bodo/ssl-poodle.pdf).

## Test Environment

* Start HTTP server with: `./poodle-dev.sh httpserver`
* Start SSLv3 forwarder to HTTP server from point above with: `./poodle-dev.sh sslserver`
* Start PoC with: `./poodle-dev.sh attacker`
* Open [HTTPS server](https://localhost:8443) in browser and accept certificate.
* Open [PoC request generator](https://localhost:8000) and watch leaking bytes in PoC terminal

More details about it [in a blog article](http://patzke.org/implementing-the-poodle-attack.html).

Only for demonstration purposes - **Don't do anything evil with it!**
