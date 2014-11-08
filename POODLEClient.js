var urllen = 0;
var postlen = 16;

function sslRequestHandler() {
    if (this.readyState == this.DONE) {
        queryNextTLSRequest();
    }
}

function performSSLRequest() {
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = sslRequestHandler;
    xhr.open("POST", "###URL###?" + strPad(urllen));
    xhr.send(strPad(postlen));
}

performSSLRequest();
