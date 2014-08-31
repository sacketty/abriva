**Abriva** is an HTTP authentication scheme using a message authentication code (MAC) algorithm to provide partial
HTTP request cryptographic verification.

Current version: **1.0**


# Table of Content
TBD

# Introduction

**Abriva** is an HTTP authentication scheme providing mechanisms for making authenticated HTTP requests with
partial cryptographic signature verification of the request and response, covering the HTTP method, request URI, host,
and optionally the request payload.





## Usage Example

Server code:

```javascript
var Http = require('http');
var Hawk = require('hawk');


// Credentials lookup function

var credentialsFunc = function (id, callback) {

    var credentials = {
        key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
        algorithm: 'sha256',
        user: 'Steve'
    };

    return callback(null, credentials);
};

// Create HTTP server

var handler = function (req, res) {

    // Authenticate incoming request

    Hawk.server.authenticate(req, credentialsFunc, {}, function (err, credentials, artifacts) {

        // Prepare response

        var payload = (!err ? 'Hello ' + credentials.user + ' ' + artifacts.ext : 'Shoosh!');
        var headers = { 'Content-Type': 'text/plain' };

        // Generate Server-Authorization response header

        var header = Hawk.server.header(credentials, artifacts, { payload: payload, contentType: headers['Content-Type'] });
        headers['Server-Authorization'] = header;

        // Send the response back

        res.writeHead(!err ? 200 : 401, headers);
        res.end(payload);
    });
};

// Start server

Http.createServer(handler).listen(8000, 'example.com');
```

Client code:

```javascript
var Request = require('request');
var Hawk = require('hawk');


// Client credentials

var credentials = {
    id: 'dh37fgj492je',
    key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
    algorithm: 'sha256'
}

// Request options

var requestOptions = {
    uri: 'http://example.com:8000/resource/1?b=1&a=2',
    method: 'GET',
    headers: {}
};

// Generate Authorization request header

var header = Hawk.client.header('http://example.com:8000/resource/1?b=1&a=2', 'GET', { credentials: credentials, ext: 'some-app-data' });
requestOptions.headers.Authorization = header.field;

// Send authenticated request

Request(requestOptions, function (error, response, body) {

    // Authenticate the server's response

    var isValid = Hawk.client.authenticate(response, credentials, header.artifacts, { payload: body });

    // Output results

    console.log(response.statusCode + ': ' + body + (isValid ? ' (valid)' : ' (invalid)'));
});
```

**Hawk** utilized the [**SNTP**](https://github.com/hueniverse/sntp) module for time sync management. By default, the local
machine time is used. To automatically retrieve and synchronice the clock within the application, use the SNTP 'start()' method.

```javascript
Hawk.sntp.start();
```


## Protocol Example

The client attempts to access a protected resource without authentication, sending the following HTTP request to
the resource server:

```
GET /resource/1?b=1&a=2 HTTP/1.1
Host: example.com:8000
```

The resource server returns an authentication challenge.

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Hawk
```

The client has previously obtained a set of **Hawk** credentials for accessing resources on the "http://example.com/"
server. The **Hawk** credentials issued to the client include the following attributes:

* Key identifier: dh37fgj492je
* Key: werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn
* Algorithm: sha256

The client generates the authentication header by calculating a timestamp (e.g. the number of seconds since January 1,
1970 00:00:00 GMT), generating a nonce, and constructing the normalized request string (each value followed by a newline
character):

```
hawk.1.header
1353832234
j4h3g2
GET
/resource/1?b=1&a=2
example.com
8000

some-app-ext-data

```

The request MAC is calculated using HMAC with the specified hash algorithm "sha256" and the key over the normalized request string.
The result is base64-encoded to produce the request MAC:

```
6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE=
```

The client includes the **Hawk** key identifier, timestamp, nonce, application specific data, and request MAC with the request using
the HTTP `Authorization` request header field:

```
GET /resource/1?b=1&a=2 HTTP/1.1
Host: example.com:8000
Authorization: Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2", ext="some-app-ext-data", mac="6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE="
```

The server validates the request by calculating the request MAC again based on the request received and verifies the validity
and scope of the **Hawk** credentials. If valid, the server responds with the requested resource.


### Payload Validation

**Hawk** provides optional payload validation. When generating the authentication header, the client calculates a payload hash
using the specified hash algorithm. The hash is calculated over the concatenated value of (each followed by a newline character):
* `hawk.1.payload`
* the content-type in lowercase, without any parameters (e.g. `application/json`)
* the request payload prior to any content encoding (the exact representation requirements should be specified by the server for payloads other than simple single-part ascii to ensure interoperability)

For example:

* Payload: `Thank you for flying Hawk`
* Content Type: `text/plain`
* Hash (sha256): `Yi9LfIIFRtBEPt74PVmbTF/xVAwPn7ub15ePICfgnuY=`

Results in the following input to the payload hash function (newline terminated values):

```
hawk.1.payload
text/plain
Thank you for flying Hawk

```

Which produces the following hash value:

```
Yi9LfIIFRtBEPt74PVmbTF/xVAwPn7ub15ePICfgnuY=
```

The client constructs the normalized request string (newline terminated values):

```
hawk.1.header
1353832234
j4h3g2
POST
/resource/1?a=1&b=2
example.com
8000
Yi9LfIIFRtBEPt74PVmbTF/xVAwPn7ub15ePICfgnuY=
some-app-ext-data

```

Then calculates the request MAC and includes the **Hawk** key identifier, timestamp, nonce, payload hash, application specific data,
and request MAC, with the request using the HTTP `Authorization` request header field:

```
POST /resource/1?a=1&b=2 HTTP/1.1
Host: example.com:8000
Authorization: Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2", hash="Yi9LfIIFRtBEPt74PVmbTF/xVAwPn7ub15ePICfgnuY=", ext="some-app-ext-data", mac="aSe1DERmZuRl3pI36/9BdZmnErTw3sNzOOAUlfeKjVw="
```

It is up to the server if and when it validates the payload for any given request, based solely on it's security policy
and the nature of the data included.

If the payload is available at the time of authentication, the server uses the hash value provided by the client to construct
the normalized string and validates the MAC. If the MAC is valid, the server calculates the payload hash and compares the value
with the provided payload hash in the header. In many cases, checking the MAC first is faster than calculating the payload hash.

However, if the payload is not available at authentication time (e.g. too large to fit in memory, streamed elsewhere, or processed
at a different stage in the application), the server may choose to defer payload validation for later by retaining the hash value
provided by the client after validating the MAC.

It is important to note that MAC validation does not mean the hash value provided by the client is valid, only that the value
included in the header was not modified. Without calculating the payload hash on the server and comparing it to the value provided
by the client, the payload may be modified by an attacker.


## Response Payload Validation

**Hawk** provides partial response payload validation. The server includes the `Server-Authorization` response header which enables the
client to authenticate the response and ensure it is talking to the right server. **Hawk** defines the HTTP `Server-Authorization` header
as a response header using the exact same syntax as the `Authorization` request header field.

The header is contructed using the same process as the client's request header. The server uses the same credentials and other
artifacts provided by the client to constructs the normalized request string. The `ext` and `hash` values are replaced with
new values based on the server response. The rest as identical to those used by the client.

The result MAC digest is included with the optional `hash` and `ext` values:

```
Server-Authorization: Hawk mac="XIJRsMl/4oL+nn+vKoeVZPdCHXB4yJkNnBbTbHFZUYE=", hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext="response-specific"
```


## Browser Support and Considerations

A browser script is provided for including using a `<script>` tag in [lib/browser.js](/lib/browser.js). It's also a [component](http://component.io/hueniverse/hawk).

**Hawk** relies on the _Server-Authorization_ and _WWW-Authenticate_ headers in its response to communicate with the client.
Therefore, in case of CORS requests, it is important to consider sending _Access-Control-Expose-Headers_ with the value
_"WWW-Authenticate, Server-Authorization"_ on each response from your server. As explained in the
[specifications](http://www.w3.org/TR/cors/#access-control-expose-headers-response-header), it will indicate that these headers
can safely be accessed by the client (using getResponseHeader() on the XmlHttpRequest object). Otherwise you will be met with a
["simple response header"](http://www.w3.org/TR/cors/#simple-response-header) which excludes these fields and would prevent the
Hawk client from authenticating the requests.You can read more about the why and how in this
[article](http://www.html5rocks.com/en/tutorials/cors/#toc-adding-cors-support-to-the-server)


# Single URI Authorization

There are cases in which limited and short-term access to a protected resource is granted to a third party which does not
have access to the shared credentials. For example, displaying a protected image on a web page accessed by anyone. **Hawk**
provides limited support for such URIs in the form of a _bewit_ - a URI query parameter appended to the request URI which contains
the necessary credentials to authenticate the request.

Because of the significant security risks involved in issuing such access, bewit usage is purposely limited only to GET requests
and for a finite period of time. Both the client and server can issue bewit credentials, however, the server should not use the same
credentials as the client to maintain clear traceability as to who issued which credentials.

In order to simplify implementation, bewit credentials do not support single-use policy and can be replayed multiple times within
the granted access timeframe. 


## Bewit Usage Example

Server code:

```javascript
var Http = require('http');
var Hawk = require('hawk');


// Credentials lookup function

var credentialsFunc = function (id, callback) {

    var credentials = {
        key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
        algorithm: 'sha256'
    };

    return callback(null, credentials);
};

// Create HTTP server

var handler = function (req, res) {

    Hawk.uri.authenticate(req, credentialsFunc, {}, function (err, credentials, attributes) {

        res.writeHead(!err ? 200 : 401, { 'Content-Type': 'text/plain' });
        res.end(!err ? 'Access granted' : 'Shoosh!');
    });
};

Http.createServer(handler).listen(8000, 'example.com');
```

Bewit code generation:

```javascript
var Request = require('request');
var Hawk = require('hawk');


// Client credentials

var credentials = {
    id: 'dh37fgj492je',
    key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
    algorithm: 'sha256'
}

// Generate bewit

var duration = 60 * 5;      // 5 Minutes
var bewit = Hawk.uri.getBewit('http://example.com:8080/resource/1?b=1&a=2', { credentials: credentials, ttlSec: duration, ext: 'some-app-data' });
var uri = 'http://example.com:8000/resource/1?b=1&a=2' + '&bewit=' + bewit;
```

### Coverage Limitations

The request MAC only covers the HTTP `Host` header and optionally the `Content-Type` header. It does not cover any other headers
which can often affect how the request body is interpreted by the server. If the server behavior is influenced by the presence
or value of such headers, an attacker can manipulate the request headers without being detected. Implementers should use the
`ext` feature to pass application-specific information via the `Authorization` header which is protected by the request MAC.

The response authentication, when performed, only covers the response payload, content-type, and the request information 
provided by the client in it's request (method, resource, timestamp, nonce, etc.). It does not cover the HTTP status code or
any other response header field (e.g. Location) which can affect the client's behaviour.

### Future Time Manipulation

The protocol relies on a clock sync between the client and server. To accomplish this, the server informs the client of its
current time when an invalid timestamp is received.

If an attacker is able to manipulate this information and cause the client to use an incorrect time, it would be able to cause
the client to generate authenticated requests using time in the future. Such requests will fail when sent by the client, and will
not likely leave a trace on the server (given the common implementation of nonce, if at all enforced). The attacker will then
be able to replay the request at the correct time without detection.

The client must only use the time information provided by the server if:
* it was delivered over a TLS connection and the server identity has been verified, or
* the `tsm` MAC digest calculated using the same client credentials over the timestamp has been verified.

### Client Clock Poisoning

When receiving a request with a bad timestamp, the server provides the client with its current time. The client must never use
the time received from the server to adjust its own clock, and must only use it to calculate an offset for communicating with
that particular server.



### Host Header Forgery

Abriva validates the incoming request MAC against the incoming HTTP Host header. However, unless the optional `host` and `port`
options are used with `server.authenticate()`, a malicous client can mint new host names pointing to the server's IP address and
use that to craft an attack by sending a valid request that's meant for another hostname than the one used by the server. Server
implementors must manually verify that the host header received matches their expectation (or use the options mentioned above).

# Frequently Asked Questions

### Where is the protocol specification?
TBD

### Is it done?

As of version 0.10.0, **Abriva** is feature-complete. However, until this module reaches version 1.0.0 it is considered experimental
and is likely to change. This also means your feedback and contribution are very welcome. Feel free to open issues with questions
and suggestions.

### Where can I find **Abriva** implementations in other languages?

**Abriva**'s only reference implementation is provided in JavaScript as a node.js module. It is yet to be ported to other languages.


### Why isn't the algorithm part of the challenge or dynamically negotiated?

The algorithm used is closely related to the key issued as different algorithms require different key sizes (and other
requirements). While some keys can be used for multiple algorithm, the protocol is designed to closely bind the key and algorithm
together as part of the issued credentials.

### Why is Host and Content-Type the only headers covered by the request MAC?

It is really hard to include other headers. Headers can be changed by proxies and other intermediaries and there is no
well-established way to normalize them. Many platforms change the case of header field names and values. The only
straight-forward solution is to include the headers in some blob (say, base64 encoded JSON) and include that with the request,
an approach taken by JWT and other such formats. However, that design violates the HTTP header boundaries, repeats information,
and introduces other security issues because firewalls will not be aware of these "hidden" headers. In addition, any information
repeated must be compared to the duplicated information in the header and therefore only moves the problem elsewhere.



### What is the purpose of the static strings used in each normalized MAC input?

When calculating a hash or MAC, a static prefix (tag) is added. The prefix is used to prevent MAC values from being
used or reused for a purpose other than what they were created for (i.e. prevents switching MAC values between a request,
response, and a bewit use cases). It also protects against expliots created after a potential change in how the protocol
creates the normalized string. For example, if a future version would switch the order of nonce and timestamp, it
can create an exploit opportunity for cases where the nonce is similar in format to a timestamp.



# Acknowledgements

**AbrivaID**  initial code borrowed heavily from [Hawk Authentication Scheme](https://github.com/hueniverse/hawk)
including the actual code used to render the coverage report into HTML.

