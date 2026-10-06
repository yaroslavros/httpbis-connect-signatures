---
title: "Authenticating HTTP Tunnels with HTTP Message Signatures"
abbrev: "HTTP Tunnels Auth with Signatures"
category: std

docname: draft-rosomakho-httpbis-tunnels-signatures-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Web and Internet Transport"
workgroup: "HTTP"
keyword:
 - http
 - tunnels
 - signatures
venue:
  group: "HTTP"
  type: "Working Group"
  mail: "ietf-http-wg@w3.org"
  arch: "https://lists.w3.org/Archives/Public/ietf-http-wg/"
  github: "yaroslavros/httpbis-connect-signatures"
  latest: "https://yaroslavros.github.io/httpbis-connect-signatures/draft-rosomakho-httpbis-tunnels-signatures.html"

author:
 -
    fullname: Yaroslav Rosomakho
    organization: Zscaler
    email: yrosomakho@zscaler.com

normative:

informative:

--- abstract

This document specifies client authentication for HTTP tunnel establishment
using HTTP Message Signatures. It covers the CONNECT method, extended CONNECT
in HTTP/2 and HTTP/3, and HTTP/1.1 Upgrade. It defines signature coverage and a
challenge-response procedure using Accept-Signature with a fresh, single-use
nonce for each tunnel establishment.

--- middle

# Introduction {#intro}

HTTP endpoints that establish tunnels often need to authenticate clients before
granting access to network resources. HTTP Message Signatures {{!HTTP-SIG=RFC9421}}
provide a flexible mechanism for authenticating selected components of an HTTP
message, but their use requires a profile that specifies the components to
cover and the verification requirements for a particular application.

This document defines such a profile for tunnel establishment using the CONNECT
method {{!HTTP=RFC9110}}, extended CONNECT in HTTP/2 {{!HTTP2-EXTCONNECT=RFC8441}} and HTTP/3
{{!HTTP3-EXTCONNECT=RFC9220}}, and HTTP/1.1 Upgrade {{Section 7.8 of HTTP}}. These mechanisms support uses such
as UDP proxying {{?CONNECT-UDP=RFC9298}} and WebSockets {{?WEBSOCKET=RFC6455}}. The profile specifies
signature coverage and a challenge-response procedure using Accept-Signature,
with a fresh, single-use nonce for each tunnel establishment request.

One motivating use case is authentication of software workloads at CONNECT
proxies. WIMSE Workload-to-Workload Authentication with HTTP Signatures
{{?WIMSE-HTTPSIG=I-D.ietf-wimse-http-signature}} uses workload credentials and HTTP Message
Signatures to authenticate workload requests. This document is intended to
support that use case while remaining independent of WIMSE and applicable to
other client authentication deployments.

Authentication applies to the tunnel establishment request. Key identification,
trust establishment, and authorization policy are outside the scope of this
document. The mechanism does not require TLS or signed responses, and does not
provide confidentiality or integrity protection for subsequent tunnel traffic.


# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Protocol Overview {#overview}

The client sends a tunnel establishment request to the server. The server
challenges the client using Accept-Signature with a fresh nonce and the required
signature coverage. The client retries the request with Signature-Input and
Signature fields, incorporating the supplied nonce. Before accepting the
request, the server verifies the signature, validates and consumes the
single-use nonce, and applies its authorization policy.

~~~aasvg
Client                                       Server
  |                                             |
  |        Tunnel establishment request         |
  |-------------------------------------------->|
  |                                             |
  |        Accept-Signature challenge           |
  |<--------------------------------------------|
  |                                             |
  |        Signed request with nonce            |
  |-------------------------------------------->|
  |                                             |
  |        Successful establishment response    |
  |<--------------------------------------------|
  |                                             |
  |              Tunnel traffic                 |
  |<===========================================>|
~~~
{: #authentication-flow title="Successful authentication exchange"}

Each tunnel establishment requires a fresh challenge. The retry can use a
different connection; authentication of one request does not authenticate other
requests on either connection.


# Signature Requirements {#signature-requirements}

The server MUST generate an Accept-Signature challenge specifying the required
signature coverage and a fresh nonce. The client MUST respond with an HTTP
Message Signature in accordance with {{HTTP-SIG}} and the requirements below.
The Signature-Input and Signature fields MUST be sent in the request header
section so that authentication can complete before tunnel establishment. A
signature accepted for authentication MUST satisfy all applicable requirements;
coverage from separate signatures MUST NOT be combined to satisfy them.

## Covered Components {#covered-components}

The signature MUST cover the components listed below for the request form in
use. The server MUST reject authentication if any required component is not
covered, even if the signature is otherwise valid.

| Request form | Required components |
| --- | --- |
| Standard CONNECT | `@method`, `@authority` |
| Extended CONNECT | `@method`, `@authority`, `@scheme`, `@path`, `@query`, `@protocol` |
| HTTP/1.1 Upgrade | `@method`, `@authority`, `@scheme`, `@path`, `@query`, `upgrade` |

For standard CONNECT, `@authority` identifies the target host and port. Coverage
of `@path` and `@query` is not required. For extended CONNECT and HTTP/1.1
Upgrade, the URI components identify the requested resource, including any
destination information conveyed in its path or query. The `@query` component
MUST be covered even when no query is present, using the value defined in
{{Section 2.2.7 of HTTP-SIG}}.

The server MUST require coverage of any additional request fields on which it
relies to determine client identity, the tunnel destination, or permissions for
the requested tunnel. It MUST include these components in its Accept-Signature
challenge. The client MAY include additional signatures to cover other
components, as described in {{Section 5.2 of HTTP-SIG}}. A challenge MUST NOT
relax the minimum coverage requirements above.

The `upgrade` component covers the Upgrade field using the field canonicalization
rules in {{Section 2.1 of HTTP-SIG}}.

## The `@protocol` Derived Component {#protocol-component}

The `@protocol` derived component identifies the protocol requested by an
extended CONNECT request. Its value is the value of the `:protocol`
pseudo-header field defined in {{Section 4 of HTTP2-EXTCONNECT}} and used in
HTTP/3 by {{HTTP3-EXTCONNECT}}, without case conversion or other normalization.
For example, a request containing `:protocol` with the value `connect-udp`
produces the following signature base line:

~~~
"@protocol": connect-udp
~~~

This component is derived from a request. It can also be referenced in a
response signature using the `req` parameter as defined in
{{Section 2.4 of HTTP-SIG}}. If the request is not an extended CONNECT request
with a valid `:protocol` pseudo-header field, the component cannot be derived
and signature base generation MUST fail. In particular, `@protocol` is not
derived from the HTTP/1.1 Upgrade field.

## Signature Parameters {#signature-parameters}

The signature MUST include the following parameters defined in
{{Section 2.3 of HTTP-SIG}}:

* `nonce`: the exact nonce value supplied by the server in the Accept-Signature
  challenge. A client-generated value MUST NOT be substituted.
* `created`: the time at which the client generated the signature.
* `expires`: the signature expiration time, which MUST be later than `created`.

The server MUST enforce the signature validity period as well as the challenge
lifetime and single-use requirement. A signature's expiration time does not
extend the lifetime of its challenge. These checks apply when authenticating
the establishment request, not to the lifetime of the resulting tunnel.

Additional parameters can be required by the challenge or another applicable
profile. This document does not mandate `keyid`, `alg`, or a particular `tag`
value; their use follows {{HTTP-SIG}} and the applicable deployment or profile.


# Authentication Procedure {#authentication-procedure}

## Issuing a Challenge {#issuing-challenge}

For an otherwise acceptable tunnel establishment request that lacks a response
to a challenge, the server MUST return 403 (Forbidden) with an Accept-Signature
field. The field MUST contain one dictionary member specifying the signature
required by this mechanism, using the syntax in {{Section 5.1 of HTTP-SIG}}.
It MUST specify the coverage required by {{signature-requirements}}, a fresh
`nonce` value, and the `created` and `expires` parameters in their Boolean true
form. The response MUST include `Cache-Control: no-store`.

The nonce MUST be unpredictable and unique among challenges that the server
can still accept. The server MUST assign each challenge a bounded lifetime and
SHOULD keep that lifetime short, on the order of minutes.

The server MUST associate the nonce with the requested signature label,
coverage, parameters, expiration, and the request's method, target, and tunnel
protocol. This association MUST be protected against modification by the
client. A challenge MUST NOT be bound to the connection on which it was issued.

## Responding to a Challenge {#responding-challenge}

On receiving a 403 response with Accept-Signature, the client MUST check that
the challenge satisfies {{signature-requirements}} and is compatible with its
signing policy. If it cannot satisfy the challenge, it MUST fail the
establishment attempt rather than retry with weaker coverage or parameters.

The client retries the establishment request with the same method, target, and
tunnel protocol. It MUST generate the requested signature following
{{Section 5.2 of HTTP-SIG}}, using the same signature label and exact set of
component identifiers, including their parameters, as the challenge. It MUST
include the supplied nonce and generate `created` and `expires` values as
specified in {{signature-parameters}}. The retry MAY use the same connection or
a different connection.

The client MUST NOT use a nonce for more than one establishment attempt. If a
retry is needed after a signed request fails or its outcome is unknown, the
client MUST obtain a fresh challenge. Clients MUST limit automatic retries to
avoid an unbounded challenge-response loop.

## Validating and Accepting a Request {#validating-request}

Before accepting a signed request, the server MUST:

1. Identify the issued challenge using the nonce and select the signature with
   the label requested by that challenge.
1. Verify that the challenge is unexpired and applies to the request's method,
   target, and tunnel protocol.
1. Check the signature coverage and parameters against both the issued
   challenge and {{signature-requirements}}, and verify the signature according
   to {{Section 3.2 of HTTP-SIG}}.
1. Check that the current time falls within the signature validity period.
   The server MAY allow a small, bounded tolerance for clock skew.
1. Atomically check that the nonce is unused and mark it as consumed. If it has
   already been consumed, authentication MUST fail.

Single-use enforcement MUST apply across all connections and server instances
that can accept the nonce. If that enforcement cannot be guaranteed, the
server MUST NOT accept the request. An invalid signature MUST NOT consume the
nonce. Once consumed, a nonce MUST NOT become usable again, including when
authorization or subsequent tunnel establishment fails.

After authentication, the server applies its authorization policy. It MUST NOT
open the requested upstream connection, forward tunnel traffic, or send a
successful establishment response before authentication and authorization
succeed. Successful establishment uses the response defined by the applicable
tunnel protocol: a 2xx response for CONNECT or a 101 (Switching Protocols)
response for HTTP/1.1 Upgrade. Authentication applies only to this request.

## Error Handling {#authentication-errors}

Malformed authentication fields SHOULD result in 400 (Bad Request). For
well-formed requests, failed authentication, including an invalid signature or
an unknown, expired, or consumed nonce, MUST result in 403 (Forbidden). The
server MAY include a fresh Accept-Signature challenge if another attempt could
succeed.

If authentication succeeds but authorization fails, the server MUST return 403
without an Accept-Signature challenge. A client receiving a 403 response without
a challenge MUST NOT automatically retry using this procedure. Other failures,
such as an unreachable tunnel destination, use the error handling of the
applicable tunnel protocol.


# Examples {#examples}

These examples show successful exchanges at 2026-10-06T00:00:00Z. All
request signatures use Ed25519 and expire 60 seconds later; the server
accepts each challenge during that interval. Keys and nonce values are
for illustration only and are not suitable for deployment. Long lines
are folded using {{?FOLDING=RFC8792}}; folding is not part of the messages.

The client public key used in all three examples is:

~~~json
{
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "LJIz3J11mSpiRKfUwM8TReBzc4OEGvurSYNJ19K4AM8",
  "alg": "Ed25519",
  "kid": "client-key"
}
~~~
{: #example-client-key title="Example client public key"}

## Standard CONNECT with WIMSE Credentials {#example-standard-connect}

A workload connects to the proxy at `https://proxy.example` and requests
a TCP tunnel to `service.example:443`. The proxy uses WIMSE credentials
{{WIMSE-HTTPSIG}} and trusts the following issuer public key for the
`example.com` trust domain:

~~~json
{
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "uJqIC9mMU6Dl3roQZqy6CIrseaodOv_hjPGhel1Q3mk",
  "alg": "Ed25519",
  "kid": "issuer-key"
}
~~~
{: #example-issuer-key title="Example WIT issuer public key"}

The Workload Identity Token (WIT) {{?WIMSE-CREDS=I-D.ietf-wimse-workload-creds}}
in the signed request identifies `wimse://example.com/workload-a`, is
issued by `https://issuer.example`, and binds the client public key above
in `cnf.jwk`. Its `iat` is 1791244740 and its `exp` is 1791248400. The
token's protected header is:

~~~json
{"alg":"Ed25519","typ":"wit+jwt","kid":"issuer-key"}
~~~
{: #example-wit-header title="WIT protected header"}

Editorial note: this example anticipates changes to WIMSE permitting
server-provided nonces and omitting `@path` and `@query` for standard
CONNECT. It is not fully conformant to draft-ietf-wimse-http-signature-07.

The client first sends:

~~~
CONNECT service.example:443 HTTP/1.1
Host: service.example:443
~~~
{: #example-connect-initial title="Initial CONNECT request"}

The proxy challenges the client:

~~~
NOTE: '\' line wrapping per RFC 8792

HTTP/1.1 403 Forbidden
Cache-Control: no-store
Content-Length: 0
Accept-Signature: sig1=("@method" "@authority" \
  "workload-identity-token");nonce="8R2YsD5mrtrsiLPZPXt07_6jex3LLjNq";\
  created;expires;tag="wimse-workload-to-workload"
~~~
{: #example-connect-challenge title="CONNECT challenge"}

The client retries with its WIT and signature. The `wimse-aud` value is
the proxy identity configured for this WIMSE deployment. The signing key
and algorithm come from the WIT, so `keyid` and `alg` are absent from
Signature-Input. Response signing is not requested.

~~~
NOTE: '\' line wrapping per RFC 8792

CONNECT service.example:443 HTTP/1.1
Host: service.example:443
Workload-Identity-Token: eyJhbGciOiJFZDI1NTE5IiwidHlwIjoid2l0K2p3dCIsIm\
  tpZCI6Imlzc3Vlci1rZXkifQ.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwi\
  c3ViIjoid2ltc2U6Ly9leGFtcGxlLmNvbS93b3JrbG9hZC1hIiwiaWF0IjoxNzkxMjQ0N\
  zQwLCJleHAiOjE3OTEyNDg0MDAsImNuZiI6eyJqd2siOnsia3R5IjoiT0tQIiwiY3J2Ij\
  oiRWQyNTUxOSIsIngiOiJMSkl6M0oxMW1TcGlSS2ZVd004VFJlQnpjNE9FR3Z1clNZTko\
  xOUs0QU04IiwiYWxnIjoiRWQyNTUxOSIsImtpZCI6ImNsaWVudC1rZXkifX19.9G8ShrC\
  Bs3m9kJDvRo54mRs-Cyczot3oPeX0u5qUNyQ5Q5b7A3I0G-24ZGOGZBmp97AAoCzdYvr6\
  g1A8gIK6Ag
Signature-Input: sig1=("@method" "@authority" \
  "workload-identity-token");created=1791244800;expires=1791244860;\
  nonce="8R2YsD5mrtrsiLPZPXt07_6jex3LLjNq";\
  tag="wimse-workload-to-workload";wimse-aud="https://proxy.example"
Signature: sig1=:DIPNsG7AHT3Z8bspv3q6Oy/paFM4ZwKkNc7INxqrq/h19/MSwgM1k/\
  fMxdqWxUM91wwcYnIIJn35UP6IqcAyDg==:
~~~
{: #example-connect-signed title="Signed CONNECT request"}

After validating the WIT and request signature and authorizing the tunnel,
the proxy responds:

~~~
HTTP/1.1 200 Connection Established
~~~
{: #example-connect-success title="CONNECT success"}

## Extended CONNECT for UDP Proxying {#example-extended-connect}

This example uses CONNECT-UDP {{CONNECT-UDP}} over HTTP/2. The same
fields and signature apply to HTTP/3. Pseudo-header fields and header
fields are shown in decoded form; connection setup and protocol settings
negotiation are omitted. The proxy maps `client-key` to the client
public key in {{example-client-key}} through local configuration.

The client requests a UDP tunnel to `192.0.2.1:443`:

~~~
:method: CONNECT
:protocol: connect-udp
:scheme: https
:authority: proxy.example
:path: /.well-known/masque/udp/192.0.2.1/443/
capsule-protocol: ?1
~~~
{: #example-udp-initial title="Initial CONNECT-UDP request"}

The proxy requests a signature:

~~~
NOTE: '\' line wrapping per RFC 8792

:status: 403
cache-control: no-store
content-length: 0
accept-signature: sig1=("@method" "@authority" "@scheme" "@path" \
  "@query" "@protocol");nonce="xAiQNf5KcJLEmgyoVmuNckWgvuNdvmCq";\
  created;expires;keyid="client-key";alg="ed25519"
~~~
{: #example-udp-challenge title="CONNECT-UDP challenge"}

The client sends the signed request:

~~~
NOTE: '\' line wrapping per RFC 8792

:method: CONNECT
:protocol: connect-udp
:scheme: https
:authority: proxy.example
:path: /.well-known/masque/udp/192.0.2.1/443/
capsule-protocol: ?1
signature-input: sig1=("@method" "@authority" "@scheme" "@path" \
  "@query" "@protocol");created=1791244800;expires=1791244860;\
  nonce="xAiQNf5KcJLEmgyoVmuNckWgvuNdvmCq";keyid="client-key";\
  alg="ed25519"
signature: sig1=:FbyVrcdlNx9SrAKNJBgDhoEHxrx22Lf/moVSW5F23kqv8hwbc9u1xc\
  xyh5qRopJlsPpCWgRFvonN/olXL4z5Cw==:
~~~
{: #example-udp-signed title="Signed CONNECT-UDP request"}

After validation and authorization, the proxy accepts the tunnel:

~~~
:status: 200
capsule-protocol: ?1
~~~
{: #example-udp-success title="CONNECT-UDP success"}

## HTTP/1.1 WebSocket Upgrade {#example-websocket}

A client opens a WebSocket at `ws://chat.example/socket`. The server
maps `client-key` to the public key in {{example-client-key}}. The
handshake follows {{WEBSOCKET}} and additionally covers its key and
version fields. This example assumes a client capable of setting the
signature fields.

The initial request is:

~~~
GET /socket HTTP/1.1
Host: chat.example
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dHVubmVsLWV4YW1wbGUtMQ==
Sec-WebSocket-Version: 13
~~~
{: #example-ws-initial title="Initial WebSocket request"}

The server challenges the client:

~~~
NOTE: '\' line wrapping per RFC 8792

HTTP/1.1 403 Forbidden
Cache-Control: no-store
Content-Length: 0
Accept-Signature: sig1=("@method" "@authority" "@scheme" "@path" \
  "@query" "upgrade" "sec-websocket-key" "sec-websocket-version");\
  nonce="EAhASAIcKgZfGHxsn8qtTBT7Tlzlp0qg";created;expires;\
  keyid="client-key";alg="ed25519"
~~~
{: #example-ws-challenge title="WebSocket challenge"}

The client retries with a signed request:

~~~
NOTE: '\' line wrapping per RFC 8792

GET /socket HTTP/1.1
Host: chat.example
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dHVubmVsLWV4YW1wbGUtMg==
Sec-WebSocket-Version: 13
Signature-Input: sig1=("@method" "@authority" "@scheme" "@path" \
  "@query" "upgrade" "sec-websocket-key" "sec-websocket-version");\
  created=1791244800;expires=1791244860;\
  nonce="EAhASAIcKgZfGHxsn8qtTBT7Tlzlp0qg";keyid="client-key";\
  alg="ed25519"
Signature: sig1=:3ZOPO6A4SOYlAca2kDi+aoVKqrkFovGYRBaoTxD5BXkSmUZuz/79uW\
  4T8VAQmSc2RkdRsSdSG3okLyUM5IvfDQ==:
~~~
{: #example-ws-signed title="Signed WebSocket request"}

After validation and authorization, the server switches protocols:

~~~
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: P8RU/XYB7aRBEQ1oQfgq2shti/c=
~~~
{: #example-ws-success title="WebSocket success"}


# Security Considerations {#security}

The security considerations of {{HTTP-SIG}} apply. A valid signature proves
possession of the signing key; the server still needs a trusted association
between that key and a client identity and an authorization decision for the
requested tunnel. Components used in that decision need to be covered as
specified in {{covered-components}}. Uncovered fields can be modified without
invalidating the signature.

Replay protection depends on both challenge expiry and atomic single-use
enforcement across all server instances that accept a nonce. An expiring,
self-contained challenge does not by itself prevent reuse before expiry.
Loss of replay state must not cause a consumed challenge to become acceptable
again; affected challenges need to be rejected.

This mechanism does not authenticate the server or protect tunnel traffic.
Without a protected transport, credentials and request details are visible,
and an active attacker can alter challenges or forge responses. An attacker
can also relay a server's challenge to a legitimate client and use the signed
response to establish a tunnel under the attacker's control. Fresh, single-use
nonces do not prevent this live relay or subsequent tunnel hijacking. TLS or
equivalent channel protection can address these risks without being a
prerequisite for this mechanism.

Clients need to apply their signing policy to challenges, including restrictions
on keys and algorithms, rather than treating Accept-Signature as authority to
use arbitrary credentials. Servers need to enforce their own coverage and
algorithm requirements even if a challenge has been altered in transit.

Challenge issuance and signature verification can be used to exhaust server
resources. Servers SHOULD bound outstanding challenge state and rate-limit
authentication attempts. Discarding challenge state to enforce those limits
must cause the affected challenges to be rejected, not accepted without replay
checks.


# IANA Considerations {#iana}

This document requests registration of the following entry in the "HTTP
Signature Derived Component Names" registry established by
{{Section 6.4 of HTTP-SIG}}, using the template in
{{Section 6.4.1 of HTTP-SIG}}:

* Name: `@protocol`
* Description: The value of the `:protocol` pseudo-header field in an extended
  CONNECT request
* Status: Active
* Target: Request
* Reference: {{protocol-component}} of this document


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
