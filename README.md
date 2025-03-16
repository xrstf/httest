# Migration note

> [!IMPORTANT]
> `httest` has been migrated to [codeberg.org/xrstf/httest](https://codeberg.org/xrstf/httest).

---

## httest

A dead-simple HTTP/HTTPS test server for developers.

### Installation

Get the binaries from the [GitHub releases](https://github.com/xrstf/httest/releases)
or use the container images at `ghcr.io/xrstf/httest`.

### Usage

```
Usage of httest:
  -e, --echo                    Respond to the client with the received request (shortcut for --response echo).
  -j, --json                    Log in JSON instead of plaintext.
  -l, --listen string           Hostname and port to listen on. (default "localhost:8080")
      --pki-directory string    Directory where CA and serving certificate should be created in. (default ".httest")
  -r, --response string         Either the identifier for a built-in response (like "kubernetes:deny") or a path to a file that is read per-request and sent in response to the client.
  -R, --responses               List all built-in responses.
      --server-name string      Unique server name to include in responses.
      --tls                     Use TLS with a self-signed certificate.
  -n, --tls-hostnames strings   Comma-separated list of domain names to include in the serving certificate. (default [localhost,127.0.0.1])
  -t, --trace                   Log full request bodies on stderr.
  -V, --version                 Show version info and exit immediately.
```

#### Basics

Running `httest` without any arguments will simply start a receive-only webserver on port 8080 that
logs incoming requests:

```bash
$ httest
INFO[2024-11-13T21:42:14+01:00] Listening…                                    address=localhost:8080
INFO[2024-11-13T21:42:21+01:00] Request                                       method=POST path=/ protocol=HTTP/1.1 remote=127.0.0.1:56238 ua=curl/8.5.0
```

Use `--listen` to change the address and port to listen on.

#### Echo requests

Use `--echo` to respond to the client with the incoming request.

```bash
$ httest --echo
INFO[2024-11-13T21:42:14+01:00] Using built-in responder.                     responder=echo
INFO[2024-11-13T21:42:14+01:00] Listening…                                    address=localhost:8080
```

```bash
$ curl -XPOST -d"foobar" http://localhost:8080/
POST / HTTP/1.1
Host: localhost:8080
Accept: */*
Content-Length: 6
Content-Type: application/x-www-form-urlencoded
User-Agent: curl/8.5.0

foobar
```

#### Trace requests

Use `--trace` to log the full request to stderr:

```bash
$ httest --trace
INFO[2024-11-13T21:42:14+01:00] Listening…                                    address=localhost:8080
INFO[2024-11-13T21:44:05+01:00] Request                                       method=POST path=/ protocol=HTTP/1.1 remote=127.0.0.1:46770 ua=curl/8.5.0
POST / HTTP/1.1
Host: localhost:8080
Accept: */*
Content-Length: 6
Content-Type: application/x-www-form-urlencoded
User-Agent: curl/8.5.0

foobar

```

#### JSON logging

With `--json` `httest` will format each log line as JSON.

**NB:** In this example output, the lines have been formatted for easier readability.

```bash
$ httest --tls --json --trace
{
  "address": "localhost:8080",
  "ca": ".httest/ca.crt",
  "domains": ["localhost","127.0.0.1"],
  "level": "info",
  "msg": "Listening securely…",
  "time": "2024-11-13T21:50:04+01:00"
}
{
  "body": "foobar",
  "headers": {
    "Accept": ["*/*"],
    "Content-Length": ["6"],
    "Content-Type": ["application/x-www-form-urlencoded"],
    "User-Agent": ["curl/8.5.0"]
  },
  "level": "info",
  "method": "POST",
  "msg": "Request",
  "path": "/",
  "protocol": "HTTP/2.0",
  "remote": "127.0.0.1:44798",
  "time": "2024-11-13T21:50:05+01:00",
  "ua": "curl/8.5.0"
}
```

#### Customizing the response

`httest` can send out a file given by `--response`. This file is re-read on every request and so can
be updated externally during runtime.

Additionally, `--response` can be one of the built-in responder names. These give quick(er) access
to commonly required responses, like a SubjectAccessReview denial in Kubernetes. Use
`--list-responses` (or `-R`) to see all built-in responders:

```bash
$ httest -R
The following identifiers can be used for --response:

  echo                          echoes the incoming request varbatim to the client
  kubernetes:authz:allow        responds with a Kubernetes SubjectAccessReview with status.allowed=true
  kubernetes:authz:deny         responds with a Kubernetes SubjectAccessReview with status.denied=true
  kubernetes:authz:no-opinion   responds with a Kubernetes SubjectAccessReview with status.allowed=false
```

#### HTTPS / TLS

`httest` comes with its own very primitive PKI implementation. When `--tls` is given, `httest` will
generate a self-signed CA and a serving certificate for itself. These will be stored, together with
the private keys, as PEM-encoded files in the PKI directory (by default `.httest`).

```bash
$ httest --tls
INFO[2024-11-13T21:46:04+01:00] Listening securely…                           address=localhost:8080 ca=.httest/ca.crt domains=[localhost 127.0.0.1]
```

Use `--tls-hostnames` to override the altnames in the generated certificate. This flag can contain
a comma-separated list of domains or IPs, and the flag itself can be provided multiple times.

#### Docker

`httest` is available as a container image at [ghcr.io/xrstf/httest](https://github.com/xrstf/httest/pkgs/container/httest):

```bash
$ docker run --rm -p 8080:8080 ghcr.io/xrstf/httest:0.2.0 --json --listen 0.0.0.0:8080
{"address":"0.0.0.0:8080","level":"info","msg":"Listening…","time":"2024-11-13T20:57:15Z"}
```

### License

MIT
