# httest

A dead-simple HTTP/HTTPS test server for developers.

## Installation

Get the binaries from the [GitHub releases](https://github.com/xrstf/httest/releases)
or use the container images at `ghcr.io/xrstf/httest`.

## Usage

```
Usage of httest:
  -e, --echo                    Respond to the client with the received request.
  -l, --listen string           Hostname and port to listen on. (default "localhost:8080")
      --pki-directory string    Directory where CA and serving certificate should be created in. (default ".httest")
  -r, --response string         Send the contents of this file as the response.
      --server-name string      Unique server name to include in responses.
      --tls                     Use TLS with a self-signed certificate.
  -n, --tls-hostnames strings   Comma-separated list of domain names to include in the serving certificate. (default [localhost,127.0.0.1])
  -t, --trace                   Log full request bodies on stderr.
  -V, --version                 Show version info and exit immediately.
```

## License

MIT
