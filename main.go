// SPDX-FileCopyrightText: 2024 Christoph Mewes
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"

	"github.com/spf13/pflag"

	"go.xrstf.de/httest/pkg/pki"
)

func newHandler(serverName string, trace bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		response, err := httputil.DumpRequest(r, true)
		if err != nil {
			log.Println(err)

			w.WriteHeader(500)
			response = []byte("Could not dump incoming request.\n")
		}

		var logMessage string
		if serverName != "" {
			logMessage += fmt.Sprintf("[%s] ", serverName)
		}
		logMessage += fmt.Sprintf(`[%s] "%s %s" %s "%s"`, r.RemoteAddr, r.Method, r.URL, r.Proto, r.UserAgent())

		if err == nil && trace {
			logMessage += fmt.Sprintf("\n%s", string(response))
		}

		log.Println(logMessage)

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(response)

		if serverName != "" {
			w.Write([]byte(fmt.Sprintf("Instance: %s\n", serverName)))
		}
	}
}

func main() {
	o := newDefaultOptions()
	o.AddFlags(pflag.CommandLine)
	pflag.Parse()

	if err := o.Validate(); err != nil {
		log.Fatalf("Error: %v.", err)
	}

	http.HandleFunc("/", newHandler(o.ServerName, o.Trace))

	if o.TLS.Enabled {
		certFile, keyFile, err := pki.EnsurePKI(pki.Options{
			Directory: o.TLS.Directory,
			Hostnames: o.TLS.Hostnames,
		})
		if err != nil {
			log.Fatalf("Failed to ensure PKI in %q: %v.", o.TLS.Directory, err)
		}

		log.Printf("Listening securely on %s (certs and keys are in %s)…", o.ListenOn, o.TLS.Directory)

		if err := http.ListenAndServeTLS(o.ListenOn, certFile, keyFile, nil); err != nil {
			log.Fatal(err)
		}
	} else {
		log.Printf("Listening on %s…", o.ListenOn)

		if err := http.ListenAndServe(o.ListenOn, nil); err != nil {
			log.Fatal(err)
		}
	}
}
