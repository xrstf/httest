// SPDX-FileCopyrightText: 2024 Christoph Mewes
// SPDX-License-Identifier: MIT

package main

import (
	"log"
	"net/http"

	"github.com/spf13/pflag"

	"go.xrstf.de/httest/pkg/options"
	"go.xrstf.de/httest/pkg/pki"
	"go.xrstf.de/httest/pkg/server"
)

func main() {
	o := options.NewDefault()
	o.AddFlags(pflag.CommandLine)
	pflag.Parse()

	if err := o.Validate(); err != nil {
		log.Fatalf("Error: %v.", err)
	}

	http.HandleFunc("/", server.NewHandler(o))

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
