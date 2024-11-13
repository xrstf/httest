// SPDX-FileCopyrightText: 2024 Christoph Mewes
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"log"
	"net/http"
	"runtime"

	"github.com/spf13/pflag"

	"go.xrstf.de/httest/pkg/options"
	"go.xrstf.de/httest/pkg/pki"
	"go.xrstf.de/httest/pkg/server"
)

// These variables get set by ldflags during compilation.
var (
	BuildTag    string
	BuildCommit string
	BuildDate   string // RFC3339 format ("2006-01-02T15:04:05Z07:00")
)

func printVersion() {
	// handle empty values in case `go install` was used
	if BuildCommit == "" {
		fmt.Printf("httest dev, built with %s\n",
			runtime.Version(),
		)
	} else {
		fmt.Printf("httest %s (%s), built with %s on %s\n",
			BuildTag,
			BuildCommit[:10],
			runtime.Version(),
			BuildDate,
		)
	}
}

func main() {
	o := options.NewDefault()
	o.AddFlags(pflag.CommandLine)
	pflag.Parse()

	if o.Version {
		printVersion()
		return
	}

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
