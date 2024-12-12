// SPDX-FileCopyrightText: 2024 Christoph Mewes
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"net/http"
	"runtime"
	"slices"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"go.xrstf.de/httest/pkg/options"
	"go.xrstf.de/httest/pkg/pki"
	"go.xrstf.de/httest/pkg/responses"
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

	log := logrus.New()
	if o.JSON {
		log.Formatter = &logrus.JSONFormatter{
			DisableHTMLEscape: true,
		}
	} else {
		log.Formatter = &logrus.TextFormatter{
			FullTimestamp: true,
			DisableQuote:  true,
		}
	}

	if err := o.Validate(); err != nil {
		log.WithError(err).Fatal("Invalid options.")
	}

	if o.ListResponses {
		listBuiltInResponses()
		return
	}

	http.HandleFunc("/", server.NewHandler(log, o, buildResponder(log, o)))

	if o.TLS.Enabled {
		pkiInfo, err := pki.EnsurePKI(log, pki.Options{
			Directory: o.TLS.Directory,
			Hostnames: o.TLS.Hostnames,
		})
		if err != nil {
			log.WithError(err).Fatalf("Failed to ensure PKI in %q.", o.TLS.Directory)
		}

		log.WithFields(logrus.Fields{
			"address": o.ListenOn,
			"ca":      pkiInfo.CAFile,
			"domains": o.TLS.Hostnames,
		}).Print("Listening securely…")

		if err := http.ListenAndServeTLS(o.ListenOn, pkiInfo.FullchainFile, pkiInfo.PrivateKeyFile, nil); err != nil {
			log.Fatal(err)
		}
	} else {
		log.WithField("address", o.ListenOn).Print("Listening…")

		if err := http.ListenAndServe(o.ListenOn, nil); err != nil {
			log.Fatal(err)
		}
	}
}

func buildResponder(log logrus.FieldLogger, opt options.Options) server.Responder {
	var responder server.Responder
	if opt.Response != "" {
		info, exists := responses.BuiltIn[opt.Response]
		if !exists {
			responder = responses.File(opt.Response)

			rlog := log.WithField("file", opt.Response)

			// try to read the file
			_, err := responder(nil, nil)
			if err != nil {
				rlog.WithError(err).Warn("Cannot read file.")
			} else {
				rlog.Info("Responding with file contents.")
			}
		} else {
			responder = info.Responder
			log.WithField("responder", opt.Response).Info("Using built-in responder.")
		}
	} else {
		responder = responses.Nop()
	}

	return responder
}

func listBuiltInResponses() {
	var (
		identifiers []string
		maxLength   int
	)
	for identifier := range responses.BuiltIn {
		identifiers = append(identifiers, identifier)
		if l := len(identifier); l > maxLength {
			maxLength = l
		}
	}
	slices.Sort(identifiers)

	fmt.Println("The following identifiers can be used for --response:")
	fmt.Println("")

	format := fmt.Sprintf("  %%-%ds   %%s\n", maxLength)

	for _, identifier := range identifiers {
		info := responses.BuiltIn[identifier]
		fmt.Printf(format, identifier, info.Description)
	}
}
