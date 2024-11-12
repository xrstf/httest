// SPDX-FileCopyrightText: 2024 Christoph Mewes
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"

	"github.com/spf13/pflag"
)

func newHandler(instance string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if instance != "" {
			log.Printf(`[%s] [%s] "%s %s" %s "%s"`, instance, r.RemoteAddr, r.Method, r.URL, r.Proto, r.UserAgent())
		} else {
			log.Printf(`[%s] "%s %s" %s "%s"`, r.RemoteAddr, r.Method, r.URL, r.Proto, r.UserAgent())
		}

		response, err := httputil.DumpRequest(r, true)
		if err != nil {
			log.Println(err)

			w.WriteHeader(500)
			response = []byte("Could not dump incoming request.\n")
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(response)

		if instance != "" {
			w.Write([]byte(fmt.Sprintf("Instance: %s\n", instance)))
		}
	}
}

func main() {
	o := newDefaultOptions()
	o.AddFlags(pflag.CommandLine)
	pflag.Parse()

	log.Printf("Listening on %s…", o.ListenOn)

	http.HandleFunc("/", newHandler(o.ServerName))
	if err := http.ListenAndServe(o.ListenOn, nil); err != nil {
		log.Fatal(err)
	}
}
