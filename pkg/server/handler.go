// SPDX-FileCopyrightText: 2024 Christoph Mewes
// SPDX-License-Identifier: MIT

package server

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"os"

	"go.xrstf.de/httest/pkg/options"
)

func NewHandler(opt options.Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var receivedRequest []byte

		if opt.Echo || opt.Trace {
			dumped, err := httputil.DumpRequest(r, true)
			if err != nil {
				log.Printf("Failed to dump request: %v", err)

				w.WriteHeader(500)
				dumped = []byte("Could not dump incoming request.\n")
			}

			receivedRequest = dumped
		}

		var response []byte

		switch {
		case opt.Echo:
			response = receivedRequest

		case opt.Response != "":
			content, err := os.ReadFile(opt.Response)
			if err != nil {
				log.Printf("Failed to read response file: %v", err)
				response = []byte(fmt.Sprintf("Failed to read response file: %v", err))
			} else {
				response = content
			}
		}

		logMessage := fmt.Sprintf(`[%s] "%s %s" %s "%s"`, r.RemoteAddr, r.Method, r.URL, r.Proto, r.UserAgent())
		if opt.Trace {
			logMessage += fmt.Sprintf("\n%s", string(receivedRequest))
		}

		log.Println(logMessage)

		if opt.ServerName != "" {
			w.Header().Set("Httest-Server", opt.ServerName)
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(response)
	}
}
