// SPDX-FileCopyrightText: 2024 Christoph Mewes
// SPDX-License-Identifier: MIT

package server

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"os"

	"github.com/sirupsen/logrus"

	"go.xrstf.de/httest/pkg/options"
)

func NewHandler(log logrus.FieldLogger, opt options.Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logFullBody := opt.Trace && !opt.JSON
		logContext := logrus.Fields{
			"remote":   r.RemoteAddr,
			"method":   r.Method,
			"path":     r.URL.String(),
			"protocol": r.Proto,
			"ua":       r.UserAgent(),
		}

		var receivedRequest []byte

		if opt.Echo || logFullBody {
			dumped, err := httputil.DumpRequest(r, true)
			if err != nil {
				log.WithError(err).Error("Failed to dump request.")
				dumped = []byte("Could not dump incoming request.\n")
			}

			dumped = append(dumped, '\n')
			receivedRequest = dumped
		}

		if opt.Trace && opt.JSON {
			logContext["headers"] = r.Header

			body, err := io.ReadAll(r.Body)
			r.Body.Close()

			if err != nil {
				log.WithError(err).Error("Failed to dump request body.")
			} else {
				logContext["body"] = string(body)
			}
		}

		var response []byte

		switch {
		case opt.Echo:
			response = receivedRequest

		case opt.Response != "":
			content, err := os.ReadFile(opt.Response)
			if err != nil {
				log.WithError(err).Error("Failed to read response file.")
				response = []byte("Failed to read response file.\n")
			} else {
				response = content
			}
		}

		log.WithFields(logContext).Info("Request")

		if logFullBody {
			fmt.Fprint(os.Stderr, string(receivedRequest))
		}

		if opt.ServerName != "" {
			w.Header().Set("Httest-Server", opt.ServerName)
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		if _, err := w.Write(response); err != nil {
			log.WithError(err).Error("Failed to send response.")
		}
	}
}
