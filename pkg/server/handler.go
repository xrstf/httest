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

type Responder func(req *http.Request, body []byte) ([]byte, error)

func NewHandler(log logrus.FieldLogger, opt options.Options, responder Responder) http.HandlerFunc {
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

		response, err := responder(r, receivedRequest)
		if err != nil {
			log.WithError(err).Error("Failed to generate response.")
			response = []byte("Failed to generate response.\n")
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
