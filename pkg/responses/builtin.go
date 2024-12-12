// SPDX-FileCopyrightText: 2024 Christoph Mewes
// SPDX-License-Identifier: MIT

package responses

import (
	"net/http"
	"os"

	"go.xrstf.de/httest/pkg/server"
)

type Responder struct {
	Responder   server.Responder
	Description string
}

var BuiltIn = map[string]Responder{
	"kubernetes:authz:allow": {
		Responder:   respondWith("kubernetes-authz-allow.json"),
		Description: "responds with a Kubernetes SubjectAccessReview with status.allowed=true",
	},
	"kubernetes:authz:deny": {
		Responder:   respondWith("kubernetes-authz-deny.json"),
		Description: "responds with a Kubernetes SubjectAccessReview with status.denied=true",
	},
	"kubernetes:authz:no-opinion": {
		Responder:   respondWith("kubernetes-authz-no-opinion.json"),
		Description: "responds with a Kubernetes SubjectAccessReview with status.allowed=false",
	},
	"echo": {
		Responder:   Echo(),
		Description: "echoes the incoming request verbatim to the client",
	},
}

func File(filename string) server.Responder {
	return func(_ *http.Request, _ []byte) ([]byte, error) {
		return os.ReadFile(filename)
	}
}

func Echo() server.Responder {
	return func(_ *http.Request, body []byte) ([]byte, error) {
		return body, nil
	}
}

func Nop() server.Responder {
	return func(_ *http.Request, _ []byte) ([]byte, error) {
		return nil, nil
	}
}
