// SPDX-FileCopyrightText: 2024 Christoph Mewes
// SPDX-License-Identifier: MIT

package responses

import (
	"embed"
	"net/http"

	"go.xrstf.de/httest/pkg/server"
)

//go:embed data/*
var embeddedFS embed.FS

func loadResponse(key string) ([]byte, error) {
	return embeddedFS.ReadFile("data/" + key)
}

func respondWith(key string) server.Responder {
	return func(_ *http.Request, _ []byte) ([]byte, error) {
		return embeddedFS.ReadFile("data/" + key)
	}
}
