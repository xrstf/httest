// SPDX-FileCopyrightText: 2024 Christoph Mewes
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"os"

	"github.com/spf13/pflag"
)

type options struct {
	ListenOn   string
	ServerName string
	TLS        tlsOptions
}

func newDefaultOptions() options {
	return options{
		ListenOn: "localhost:8080",
		TLS: tlsOptions{
			Directory: ".httest",
			Hostnames: []string{"localhost", "127.0.0.1"},
		},
	}
}

func (o *options) AddFlags(fs *pflag.FlagSet) {
	fs.StringVarP(&o.ListenOn, "listen", "l", o.ListenOn, "Hostname and port to listen on.")
	fs.StringVarP(&o.ServerName, "server-name", "", o.ServerName, "Unique server name to include in responses.")
	o.TLS.AddFlags(fs)
}

func (o *options) Validate() error {
	if err := o.TLS.Validate(); err != nil {
		return fmt.Errorf("invalid TLS options: %w", err)
	}

	return nil
}

type tlsOptions struct {
	Enabled   bool
	Directory string
	Hostnames []string
}

func (o *tlsOptions) AddFlags(fs *pflag.FlagSet) {
	fs.BoolVarP(&o.Enabled, "tls", "", o.Enabled, "Use TLS with a self-signed certificate.")
	fs.StringVarP(&o.Directory, "pki-directory", "", o.Directory, "Directory where CA and serving certificate should be created in.")
	fs.StringSliceVarP(&o.Hostnames, "tls-hostnames", "n", o.Hostnames, "Comma-separated list of domain names to include in the serving certificate.")
}

func (o *tlsOptions) Validate() error {
	if !o.Enabled {
		return nil
	}

	if o.Directory == "" {
		o.Directory = ".httest"
	}

	if info, err := os.Stat(o.Directory); err != nil {
		if err := os.MkdirAll(o.Directory, 0755); err != nil {
			return fmt.Errorf("PKI directory %q does not exist and could not be created", o.Directory)
		}
	} else if !info.IsDir() {
		return fmt.Errorf("PKI directory %q points to a file", o.Directory)
	}

	return nil
}
