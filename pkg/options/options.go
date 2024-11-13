// SPDX-FileCopyrightText: 2024 Christoph Mewes
// SPDX-License-Identifier: MIT

package options

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/pflag"
)

type Options struct {
	ListenOn   string
	ServerName string
	Echo       bool
	Response   string
	Trace      bool
	Version    bool
	TLS        TLSOptions
}

func NewDefault() Options {
	return Options{
		ListenOn: "localhost:8080",
		TLS: TLSOptions{
			Directory: ".httest",
			Hostnames: []string{"localhost", "127.0.0.1"},
		},
	}
}

func (o *Options) AddFlags(fs *pflag.FlagSet) {
	fs.StringVarP(&o.ListenOn, "listen", "l", o.ListenOn, "Hostname and port to listen on.")
	fs.StringVarP(&o.ServerName, "server-name", "", o.ServerName, "Unique server name to include in responses.")
	fs.BoolVarP(&o.Echo, "echo", "e", o.Echo, "Respond to the client with the received request.")
	fs.BoolVarP(&o.Trace, "trace", "t", o.Trace, "Log full request bodies on stderr.")
	fs.BoolVarP(&o.Version, "version", "V", o.Version, "Show version info and exit immediately.")
	fs.StringVarP(&o.Response, "response", "r", o.Response, "Send the contents of this file as the response.")
	o.TLS.AddFlags(fs)
}

func (o *Options) Validate() error {
	if err := o.TLS.Validate(); err != nil {
		return fmt.Errorf("invalid TLS options: %w", err)
	}

	if o.Response != "" && o.Echo {
		return errors.New("cannot enable --echo and --response at the same time")
	}

	if o.Response != "" {
		if info, err := os.Stat(o.Response); err != nil {
			return fmt.Errorf("invalid response file %q: %w", o.Response, err)
		} else if info.IsDir() {
			return fmt.Errorf("invalid response file %q: is a directory", o.Response)
		}
	}

	return nil
}

type TLSOptions struct {
	Enabled   bool
	Directory string
	Hostnames []string
}

func (o *TLSOptions) AddFlags(fs *pflag.FlagSet) {
	fs.BoolVarP(&o.Enabled, "tls", "", o.Enabled, "Use TLS with a self-signed certificate.")
	fs.StringVarP(&o.Directory, "pki-directory", "", o.Directory, "Directory where CA and serving certificate should be created in.")
	fs.StringSliceVarP(&o.Hostnames, "tls-hostnames", "n", o.Hostnames, "Comma-separated list of domain names to include in the serving certificate.")
}

func (o *TLSOptions) Validate() error {
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
