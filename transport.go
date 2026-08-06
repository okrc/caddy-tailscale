// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: Apache-2.0

package tscaddy

// transport.go contains the Transport module.

import (
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func init() {
	caddy.RegisterModule(&Transport{})
}

// Transport is a caddy transport that uses a tailscale node to make requests.
type Transport struct {
	Name string `json:"name,omitempty"`

	node *tailscaleNode

	// A non-nil TLS config enables TLS.
	TLS *reverseproxy.TLSConfig `json:"tls,omitempty"`

	// rt is the http.RoundTripper used for requests.
	// Set during Provision; may differ from node.HTTPClient().Transport
	// when custom TLS settings (e.g. InsecureSkipVerify) are configured.
	rt http.RoundTripper
}

func (t *Transport) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.reverse_proxy.transport.tailscale",
		New: func() caddy.Module { return new(Transport) },
	}
}

// UnmarshalCaddyfile populates a Transport config from a caddyfile.
//
// We only support a single token identifying the name of a node in the App config.
// For example:
//
//	reverse_proxy {
//	  transport tailscale my-node
//	}
//
// If a node name is not specified, a default name is used.
func (t *Transport) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	const defaultNodeName = "caddy-proxy"

	d.Next() // skip transport name
	if d.NextArg() {
		t.Name = d.Val()
	} else {
		t.Name = defaultNodeName
	}

	// Parse optional block for TLS configuration
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "tls_client_auth":
			if t.TLS == nil {
				t.TLS = new(reverseproxy.TLSConfig)
			}
			if d.CountRemainingArgs() == 1 {
				_, t.TLS.ClientCertificateAutomate = d.NextArg(), d.Val()
			} else if d.CountRemainingArgs() == 2 {
				_, t.TLS.ClientCertificateFile = d.NextArg(), d.Val()
				_, t.TLS.ClientCertificateKeyFile = d.NextArg(), d.Val()
			} else {
				return d.ArgErr()
			}

		case "tls_insecure_skip_verify":
			if d.NextArg() {
				return d.ArgErr()
			}
			if t.TLS == nil {
				t.TLS = new(reverseproxy.TLSConfig)
			}
			t.TLS.InsecureSkipVerify = true

		case "tls_server_name":
			if !d.NextArg() {
				return d.ArgErr()
			}
			if t.TLS == nil {
				t.TLS = new(reverseproxy.TLSConfig)
			}
			t.TLS.ServerName = d.Val()

		case "tls_trust_pool":
			if !d.NextArg() {
				return d.ArgErr()
			}
			modStem := d.Val()
			modID := "tls.ca_pool.source." + modStem
			unm, err := caddyfile.UnmarshalModule(d, modID)
			if err != nil {
				return err
			}
			ca, ok := unm.(caddytls.CA)
			if !ok {
				return d.Errf("module %s is not a caddytls.CA", modID)
			}
			if t.TLS == nil {
				t.TLS = new(reverseproxy.TLSConfig)
			}
			if t.TLS.CARaw != nil {
				return d.Err("cannot specify \"tls_trust_pool\" twice in caddyfile")
			}
			t.TLS.CARaw = caddyconfig.JSONModuleObject(ca, "provider", modStem, nil)

		default:
			return d.Errf("unrecognized subdirective %s", d.Val())
		}
	}

	return nil
}

func (t *Transport) Provision(ctx caddy.Context) error {
	var err error
	t.node, err = getNode(ctx, t.Name)
	if err != nil {
		return err
	}

	tsTransport := t.node.HTTPClient().Transport
	t.rt = tsTransport

	// Apply custom TLS configuration to the transport if set.
	if t.TLS != nil {
		httpTransport, ok := tsTransport.(*http.Transport)
		if !ok {
			return nil
		}

		// MakeTLSClientConfig handles InsecureSkipVerify, ServerName,
		// and CARaw (custom CA pool via tls_trust_pool).
		tlsCfg, err := t.TLS.MakeTLSClientConfig(ctx)
		if err != nil {
			return err
		}
		httpTransport.TLSClientConfig = tlsCfg
	}

	return nil
}

func (t *Transport) Cleanup() error {
	// Decrement usage count of this node.
	_, err := nodes.Delete(t.Name)
	return err
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "" {
		if t.TLSEnabled() {
			req.URL.Scheme = "https"
		} else {
			req.URL.Scheme = "http"
		}
	}
	return t.rt.RoundTrip(req)
}

// TLSEnabled returns true if TLS is enabled.
func (h Transport) TLSEnabled() bool {
	return h.TLS != nil
}

// EnableTLS enables TLS on the transport.
func (h *Transport) EnableTLS(config *reverseproxy.TLSConfig) error {
	h.TLS = config
	return nil
}

var (
	_ http.RoundTripper         = (*Transport)(nil)
	_ caddy.Provisioner         = (*Transport)(nil)
	_ caddy.CleanerUpper        = (*Transport)(nil)
	_ caddyfile.Unmarshaler     = (*Transport)(nil)
	_ reverseproxy.TLSTransport = (*Transport)(nil)
)
