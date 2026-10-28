// Package httpclient builds HTTP clients for matchers that talk to
// self-hosted services, which often use a private or self-signed CA.
package httpclient

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"
)

// TLSOptions controls certificate verification. CACertFile is preferred;
// InsecureSkipVerify is a last resort for lab instances.
type TLSOptions struct {
	CACertFile         string
	InsecureSkipVerify bool
}

// New returns a client with the given timeout and TLS settings. An unreadable
// or invalid CA file is an error rather than a silent fallback to the system
// roots, so misconfiguration surfaces on the first request.
func New(timeout time.Duration, opts TLSOptions) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}

	if opts.CACertFile != "" {
		pem, err := os.ReadFile(opts.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("unable to read CA certificate file %s: %w", opts.CACertFile, err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no PEM certificates found in %s", opts.CACertFile)
		}
		tlsConfig.RootCAs = pool
	}
	if opts.InsecureSkipVerify {
		tlsConfig.InsecureSkipVerify = true // explicit opt-in, documented as lab-only
	}

	transport.TLSClientConfig = tlsConfig
	return &http.Client{Timeout: timeout, Transport: transport}, nil
}
