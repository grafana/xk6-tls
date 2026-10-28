// Package tls give access to information access and operations for tls connections
package tls

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/grafana/sobek"
	"go.k6.io/k6/v2/js/modules"
	"go.k6.io/k6/v2/js/promises"
)

type (
	// RootModule is the global module instance that will create Client
	// instances for each VU.
	RootModule struct{}

	// ModuleInstance represents an instance of the JS module.
	ModuleInstance struct {
		vu modules.VU
	}
)

// Ensure the interfaces are implemented correctly
var (
	_ modules.Instance = &ModuleInstance{}
	_ modules.Module   = &RootModule{}
)

// New returns a pointer to a new RootModule instance
func New() *RootModule {
	return &RootModule{}
}

// NewModuleInstance implements the modules.Module interface and returns
// a new instance for each VU.
func (*RootModule) NewModuleInstance(vu modules.VU) modules.Instance {
	return &ModuleInstance{
		vu: vu,
	}
}

// Exports implements the modules.Instance interface and returns
// the exports of the JS module.
func (mi *ModuleInstance) Exports() modules.Exports {
	return modules.Exports{Default: mi}
}

type GetCertificateOptions struct {
	InsecureSkipVerify *bool  `json:"insecureSkipVerify"`
	ServerName         string `json:"serverName"`
}

func parseOptions(runtime *sobek.Runtime, value sobek.Value) (GetCertificateOptions, error) {
	var opts GetCertificateOptions

	if value == nil || sobek.IsUndefined(value) || sobek.IsNull(value) {
		return opts, nil
	}

	obj := value.ToObject(runtime)
	if obj == nil {
		return opts, fmt.Errorf("TLS options must be an object")
	}

	if v := obj.Get("insecureSkipVerify"); v != nil && !sobek.IsUndefined(v) && !sobek.IsNull(v) {
		b, ok := v.Export().(bool)
		if !ok {
			return opts, fmt.Errorf("insecureSkipVerify must be a boolean")
		}
		opts.InsecureSkipVerify = &b
	}

	if v := obj.Get("serverName"); v != nil && !sobek.IsUndefined(v) && !sobek.IsNull(v) {
		s, ok := v.Export().(string)
		if !ok {
			return opts, fmt.Errorf("serverName must be a string")
		}
		opts.ServerName = s
	}

	return opts, nil
}

func buildTLSConfig(target addr, opts GetCertificateOptions) *tls.Config {
	// we need to skip the check otherwise any eventual
	// expired certificate will return an error
	insecureSkipVerify := true

	if opts.InsecureSkipVerify != nil {
		insecureSkipVerify = *opts.InsecureSkipVerify
	}

	var serverName string
	if opts.ServerName != "" {
		serverName = opts.ServerName
	}

	return &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: insecureSkipVerify,
	}
}

// GetCertificate fetches and exposes the peer certificate's details.
func (mi *ModuleInstance) GetCertificate(target string, options sobek.Value) *sobek.Promise {
	p, resolve, reject := promises.New(mi.vu)

	state := mi.vu.State()
	if state == nil {
		reject(fmt.Errorf("getCertificate is not allowed to run from the Init Context"))
		return p
	}

	addr, err := parseTargetAddr(target)
	if err != nil {
		reject(err)
		return p
	}

	go func() {
		netconn, err := state.Dialer.DialContext(mi.vu.Context(), "tcp", addr.uri)
		if err != nil {
			reject(err)
			return
		}
		defer func() {
			err := netconn.Close()
			if err != nil {
				state.Logger.WithError(err).Debug("Failed to close connection")
			}
		}()

		opts, err := parseOptions(mi.vu.Runtime(), options)
		if err != nil {
			reject(err)
			return
		}

		tlsOpts := buildTLSConfig(addr, opts)
		if !tlsOpts.InsecureSkipVerify && opts.ServerName == "" {
			reject(fmt.Errorf("serverName is required when insecureSkipVerify is false"))
			return
		}
		conn := tls.Client(netconn, tlsOpts)
		if err := conn.HandshakeContext(mi.vu.Context()); err != nil {
			reject(err)
			return
		}
		peerCerts := conn.ConnectionState().PeerCertificates
		if len(peerCerts) < 1 {
			reject(fmt.Errorf("no certificate found for %s - the server may not be using TLS or the connection failed", target))
			return
		}
		c := peerCerts[0]
		vc := mi.vu.Runtime().ToValue(certificate{
			Subject:     pkixName{CommonName: c.Subject.CommonName},
			Issuer:      pkixName{CommonName: c.Issuer.CommonName},
			Issued:      c.NotBefore.UnixMilli(),
			Expires:     c.NotAfter.UnixMilli(),
			Fingerprint: fingerprint(c.Raw),
		})
		resolve(vc)
	}()
	return p
}

type certificate struct {
	Subject     pkixName
	Issuer      pkixName
	Issued      int64
	Expires     int64
	Fingerprint string
}

func fingerprint(cert []byte) string {
	sum := sha256.Sum256(cert)
	return fmt.Sprintf("%x", sum)
}

type pkixName struct {
	CommonName string
}
type addr struct {
	host, port string
	uri        string
}

func parseTargetAddr(target string) (addr, error) {
	if target == "" {
		return addr{}, fmt.Errorf("target address was not provided")
	}
	port := "443" // default https port

	if !strings.Contains(target, ":") {
		return addr{
			host: target,
			port: port,
			uri:  net.JoinHostPort(target, port),
		}, nil
	}

	h, p, err := net.SplitHostPort(target)
	if err != nil {
		return addr{}, err
	}
	if h == "" {
		return addr{}, fmt.Errorf("the provided target does not contain a valid address in the host:[port] format")
	}

	if p != "" {
		_, parseErr := strconv.ParseUint(p, 10, 16)
		if parseErr != nil {
			return addr{}, fmt.Errorf("the provided target does not contain a valid port %q", p)
		}
		port = p
	}

	return addr{
		host: h,
		port: port,
		uri:  net.JoinHostPort(h, port),
	}, nil
}
