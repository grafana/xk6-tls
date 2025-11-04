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
	"go.k6.io/k6/js/modules"
	"go.k6.io/k6/js/promises"
	"go.k6.io/k6/lib/netext"
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

// GetCertificate fetches and exposes the peer certificate's details.
func (mi *ModuleInstance) GetCertificate(target string) *sobek.Promise {
	p, resolve, reject := promises.New(mi.vu)

	state := mi.vu.State()
	if state == nil {
		reject(fmt.Errorf("not allowed to run in initcontext"))
		return p
	}

	addr, err := parseTargetAddr(target)
	if err != nil {
		reject(err)
		return p
	}

	d, ok := state.Dialer.(*netext.Dialer)
	if !ok {
		panic("state.Dialer is not the expected *netext.Dialer type")
	}
	if d.BlockedHostnames != nil {
		if _, blocked := d.BlockedHostnames.Contains(addr.host); blocked {
			reject(fmt.Sprintf("blocked hostname: %s", addr))
			return p
		}
	}

	go func() {
		td := tls.Dialer{
			NetDialer: &d.Dialer,
			Config: &tls.Config{
				//nolint:gosec
				// we need to skip the check otherwise any eventual
				// expired certificate will return an error
				InsecureSkipVerify: true,
			},
		}
		rawconn, err := td.DialContext(mi.vu.Context(), "tcp", addr.uri)
		if err != nil {
			reject(err)
			return
		}
		defer func() {
			err := rawconn.Close()
			if err != nil {
				state.Logger.WithError(err).Warn("Failed closing connection for TLS certificate detection")
			}
		}()
		conn, ok := rawconn.(*tls.Conn)
		if !ok {
			panic("the dialing operation didn't return the expected tls.Conn type")
		}
		peerCerts := conn.ConnectionState().PeerCertificates
		if len(peerCerts) < 1 {
			reject(fmt.Errorf("chain of peer certificates for %q is empty", target))
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
