package tls

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

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
		clock

		vu modules.VU
	}

	clock interface {
		Now() time.Time
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
		clock: clockNowFunc(time.Now),
		vu:    vu,
	}
}

// Exports implements the modules.Instance interface and returns
// the exports of the JS module.
func (mi *ModuleInstance) Exports() modules.Exports {
	return modules.Exports{Default: mi}
}

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

	d := state.Dialer.(*netext.Dialer)
	if d.BlockedHostnames != nil {
		if _, blocked := d.BlockedHostnames.Contains(addr.host); blocked {
			reject(fmt.Sprintf("blocked hostname: %s", addr))
			return p
		}
	}

	go func() {
		conn, err := tls.DialWithDialer(
			&d.Dialer,
			"tcp",
			addr.uri,
			&tls.Config{
				InsecureSkipVerify: true,
			})
		if err != nil {
			reject(err)
			return
		}
		defer func() {
			err := conn.Close()
			if err != nil {
				state.Logger.WithError(err).Warn("Failed closing connection for TLS certificate detection")
			}
		}()
		peerCerts := conn.ConnectionState().PeerCertificates
		if len(peerCerts) < 1 {
			reject(fmt.Errorf("chain of peer certificates for %q is empty", target))
			return
		}
		c := peerCerts[0]
		vc := mi.vu.Runtime().ToValue(Certificate{
			Subject:     PkixName{CommonName: c.Subject.CommonName},
			Issuer:      PkixName{CommonName: c.Issuer.CommonName},
			Issued:      c.NotBefore.UnixMilli(),
			Expires:     c.NotAfter.UnixMilli(),
			Fingerprint: fingerprint(c.Raw),
		})
		resolve(vc)
	}()
	return p
}

type Certificate struct {
	Subject     PkixName
	Issuer      PkixName
	Issued      int64
	Expires     int64
	Fingerprint string
}

type PkixName struct {
	CommonName string
}

func fingerprint(cert []byte) string {
	sum := sha256.Sum256(cert)
	return fmt.Sprintf("%x", sum)
}

type clockNowFunc func() time.Time

func (clockNowFunc) Now() time.Time {
	return time.Now()
}

type addr struct {
	host, port string
	uri        string
}

func parseTargetAddr(target string) (addr, error) {
	var a addr

	if target == "" {
		return a, fmt.Errorf("target address was not provided")
	}

	var (
		port = "443" // default https port
		host = target
	)

	if strings.Contains(target, ":") {
		h, p, err := net.SplitHostPort(target)
		if err != nil {
			return a, err
		}
		if h == "" {
			return a, fmt.Errorf("the provided target does not contain a valid address in the host:[port] format")
		}
		host = h

		if p != "" {
			_, parseErr := strconv.ParseUint(p, 10, 16)
			if parseErr != nil {
				return a, fmt.Errorf("the provided target does not contain a valid port %q", p)
			}
			port = p
		}
	}

	return addr{
		host: host,
		port: port,
		uri:  net.JoinHostPort(host, port),
	}, nil
}
