package tls

import (
	"fmt"
	"net"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.k6.io/k6/js/modulestest"
	"go.k6.io/k6/lib"
	"go.k6.io/k6/lib/netext"
	"go.k6.io/k6/lib/types"
	"go.k6.io/k6/metrics"
)

func TestGetCertificateOK(t *testing.T) {
	t.Parallel()
	trt := newTestRuntime(t)

	ts := httptest.NewTLSServer(nil)
	defer ts.Close()

	testcases := []string{
		fmt.Sprintf(`await tls.getCertificate("%s")`, strings.TrimPrefix(ts.URL, "https://")),
	}

	for i, tc := range testcases {
		t.Run("testcase#"+strconv.Itoa(i), func(t *testing.T) {
			_, err := trt.RunOnEventLoop(wrapInAsyncLambda(tc))
			assert.NoError(t, err)
		})
	}

}

func TestGetCertificateNoTLS(t *testing.T) {
	t.Parallel()
	trt := newTestRuntime(t)

	ts := httptest.NewServer(nil)
	defer ts.Close()

	testScript := fmt.Sprintf(`await tls.getCertificate("%s")`, strings.TrimPrefix(ts.URL, "http://"))

	_, err := trt.RunOnEventLoop(wrapInAsyncLambda(testScript))
	assert.ErrorContains(t, err, "not look like a TLS handshake")
}

func TestGetCertificateBlockedHostname(t *testing.T) {
	t.Parallel()
	trt := newTestRuntime(t)

	ts := httptest.NewTLSServer(nil)
	defer ts.Close()

	testScript := `await tls.getCertificate("blocked.net")`
	_, err := trt.RunOnEventLoop(wrapInAsyncLambda(testScript))
	assert.ErrorContains(t, err, "blocked hostname")
}

func newTestRuntime(t testing.TB) *modulestest.Runtime {
	runtime := modulestest.NewRuntime(t)

	err := runtime.SetupModuleSystem(
		map[string]any{"k6/x/tls": New()},
		nil,
		nil,
	)
	require.NoError(t, err)

	_, err = runtime.VU.Runtime().RunString(initGlobals)
	require.NoError(t, err)

	state := newTestVUState()
	state.Dialer = newTestDialer()
	runtime.MoveToVUContext(state)

	return runtime
}

func newTestVUState() *lib.State {
	return &lib.State{
		BuiltinMetrics: metrics.RegisterBuiltinMetrics(metrics.NewRegistry()),
		Dialer:         newTestDialer(),
		Tags:           lib.NewVUStateTags(metrics.NewRegistry().RootTagSet().With("tag-vu", "mytag")),
		Samples:        make(chan metrics.SampleContainer, 8),
	}
}

func newTestDialer() *netext.Dialer {

	d := netext.NewDialer(net.Dialer{
		Timeout:   2 * time.Second,
		KeepAlive: 10 * time.Second,
	}, nil)

	blacklist := []*lib.IPNet{{
		IPNet: net.IPNet{
			IP:   net.ParseIP("1.1.1.1"), // just an ip
			Mask: net.IPv4Mask(0, 0, 0, 0),
		},
	}}
	d.Blacklist = blacklist

	trie, _ := types.NewHostnameTrie([]string{"blocked.net"})
	d.BlockedHostnames = trie

	return d
}

func TestParseTargetAddr(t *testing.T) {
	testcases := []struct {
		target  string
		expAddr string
		expErr  string
	}{
		{"", "", "target address was not provided"},
		{"htt://", "", "not contain a valid port"},
		{"http://", "", "not contain a valid port"},
		{"http://notok.com", "", "not contain a valid port"},
		{"https://ok.com", "", "not contain a valid port"},
		{"https://ok.com:", "", "too many colons"},
		{"ok.com", "ok.com:443", ""},
		{"ok.com:", "ok.com:443", ""},
		{"ok.com:443", "ok.com:443", ""},
		{"ok.com:1234", "ok.com:1234", ""},
		{"ok.com:65536", "", "not contain a valid port"}, // over the max allowed
	}
	for _, tc := range testcases {
		t.Run(tc.target, func(t *testing.T) {
			addr, err := parseTargetAddr(tc.target)
			if tc.expErr != "" {
				require.ErrorContains(t, err, tc.expErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expAddr, addr.uri)
			}
		})
	}
}

// wrapInAsyncLambda is a helper function that wraps the provided input in an async lambda.
// This makes the use of `await` statements in the input possible.
func wrapInAsyncLambda(input string) string {
	// This makes it possible to use `await` freely on the "top" level
	return "(async () => {\n " + input + "\n })()"
}

const initGlobals = `
	globalThis.tls = require("k6/x/tls");
`
