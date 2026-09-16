package httpqueryb64

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

func b64Std(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func b64URL(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// buildCtx builds a sniffing context: an outbound session targeting the
// gateway (ip:port) plus sniffing content with the given config.
func buildCtx(dst []string, param, variant string, target net.Destination) context.Context {
	ctx := context.Background()
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{
		OriginalTarget: target,
		Target:         target,
	}})
	ctx = session.ContextWithContent(ctx, &session.Content{
		SniffingRequest: session.SniffingRequest{
			Enabled: true,
			HTTPQueryB64: &session.HTTPQueryB64{
				Param:   param,
				Dst:     dst,
				Variant: variant,
			},
		},
	})
	return ctx
}

func gatewayDest() net.Destination {
	d, _ := net.ParseDestination("tcp:10.10.0.1:8080")
	return d
}

func TestSniffUnnamedParamStd(t *testing.T) {
	ctx := buildCtx([]string{"10.10.0.1:8080"}, "", "", gatewayDest())
	req := "GET /?" + b64Std("https://example.com/video") + " HTTP/1.1\r\nHost: 10.10.0.1:8080\r\n\r\n"
	h, err := Sniff([]byte(req), ctx)
	if err != nil {
		t.Fatalf("Sniff() error = %v", err)
	}
	if h.Protocol() != "httpqueryb64" {
		t.Errorf("Protocol() = %v", h.Protocol())
	}
	if h.Domain() != "example.com" {
		t.Errorf("Domain() = %v", h.Domain())
	}
}

func TestSniffNamedParamURLSafeNoPadding(t *testing.T) {
	ctx := buildCtx([]string{"10.10.0.1:8080"}, "url", "", gatewayDest())
	req := "GET /?foo=1&url=" + b64URL("http://cdn.example.com/f") + " HTTP/1.1\r\nHost: 10.10.0.1:8080\r\n\r\n"
	h, err := Sniff([]byte(req), ctx)
	if err != nil {
		t.Fatalf("Sniff() error = %v", err)
	}
	if h.Domain() != "cdn.example.com" {
		t.Errorf("Domain() = %v", h.Domain())
	}
}

func TestSniffPercentEscapedPlus(t *testing.T) {
	// Standard base64 of "https://a.example.com/z~z" contains '+'; a query
	// transport percent-escapes it as %2B. The sniffer must decode it back
	// and NOT treat '+' as space.
	const encB64 = "aHR0cHM6Ly9hLmV4YW1wbGUuY29tL3p+eg=="
	if !strings.ContainsRune(encB64, '+') {
		t.Fatal("test vector lost its '+' — pick another")
	}
	escaped := strings.ReplaceAll(encB64, "+", "%2B")
	ctx := buildCtx([]string{"10.10.0.1:8080"}, "", "", gatewayDest())
	req := "GET /?" + escaped + " HTTP/1.1\r\nHost: 10.10.0.1:8080\r\n\r\n"
	h, err := Sniff([]byte(req), ctx)
	if err != nil {
		t.Fatalf("Sniff() error = %v", err)
	}
	if h.Domain() != "a.example.com" {
		t.Errorf("Domain() = %v, want a.example.com", h.Domain())
	}
}

func TestSniffDstMismatchNoClue(t *testing.T) {
	ctx := buildCtx([]string{"10.10.0.1:8080"}, "", "", mustDest("tcp:10.10.0.2:8080"))
	req := "GET /?" + b64Std("https://example.com/") + " HTTP/1.1\r\nHost: 10.10.0.2:8080\r\n\r\n"
	_, err := Sniff([]byte(req), ctx)
	if err != common.ErrNoClue {
		t.Errorf("dst mismatch: err = %v, want ErrNoClue", err)
	}
}

func TestSniffNoQueryNoClue(t *testing.T) {
	ctx := buildCtx([]string{"10.10.0.1:8080"}, "", "", gatewayDest())
	req := "GET /path HTTP/1.1\r\nHost: example.org\r\n\r\n"
	_, err := Sniff([]byte(req), ctx)
	if err != common.ErrNoClue {
		t.Errorf("no query: err = %v, want ErrNoClue", err)
	}
}

func TestSniffUndecodableFallsBackNoClue(t *testing.T) {
	ctx := buildCtx([]string{"10.10.0.1:8080"}, "", "", gatewayDest())
	req := "GET /?!!!not-base64!!! HTTP/1.1\r\nHost: 10.10.0.1:8080\r\n\r\n"
	_, err := Sniff([]byte(req), ctx)
	if err != common.ErrNoClue {
		t.Errorf("undecodable: err = %v, want ErrNoClue", err)
	}
}

func TestSniffMixedAlphabetsRejected(t *testing.T) {
	ctx := buildCtx([]string{"10.10.0.1:8080"}, "", "", gatewayDest())
	// auto variant: mixing '-' (urlsafe) and '+' (standard) must fail.
	mixed := "abcd+efg-hijk"
	req := "GET /?" + mixed + " HTTP/1.1\r\nHost: 10.10.0.1:8080\r\n\r\n"
	_, err := Sniff([]byte(req), ctx)
	if err != common.ErrNoClue {
		t.Errorf("mixed alphabets: err = %v, want ErrNoClue", err)
	}
}

func TestSniffNoConfigNoClue(t *testing.T) {
	ctx := context.Background()
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: gatewayDest()}})
	ctx = session.ContextWithContent(ctx, &session.Content{
		SniffingRequest: session.SniffingRequest{Enabled: true},
	})
	req := "GET /?" + b64Std("https://example.com/") + " HTTP/1.1\r\n\r\n"
	_, err := Sniff([]byte(req), ctx)
	if err != common.ErrNoClue {
		t.Errorf("no config: err = %v, want ErrNoClue", err)
	}
}

func TestSniffIPv6HostInURL(t *testing.T) {
	ctx := buildCtx([]string{"10.10.0.1:8080"}, "", "", gatewayDest())
	req := "GET /?" + b64Std("http://[2001:db8::1]:8080/x") + " HTTP/1.1\r\nHost: 10.10.0.1:8080\r\n\r\n"
	h, err := Sniff([]byte(req), ctx)
	if err != nil {
		t.Fatalf("Sniff() error = %v", err)
	}
	if h.Domain() != "2001:db8::1" {
		t.Errorf("Domain() = %v, want 2001:db8::1", h.Domain())
	}
}

func TestSniffUppercaseHostLowered(t *testing.T) {
	ctx := buildCtx([]string{"10.10.0.1:8080"}, "", "", gatewayDest())
	req := "GET /?" + b64Std("https://WWW.Example.COM/") + " HTTP/1.1\r\nHost: 10.10.0.1:8080\r\n\r\n"
	h, err := Sniff([]byte(req), ctx)
	if err != nil {
		t.Fatalf("Sniff() error = %v", err)
	}
	if h.Domain() != "www.example.com" {
		t.Errorf("Domain() = %v, want www.example.com", h.Domain())
	}
}

func mustDest(s string) net.Destination {
	d, err := net.ParseDestination(s)
	if err != nil {
		panic(err)
	}
	return d
}
