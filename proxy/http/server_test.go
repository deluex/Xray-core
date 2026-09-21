package http

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/session"
)

// TestHandlePlainHTTPPreservesSniffingRequest guards the fix for plain HTTP
// proxy requests losing the inbound sniffing config: handlePlainHTTP builds
// a fresh session.Content for attributes, which used to drop the
// SniffingRequest installed by proxyman/inbound/always.go — disabling
// sniffing (including httpqueryb64) for every plain request.
func TestHandlePlainHTTPPreservesSniffingRequest(t *testing.T) {
	sr := session.SniffingRequest{
		Enabled:     true,
		RouteOnly:   true,
		HTTPQueryB64: &session.HTTPQueryB64{Dst: []string{"10.10.0.1:8080"}},
	}
	ctx := session.ContextWithContent(context.Background(), &session.Content{
		SniffingRequest: sr,
	})

	// Reproduce the content swap in handlePlainHTTP.
	content := &session.Content{Protocol: "http/1.1"}
	if originContent := session.ContentFromContext(ctx); originContent != nil {
		content.SniffingRequest = originContent.SniffingRequest
	}
	ctx = session.ContextWithContent(ctx, content)

	got := session.ContentFromContext(ctx).SniffingRequest
	if !got.Enabled || !got.RouteOnly {
		t.Fatalf("sniffing request lost: %+v", got)
	}
	if got.HTTPQueryB64 == nil || len(got.HTTPQueryB64.Dst) != 1 {
		t.Fatalf("queryB64 config lost: %+v", got.HTTPQueryB64)
	}
}
