package router

import (
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
)

func TestAffinityPutGetRefresh(t *testing.T) {
	a := newAffinityTable(&AffinityConfig{Enabled: true, TtlSeconds: 60, MaxEntries: 10})
	if tag, ok := a.Get("example.com"); ok {
		t.Fatalf("empty table Get = %v, %v", tag, ok)
	}
	a.Put("example.com", "proxy-a")
	if tag, ok := a.Get("example.com"); !ok || tag != "proxy-a" {
		t.Fatalf("Get = %v, %v; want proxy-a, true", tag, ok)
	}
	// Overwrite.
	a.Put("example.com", "proxy-b")
	if tag, _ := a.Get("example.com"); tag != "proxy-b" {
		t.Fatalf("after overwrite Get = %v, want proxy-b", tag)
	}
}

func TestAffinityExpiry(t *testing.T) {
	a := newAffinityTable(&AffinityConfig{Enabled: true, TtlSeconds: 1, MaxEntries: 10})
	a.Put("example.com", "proxy-a")
	a.domains.entries["example.com"].Value.(*affinityEntry).expiresAt = time.Now().Add(-time.Second)
	if _, ok := a.Get("example.com"); ok {
		t.Fatal("expired entry must not be returned")
	}
	if _, ok := a.domains.entries["example.com"]; ok {
		t.Fatal("expired entry must be removed")
	}
}

func TestGatewayAffinityPutGet(t *testing.T) {
	a := newAffinityTable(&AffinityConfig{Enabled: true, TtlSeconds: 60, MaxEntries: 10})
	tcpDst := mustRouterDest("tcp:10.10.0.1:8080")
	if _, ok := a.GetGateway(tcpDst); ok {
		t.Fatal("empty gateway table must miss")
	}
	a.PutGateway(tcpDst, "proxy-a")
	if tag, ok := a.GetGateway(tcpDst); !ok || tag != "proxy-a" {
		t.Fatalf("GetGateway = %v, %v; want proxy-a, true", tag, ok)
	}
	// The key is address+port only: a network-less or udp variant of the
	// same gateway must hit the same record.
	if tag, ok := a.GetGateway(mustRouterDest("10.10.0.1:8080")); !ok || tag != "proxy-a" {
		t.Fatalf("network-less lookup = %v, %v; want proxy-a, true", tag, ok)
	}
	// Overwrite.
	a.PutGateway(tcpDst, "proxy-b")
	if tag, _ := a.GetGateway(tcpDst); tag != "proxy-b" {
		t.Fatalf("after overwrite GetGateway = %v, want proxy-b", tag)
	}
	// Domain and gateway stores are independent.
	a.Put("example.com", "proxy-c")
	if _, ok := a.GetGateway(mustRouterDest("tcp:9.9.9.9:80")); ok {
		t.Fatal("domain record must not leak into gateway store")
	}
}

func TestGatewayAffinityExpiry(t *testing.T) {
	a := newAffinityTable(&AffinityConfig{Enabled: true, TtlSeconds: 1, MaxEntries: 10})
	tcpDst := mustRouterDest("tcp:10.10.0.1:8080")
	a.PutGateway(tcpDst, "proxy-a")
	a.gateways.entries[gatewayKey(tcpDst)].Value.(*affinityEntry).expiresAt = time.Now().Add(-time.Second)
	if _, ok := a.GetGateway(tcpDst); ok {
		t.Fatal("expired gateway entry must not be returned")
	}
	if _, ok := a.gateways.entries[gatewayKey(tcpDst)]; ok {
		t.Fatal("expired gateway entry must be removed")
	}
}

func TestAffinityLRUEviction(t *testing.T) {
	a := newAffinityTable(&AffinityConfig{Enabled: true, TtlSeconds: 60, MaxEntries: 2})
	a.Put("a.com", "p1")
	a.Put("b.com", "p1")
	// Touch a.com so b.com becomes the LRU tail.
	a.Get("a.com")
	a.Put("c.com", "p1") // evicts b.com
	if _, ok := a.Get("b.com"); ok {
		t.Fatal("b.com should have been evicted")
	}
	if _, ok := a.Get("a.com"); !ok {
		t.Fatal("a.com should have survived")
	}
	if _, ok := a.Get("c.com"); !ok {
		t.Fatal("c.com should be present")
	}
}

func TestAffinityNilTable(t *testing.T) {
	// newAffinityTable returns nil for disabled config; all methods must be no-ops.
	var a *AffinityTable = newAffinityTable(&AffinityConfig{})
	if a != nil {
		t.Fatal("disabled config must yield nil table")
	}
	if _, ok := a.Get("x"); ok {
		t.Fatal("nil table Get must miss")
	}
	a.Put("x", "y") // must not panic
	if a.MatchSpecialDst([]string{"1.2.3.4:80"}, mustRouterDest("tcp:1.2.3.4:80")) {
		t.Fatal("nil table must not match special dst")
	}
}

func TestMatchSpecialDst(t *testing.T) {
	a := newAffinityTable(&AffinityConfig{Enabled: true})
	dst := []string{"10.10.0.1:8080"}
	if !a.MatchSpecialDst(dst, mustRouterDest("tcp:10.10.0.1:8080")) {
		t.Fatal("exact match expected")
	}
	if a.MatchSpecialDst(dst, mustRouterDest("tcp:10.10.0.1:8081")) {
		t.Fatal("port mismatch must not match")
	}
	if a.MatchSpecialDst(dst, mustRouterDest("tcp:10.10.0.2:8080")) {
		t.Fatal("ip mismatch must not match")
	}
	// Bare "ip:port" matches any network.
	if !a.MatchSpecialDst(dst, mustRouterDest("udp:10.10.0.1:8080")) {
		t.Fatal("bare entry must match udp too")
	}
	// "udp:" prefixed entry must not match a TCP connection.
	dstUDP := []string{"udp:10.10.0.1:8080"}
	if a.MatchSpecialDst(dstUDP, mustRouterDest("tcp:10.10.0.1:8080")) {
		t.Fatal("udp-prefixed entry must not match tcp")
	}
	if !a.MatchSpecialDst(dstUDP, mustRouterDest("udp:10.10.0.1:8080")) {
		t.Fatal("udp-prefixed entry must match udp")
	}
}

func mustRouterDest(s string) net.Destination {
	d, err := net.ParseDestination(s)
	if err != nil {
		panic(err)
	}
	return d
}
