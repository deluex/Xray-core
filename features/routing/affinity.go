package routing

import "github.com/xtls/xray-core/common/net"

// DomainAffinity is an optional capability a Router may implement: it
// remembers which outbound a domain was first routed to, so follow-up
// connections whose real target is only recoverable by sniffing can reuse
// the same outbound. The dispatcher type-asserts this interface; routers
// without affinity support are unaffected.
type DomainAffinity interface {
	// LookupAffinity returns the remembered outbound tag for the domain.
	LookupAffinity(domain string) (string, bool)
	// RecordAffinity records the outbound tag chosen for the domain.
	RecordAffinity(domain, outbound string)
	// MatchSpecialDst reports whether dest is one of the configured
	// affinity gateway destinations ("ip:port").
	MatchSpecialDst(dest net.Destination) bool
}
