package router

import (
	"container/list"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/net"
)

// AffinityTable remembers which outbound a domain was first routed to, so
// follow-up connections to a fixed gateway destination (whose real target is
// only recoverable by sniffing) can be sent to the same outbound that
// served the domain's original connection. Without the table, the gateway
// traffic would be re-classified by rules against the gateway IP itself.
//
// Entries expire after ttl without refresh; the table holds at most
// maxEntries domains (LRU eviction).
type AffinityTable struct {
	mu         sync.Mutex
	ttl        time.Duration
	maxEntries int
	entries    map[string]*list.Element // domain → element of *affinityEntry
	lru        list.List                // front = most recently used
}

type affinityEntry struct {
	domain    string
	outbound  string
	expiresAt time.Time
}

const (
	defaultAffinityTTL        = 10 * time.Minute
	defaultAffinityMaxEntries = 65536
)

func newAffinityTable(cfg *AffinityConfig) *AffinityTable {
	if cfg == nil || !cfg.Enabled {
		return nil
	}
	ttl := time.Duration(cfg.TtlSeconds) * time.Second
	if ttl <= 0 {
		ttl = defaultAffinityTTL
	}
	maxEntries := int(cfg.MaxEntries)
	if maxEntries <= 0 {
		maxEntries = defaultAffinityMaxEntries
	}
	return &AffinityTable{
		ttl:        ttl,
		maxEntries: maxEntries,
		entries:    make(map[string]*list.Element),
	}
}

// MatchSpecialDst reports whether dest is covered by the configured
// special-dst gateway list ("ip:port" strings; an optional "tcp:"/"udp:"
// prefix constrains the network).
func (a *AffinityTable) MatchSpecialDst(specialDst []string, dest net.Destination) bool {
	if a == nil || !dest.IsValid() || !dest.Address.Family().IsIP() {
		return false
	}
	for _, d := range specialDst {
		parsed, err := net.ParseDestination(d)
		if err != nil || parsed.Address == nil {
			continue
		}
		networkMatch := parsed.Network == net.Network_Unknown || parsed.Network == dest.Network
		if networkMatch && parsed.Address == dest.Address && parsed.Port == dest.Port {
			return true
		}
	}
	return false
}

// Get returns the remembered outbound for domain, if present and not
// expired. A miss moves the entry to the LRU front.
func (a *AffinityTable) Get(domain string) (string, bool) {
	if a == nil || domain == "" {
		return "", false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	el, ok := a.entries[domain]
	if !ok {
		return "", false
	}
	entry := el.Value.(*affinityEntry)
	if time.Now().After(entry.expiresAt) {
		a.removeLocked(el)
		return "", false
	}
	a.lru.MoveToFront(el)
	return entry.outbound, true
}

// Put records (or refreshes) the outbound for domain.
func (a *AffinityTable) Put(domain, outbound string) {
	if a == nil || domain == "" || outbound == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	if el, ok := a.entries[domain]; ok {
		entry := el.Value.(*affinityEntry)
		entry.outbound = outbound
		entry.expiresAt = now.Add(a.ttl)
		a.lru.MoveToFront(el)
		return
	}
	if a.lru.Len() >= a.maxEntries {
		if oldest := a.lru.Back(); oldest != nil {
			a.removeLocked(oldest)
		}
	}
	el := a.lru.PushFront(&affinityEntry{
		domain:    domain,
		outbound:  outbound,
		expiresAt: now.Add(a.ttl),
	})
	a.entries[domain] = el
}

func (a *AffinityTable) removeLocked(el *list.Element) {
	entry := a.lru.Remove(el).(*affinityEntry)
	delete(a.entries, entry.domain)
}

// Router-side accessors used by the dispatcher through the
// routing.DomainAffinity interface.

// LookupAffinity implements routing.DomainAffinity.
func (r *Router) LookupAffinity(domain string) (string, bool) {
	return r.affinity.Get(domain)
}

// RecordAffinity implements routing.DomainAffinity.
func (r *Router) RecordAffinity(domain, outbound string) {
	r.affinity.Put(domain, outbound)
}

// MatchSpecialDst reports whether dest is one of the configured affinity
// gateways. It implements routing.DomainAffinity.
func (r *Router) MatchSpecialDst(dest net.Destination) bool {
	return r.affinity.MatchSpecialDst(r.specialDst, dest)
}
