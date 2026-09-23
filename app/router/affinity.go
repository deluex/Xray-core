package router

import (
	"container/list"
	"strconv"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/net"
)

// AffinityTable remembers which outbound traffic was routed to, on two
// levels:
//
//   - domain → outbound: which outbound served a domain's original
//     connection, so follow-up connections to a fixed gateway destination
//     (whose real target is only recoverable by sniffing) can be sent to
//     the same outbound.
//   - gateway → outbound: the outbound last used for a gateway destination.
//     Follow-up requests to the same gateway that carry no sniffable hint
//     of their own (no ori_url query) reuse it.
//
// Entries expire after ttl without refresh; each level holds at most
// maxEntries keys (LRU eviction).
type AffinityTable struct {
	mu         sync.Mutex
	ttl        time.Duration
	maxEntries int
	domains    affinityStore
	gateways   affinityStore
}

// affinityStore is one LRU+TTL keyed set of outbound tags.
type affinityStore struct {
	entries map[string]*list.Element // key → element of *affinityEntry
	lru     list.List                // front = most recently used
}

type affinityEntry struct {
	key       string
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
		domains:    affinityStore{entries: make(map[string]*list.Element)},
		gateways:   affinityStore{entries: make(map[string]*list.Element)},
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

// gatewayKey builds the store key for a gateway destination. Only
// address+port matter; a bare "ip:port" config entry matches any network,
// so the recorded key must not depend on it either.
func gatewayKey(dest net.Destination) string {
	return dest.Address.String() + ":" + strconv.Itoa(int(dest.Port))
}

// Get returns the remembered outbound for domain, if present and not
// expired. A hit moves the entry to the LRU front.
func (a *AffinityTable) Get(domain string) (string, bool) {
	if a == nil {
		return "", false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.domains.get(domain)
}

// Put records (or refreshes) the outbound for domain.
func (a *AffinityTable) Put(domain, outbound string) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.domains.put(domain, outbound, a.ttl, a.maxEntries)
}

// GetGateway returns the outbound last used for the gateway destination.
// Note: IsValid() is deliberately not required — a bare "ip:port"
// destination parses with Network_Unknown and !IsValid() but is still a
// usable key.
func (a *AffinityTable) GetGateway(dest net.Destination) (string, bool) {
	if a == nil || dest.Address == nil {
		return "", false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.gateways.get(gatewayKey(dest))
}

// PutGateway records (or refreshes) the outbound last used for the gateway
// destination.
func (a *AffinityTable) PutGateway(dest net.Destination, outbound string) {
	if a == nil || dest.Address == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.gateways.put(gatewayKey(dest), outbound, a.ttl, a.maxEntries)
}

func (s *affinityStore) get(key string) (string, bool) {
	if key == "" {
		return "", false
	}
	el, ok := s.entries[key]
	if !ok {
		return "", false
	}
	entry := el.Value.(*affinityEntry)
	if time.Now().After(entry.expiresAt) {
		s.removeLocked(el)
		return "", false
	}
	s.lru.MoveToFront(el)
	return entry.outbound, true
}

func (s *affinityStore) put(key, outbound string, ttl time.Duration, maxEntries int) {
	if key == "" || outbound == "" {
		return
	}
	now := time.Now()
	if el, ok := s.entries[key]; ok {
		entry := el.Value.(*affinityEntry)
		entry.outbound = outbound
		entry.expiresAt = now.Add(ttl)
		s.lru.MoveToFront(el)
		return
	}
	if s.lru.Len() >= maxEntries {
		if oldest := s.lru.Back(); oldest != nil {
			s.removeLocked(oldest)
		}
	}
	el := s.lru.PushFront(&affinityEntry{
		key:       key,
		outbound:  outbound,
		expiresAt: now.Add(ttl),
	})
	s.entries[key] = el
}

func (s *affinityStore) removeLocked(el *list.Element) {
	entry := s.lru.Remove(el).(*affinityEntry)
	delete(s.entries, entry.key)
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

// LookupGatewayAffinity implements routing.DomainAffinity.
func (r *Router) LookupGatewayAffinity(dest net.Destination) (string, bool) {
	return r.affinity.GetGateway(dest)
}

// RecordGatewayAffinity implements routing.DomainAffinity.
func (r *Router) RecordGatewayAffinity(dest net.Destination, outbound string) {
	r.affinity.PutGateway(dest, outbound)
}
