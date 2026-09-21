// Package httpqueryb64 recovers the real target host from an HTTP request
// whose query string carries the original URL in base64.
//
// Wire shape (origin-form and absolute-form request targets both work —
// only the part after '?' is examined):
//
//	GET /?aHR0cHM6Ly9leGFtcGxlLmNvbS92aWRlbw== HTTP/1.1\r\nHost: 10.0.0.1:8080\r\n\r\n
//
// where the query value decodes to a full URL such as
// https://example.com/video. The extracted host is reported as the sniffed
// domain; the dial target is untouched (route-only semantics — the gateway
// at the original ip:port unpacks the URL itself).
package httpqueryb64

import (
	"context"
	"net/netip"
	"strings"
	"unicode/utf8"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

// Hard caps mirroring the meow-rs implementation: the dispatcher's sniffing
// window is 32 KiB; anything longer is not a plausible encoded-URL payload.
const (
	maxEncodedLen = 4096
	maxDecodedLen = 3072
)

type variant int

const (
	variantAuto variant = iota
	variantStandard
	variantURLSafe
)

type SniffHeader struct {
	host string
}

func (h *SniffHeader) Protocol() string { return "httpqueryb64" }

func (h *SniffHeader) Domain() string { return h.host }

// Sniff extracts the routing host from an HTTP request whose query carries
// a base64-encoded original URL. It applies only when the inbound's
// sniffing config carries an http_query_b64 block whose dst list covers the
// connection's original destination. All failure modes return
// common.ErrNoClue so the http (Host header) sniffer gets its turn.
func Sniff(b []byte, c context.Context) (*SniffHeader, error) {
	content := session.ContentFromContext(c)
	if content == nil {
		errors.LogDebug(c, "httpqueryb64: no content in context, skip")
		return nil, common.ErrNoClue
	}
	cfg := content.SniffingRequest.HTTPQueryB64
	if cfg == nil || len(cfg.Dst) == 0 {
		errors.LogDebug(c, "httpqueryb64: no queryB64 config, skip")
		return nil, common.ErrNoClue
	}

	// dst gate: the original destination must be covered by the rule.
	outbounds := session.OutboundsFromContext(c)
	if len(outbounds) == 0 {
		errors.LogDebug(c, "httpqueryb64: no outbound session, skip")
		return nil, common.ErrNoClue
	}
	ob := outbounds[len(outbounds)-1]
	if !matchDst(cfg.Dst, ob.OriginalTarget, ob.Target) {
		errors.LogDebug(c, "httpqueryb64: dst [", ob.OriginalTarget.String(), ob.Target.String(), "] not in configured list, skip")
		return nil, common.ErrNoClue
	}

	// Request line: "GET /?<query> HTTP/1.1". The target is the second token.
	target, ok := requestTarget(b)
	if !ok {
		errors.LogDebug(c, "httpqueryb64: request line has no target, skip")
		return nil, common.ErrNoClue
	}
	_, query, found := strings.Cut(target, "?")
	if !found {
		errors.LogDebug(c, "httpqueryb64: request target has no query, skip")
		return nil, common.ErrNoClue
	}

	value := queryValue(query, cfg.Param)
	if value == "" || len(value) > maxEncodedLen {
		errors.LogDebug(c, "httpqueryb64: query param [", cfg.Param, "] empty or too long, skip")
		return nil, common.ErrNoClue
	}

	// Query transport may percent-escape alphabet chars (%2B for '+').
	// '+' is NOT treated as space: in standard base64 it is a data char.
	enc, ok := percentDecode(value)
	if !ok {
		errors.LogDebug(c, "httpqueryb64: percent-decode failed, skip")
		return nil, common.ErrNoClue
	}

	dec, ok := base64Decode(enc, parseVariant(cfg.Variant))
	if !ok {
		errors.LogDebug(c, "httpqueryb64: base64 decode failed, skip")
		return nil, common.ErrNoClue
	}

	url := string(dec)
	if !utf8.ValidString(url) {
		errors.LogDebug(c, "httpqueryb64: decoded URL is not valid UTF-8, skip")
		return nil, common.ErrNoClue
	}
	host := extractURLHost(url)
	if host == "" {
		errors.LogDebug(c, "httpqueryb64: decoded payload [", url, "] has no usable host, skip")
		return nil, common.ErrNoClue
	}
	errors.LogInfo(c, "httpqueryb64: sniffed domain [", host, "] from query")
	return &SniffHeader{host: strings.ToLower(host)}, nil
}

// matchDst reports whether the connection's original destination is covered
// by the configured gateway list. OriginalTarget is preferred (dispatcher
// sets it before sniffing); Target is the fallback. An optional "tcp:"/
// "udp:" prefix on a dst entry constrains the network; bare "ip:port"
// entries match any network.
func matchDst(dst []string, original, target net.Destination) bool {
	for _, d := range dst {
		parsed, err := net.ParseDestination(d)
		// Note: a bare "ip:port" entry parses with Network_Unknown and
		// !IsValid(); that is fine — destEquals treats Unknown as
		// "any network".
		if err != nil || parsed.Address == nil {
			continue
		}
		if destEquals(original, parsed) || destEquals(target, parsed) {
			return true
		}
	}
	return false
}

func destEquals(a, b net.Destination) bool {
	if !a.IsValid() {
		return false
	}
	networkMatch := b.Network == net.Network_Unknown || b.Network == a.Network
	return networkMatch && a.Address == b.Address && a.Port == b.Port
}

// requestTarget extracts the request target (second token) from the first
// line. No method validation: the http sniffer runs later and rejects
// non-HTTP bytes authoritatively.
func requestTarget(b []byte) (string, bool) {
	lineEnd := strings.IndexByte(string(b), '\n')
	if lineEnd < 0 {
		return "", false
	}
	line := strings.TrimRight(string(b[:lineEnd]), "\r")
	parts := strings.Split(line, " ")
	if len(parts) != 3 {
		return "", false
	}
	target := parts[1]
	return target, target != ""
}

// queryValue returns the encoded URL from the query string. Empty param
// means the first unnamed parameter (the value directly following '?');
// a named param looks for "name=" among '&'-separated segments.
func queryValue(query, param string) string {
	if param == "" {
		first, _, _ := strings.Cut(query, "&")
		return first
	}
	for _, seg := range strings.Split(query, "&") {
		k, v, found := strings.Cut(seg, "=")
		if found && k == param {
			return v
		}
	}
	return ""
}

// percentDecode returns the %XX-decoded form of s.
func percentDecode(s string) (string, bool) {
	if !strings.ContainsRune(s, '%') {
		return s, true
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] == '%' {
			if i+2 >= len(s) {
				return "", false
			}
			hi, ok1 := hexVal(s[i+1])
			lo, ok2 := hexVal(s[i+2])
			if !ok1 || !ok2 {
				return "", false
			}
			sb.WriteByte(hi<<4 | lo)
			i += 3
		} else {
			sb.WriteByte(s[i])
			i++
		}
	}
	return sb.String(), true
}

func hexVal(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	}
	return 0, false
}

const (
	stdAlphabet     = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	urlSafeAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)

// base64Decode returns the base64 decoding of src. Both padded and unpadded
// input are accepted; data after '=' is rejected. For variantAuto, the
// alphabet is inferred from the data ('-'/'_' → URL-safe, '+'/'/' →
// standard); mixing both fails.
func base64Decode(src string, v variant) (string, bool) {
	var table [256]int8
	switch v {
	case variantStandard:
		buildTable(&table, stdAlphabet)
	case variantURLSafe:
		buildTable(&table, urlSafeAlphabet)
	default:
		hasURLSafe := strings.ContainsAny(src, "-_")
		hasStandard := strings.ContainsAny(src, "+/")
		if hasURLSafe && hasStandard {
			return "", false
		}
		if hasURLSafe {
			buildTable(&table, urlSafeAlphabet)
		} else {
			buildTable(&table, stdAlphabet)
		}
	}

	var sb strings.Builder
	sb.Grow(len(src) * 3 / 4)
	var acc uint32
	var nbits uint
	padded := false
	for i := 0; i < len(src); i++ {
		val := table[src[i]]
		switch {
		case val >= 0:
			if padded {
				return "", false
			}
			acc = acc<<6 | uint32(val)
			nbits += 6
			if nbits >= 8 {
				nbits -= 8
				if sb.Len() >= maxDecodedLen {
					return "", false
				}
				sb.WriteByte(byte(acc >> nbits))
			}
		case val == -2: // '='
			padded = true
		default:
			return "", false
		}
	}
	return sb.String(), true
}

func buildTable(table *[256]int8, alphabet string) {
	for i := range table {
		table[i] = -1
	}
	for i := 0; i < len(alphabet); i++ {
		table[alphabet[i]] = int8(i)
	}
	table['='] = -2
}

func parseVariant(s string) variant {
	switch strings.ToLower(s) {
	case "standard":
		return variantStandard
	case "urlsafe", "url-safe", "url_safe":
		return variantURLSafe
	default:
		return variantAuto
	}
}

// extractURLHost extracts the host from an absolute URL
// (scheme://host[:port]/…) or a bare host[:port]/… form. Bracketed IPv6
// literals survive port stripping. Returns "" for malformed authorities.
func extractURLHost(url string) string {
	rest := url
	if i := strings.Index(url, "://"); i >= 0 {
		if !allSchemeBytes(url[:i]) {
			return ""
		}
		rest = url[i+3:]
	}

	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	authority := rest[:end]
	// userinfo@host:port — keep everything after the last '@'.
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		authority = authority[at+1:]
	}
	host := authority
	if strings.HasPrefix(host, "[") {
		// IPv6 literal: [::1] or [::1]:8080.
		if close := strings.IndexByte(host, ']'); close > 0 {
			host = host[1:close]
		} else {
			return ""
		}
	} else if colon := strings.IndexByte(host, ':'); colon >= 0 {
		host = host[:colon]
	}
	if host != "" && validHost(host) {
		return host
	}
	return ""
}

func allSchemeBytes(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' ||
			b == '+' || b == '-' || b == '.') {
			return false
		}
	}
	return true
}

// validHost: either a well-formed IP literal or a plausible hostname.
func validHost(host string) bool {
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	for i := 0; i < len(host); i++ {
		b := host[i]
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' ||
			b == '-' || b == '.' || b == '_') {
			return false
		}
	}
	return true
}
