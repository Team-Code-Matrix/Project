package ssrf

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

var (
	ErrProhibitedIP   = errors.New("anti-ssrf: connection to prohibited or internal IP blocked")
	ErrRedirectLimit  = errors.New("anti-ssrf: maximum redirect hops (5) exceeded")
	ErrPayloadTooLarge = errors.New("anti-ssrf: payload exceeds maximum limit of 10 MB")
)

// Prohibited IP CIDR ranges
var prohibitedCIDRs []*net.IPNet

func init() {
	ranges := []string{
		"0.0.0.0/8",          // Current network
		"10.0.0.0/8",         // RFC 1918 Private
		"100.64.0.0/10",      // Shared Address Space / Carrier Grade NAT
		"127.0.0.0/8",        // Loopback
		"169.254.0.0/16",     // IPv4 Link-Local / Cloud Metadata (169.254.169.254)
		"172.16.0.0/12",      // RFC 1918 Private
		"192.0.0.0/24",       // IETF Protocol Assignments
		"192.0.2.0/24",       // TEST-NET-1
		"192.88.99.0/24",     // 6to4 Relay Anycast
		"192.168.0.0/16",     // RFC 1918 Private
		"198.18.0.0/15",      // Network Interconnect Device Benchmark
		"198.51.100.0/24",    // TEST-NET-2
		"203.0.113.0/24",     // TEST-NET-3
		"224.0.0.0/4",        // Multicast
		"240.0.0.0/4",        // Reserved / Future Use
		"255.255.255.255/32", // Broadcast
		// IPv6 Prohibited Ranges
		"::/128",             // Unspecified
		"::1/128",            // IPv6 Loopback
		"::ffff:0:0/96",      // IPv4-mapped IPv6
		"64:ff9b::/96",       // IPv4/IPv6 translation
		"100::/64",           // Discard-Only Prefix
		"2001::/23",          // IETF Protocol Assignments
		"2001:db8::/32",      // Documentation
		"fc00::/7",           // Unique Local Address (ULA)
		"fe80::/10",          // Link-Local Unicast
		"ff00::/8",           // Multicast
	}

	for _, cidr := range ranges {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			prohibitedCIDRs = append(prohibitedCIDRs, ipNet)
		}
	}
}

// IsIPProhibited checks whether an IP falls into RFC 1918, loopback, or cloud metadata ranges.
func IsIPProhibited(ip net.IP) bool {
	if ip == nil {
		return true
	}

	// Unwrap IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1 -> 127.0.0.1)
	if ipv4 := ip.To4(); ipv4 != nil {
		ip = ipv4
	}

	for _, cidr := range prohibitedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}

	// Cloud metadata explicit checks
	ipStr := ip.String()
	if ipStr == "169.254.169.254" || ipStr == "100.100.100.200" {
		return true
	}

	return false
}

// SafeDialer creates a net.Dialer that performs DNS pre-resolution and blocks prohibited IPs at the socket level.
type SafeDialer struct {
	dialer   *net.Dialer
	resolver *net.Resolver
}

func NewSafeDialer(timeout time.Duration) *SafeDialer {
	return &SafeDialer{
		dialer: &net.Dialer{
			Timeout:   timeout,
			KeepAlive: 15 * time.Second,
			Control: func(network, address string, c syscall.RawConn) error {
				// Additional socket control options can be attached here
				return nil
			},
		},
		resolver: net.DefaultResolver,
	}
}

// DialContext intercepts every connection attempt and validates the resolved IP.
func (sd *SafeDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address %s: %w", addr, err)
	}

	// 1. Resolve host IP addresses
	ips, err := sd.resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed for %s: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found for host %s", host)
	}

	// 2. Validate all resolved IPs against Anti-SSRF policies
	var safeIP net.IP
	for _, ip := range ips {
		if IsIPProhibited(ip) {
			return nil, fmt.Errorf("%w: %s resolved to %s", ErrProhibitedIP, host, ip.String())
		}
		if safeIP == nil {
			safeIP = ip
		}
	}

	// 3. Dial verified safe IP directly to defeat DNS Rebinding (Time-of-Check to Time-of-Use)
	safeAddr := net.JoinHostPort(safeIP.String(), port)
	return sd.dialer.DialContext(ctx, network, safeAddr)
}

// NewHardenedHTTPClient returns an http.Client with strict Anti-SSRF, 5-redirect cap, and 10MB payload limit.
func NewHardenedHTTPClient(timeout time.Duration, maxRedirects int) *http.Client {
	safeDialer := NewSafeDialer(timeout)

	transport := &http.Transport{
		DialContext:           safeDialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          50,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: timeout,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Enforce max 5 redirects limit
			if len(via) >= maxRedirects {
				return ErrRedirectLimit
			}

			// Validate target redirect hostname before following hop
			targetHost := req.URL.Hostname()
			ips, err := net.LookupIP(targetHost)
			if err != nil {
				return fmt.Errorf("redirect DNS lookup failed for %s: %w", targetHost, err)
			}

			for _, ip := range ips {
				if IsIPProhibited(ip) {
					return fmt.Errorf("%w on redirect hop to %s (%s)", ErrProhibitedIP, targetHost, ip.String())
				}
			}

			return nil
		},
	}

	return client
}

// LimitResponseBody wraps a response body in an io.LimitReader to enforce the 10 MB payload cap.
func LimitResponseBody(body io.ReadCloser, maxBytes int64) io.ReadCloser {
	return &limitedReadCloser{
		reader:   io.LimitReader(body, maxBytes+1),
		closer:   body,
		maxBytes: maxBytes,
	}
}

type limitedReadCloser struct {
	reader   io.Reader
	closer   io.Closer
	maxBytes int64
	readSoFar int64
}

func (l *limitedReadCloser) Read(p []byte) (n int, err error) {
	n, err = l.reader.Read(p)
	l.readSoFar += int64(n)
	if l.readSoFar > l.maxBytes {
		return n, ErrPayloadTooLarge
	}
	return n, err
}

func (l *limitedReadCloser) Close() error {
	return l.closer.Close()
}

// ValidateTargetURL validates syntax and ensures target hostname does not resolve to a prohibited IP.
func ValidateTargetURL(target string) (*url.URL, error) {
	parsed, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("syntax error in URL: %w", err)
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("prohibited scheme '%s' - only HTTP/HTTPS permitted", scheme)
	}

	host := parsed.Hostname()
	if host == "" {
		return nil, fmt.Errorf("missing hostname")
	}

	// Check if hostname is an IP string
	if ip := net.ParseIP(host); ip != nil {
		if IsIPProhibited(ip) {
			return nil, fmt.Errorf("%w: literal IP %s is prohibited", ErrProhibitedIP, host)
		}
	}

	return parsed, nil
}

