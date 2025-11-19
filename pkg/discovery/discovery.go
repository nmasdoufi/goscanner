package discovery

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/x1thexxx-lgtm/goscanner/pkg/config"
	"github.com/x1thexxx-lgtm/goscanner/pkg/logging"
)

// HostResult describes liveness outcome.
type HostResult struct {
	IP        netip.Addr
	Alive     bool
	OpenPorts map[int]time.Duration
	MAC       string
	LastError error
}

// Scanner performs network discovery.
type Scanner struct {
	profile config.Profile
	logger  *logging.Logger
}

// NewScanner constructs scanner for profile.
func NewScanner(profile config.Profile, logger *logging.Logger) *Scanner {
	if profile.MaxWorkers == 0 {
		profile.MaxWorkers = 64
	}
	if profile.TimeoutMS == 0 {
		profile.TimeoutMS = 1000
	}
	if len(profile.Ports) == 0 {
		profile.Ports = []int{22, 80, 443, 135, 139, 445, 3389, 161}
	}
	return &Scanner{profile: profile, logger: logger}
}

// ScanCIDR enumerates a CIDR range and tests hosts.
func (s *Scanner) ScanCIDR(ctx context.Context, cidr string) ([]HostResult, error) {
	ips, err := expandCIDR(cidr)
	if err != nil {
		return nil, err
	}
	timeout := time.Duration(s.profile.TimeoutMS) * time.Millisecond
	workerCount := s.profile.MaxWorkers
	jobs := make(chan netip.Addr)
	results := make([]HostResult, 0, len(ips))
	var mu sync.Mutex
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for ip := range jobs {
			select {
			case <-ctx.Done():
				return
			default:
			}
			res := HostResult{IP: ip, OpenPorts: map[int]time.Duration{}}
			for _, port := range s.profile.Ports {
				start := time.Now()
				addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
				conn, err := net.DialTimeout("tcp", addr, timeout)
				if err == nil {
					res.Alive = true
					res.OpenPorts[port] = time.Since(start)
					conn.Close()
				}
			}

			// Attempt to get MAC address if host is alive
			if res.Alive {
				res.MAC = getMACAddress(ip.String())
			}

			mu.Lock()
			results = append(results, res)
			mu.Unlock()
		}
	}

	if workerCount <= 0 {
		workerCount = 64
	}
	wg.Add(workerCount)
	for i := 0; i < workerCount; i++ {
		go worker()
	}
	go func() {
		defer close(jobs)
		for _, ip := range ips {
			select {
			case <-ctx.Done():
				return
			case jobs <- ip:
			}
		}
	}()
	wg.Wait()
	return results, nil
}

func expandCIDR(cidr string) ([]netip.Addr, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse cidr %s: %w", cidr, err)
	}
	var ips []netip.Addr
	for addr := prefix.Masked().Addr(); prefix.Contains(addr); addr = addr.Next() {
		ips = append(ips, addr)
		if !addr.Next().IsValid() {
			break
		}
	}
	return ips, nil
}

// getMACAddress attempts to retrieve MAC address for an IP via ARP
func getMACAddress(ip string) string {
	// Try to get MAC from ARP table
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	// Parse the target IP
	targetIP := net.ParseIP(ip)
	if targetIP == nil {
		return ""
	}

	// Check each interface to find if the IP is in the same subnet
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			// Check if target IP is in this subnet
			if ipNet.Contains(targetIP) {
				// On same subnet, try ARP lookup
				if mac := lookupARPCache(ip); mac != "" {
					return mac
				}
			}
		}
	}

	return ""
}

// lookupARPCache reads the system ARP cache to find MAC address
func lookupARPCache(ip string) string {
	// This implementation uses platform-specific commands
	// For Linux: read /proc/net/arp
	// For Windows: use arp -a command
	// For macOS: use arp -n command

	// Try reading /proc/net/arp (Linux)
	data, err := os.ReadFile("/proc/net/arp")
	if err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines[1:] { // Skip header
			fields := strings.Fields(line)
			if len(fields) >= 4 && fields[0] == ip {
				mac := fields[3]
				if mac != "00:00:00:00:00:00" && len(mac) >= 17 {
					return normalizeMAC(mac)
				}
			}
		}
	}

	return ""
}

// normalizeMAC converts MAC address to standard format
func normalizeMAC(mac string) string {
	// Remove any dashes and convert to colon-separated format
	mac = strings.ReplaceAll(mac, "-", ":")
	mac = strings.ToUpper(mac)
	return mac
}
