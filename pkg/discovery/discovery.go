package discovery

import (
	"context"
	"fmt"
	"net"
	"net/netip"
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
