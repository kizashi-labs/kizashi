//go:build darwin

package darwin

import (
	"bufio"
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/edr-platform/agent/internal/collector"
	"github.com/google/uuid"
)

// DarwinDNSCollector captures DNS queries on macOS using tcpdump.
// For production: use Network Extension framework for proper DNS monitoring.
type DarwinDNSCollector struct {
	cancel context.CancelFunc
	iface  string
}

func NewDarwinDNSCollector(iface string) *DarwinDNSCollector {
	if iface == "" {
		iface = "en0"
	}
	return &DarwinDNSCollector{iface: iface}
}

func (c *DarwinDNSCollector) Start(ctx context.Context, out chan<- collector.DNSEvent) error {
	ctx, c.cancel = context.WithCancel(ctx)
	go c.capture(ctx, out)
	return nil
}

func (c *DarwinDNSCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}

func (c *DarwinDNSCollector) capture(ctx context.Context, out chan<- collector.DNSEvent) {
	// tcpdump -i en0 -l -n port 53
	cmd := exec.CommandContext(ctx, "tcpdump",
		"-i", c.iface,
		"-l", "-n",
		"-s", "0",
		"port", "53",
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
		}

		line := scanner.Text()
		evt := parseTcpdumpDNS(line)
		if evt == nil {
			continue
		}

		select {
		case out <- *evt:
		case <-ctx.Done():
			return
		}
	}
}

// parseTcpdumpDNS parses a tcpdump DNS output line.
// Example: "12:34:56.789 IP 10.0.1.5.53422 > 8.8.8.8.53: A? example.com. (30)"
func parseTcpdumpDNS(line string) *collector.DNSEvent {
	if !strings.Contains(line, " A? ") && !strings.Contains(line, " AAAA? ") &&
		!strings.Contains(line, " A ") {
		return nil
	}

	// Very simplified parser — production should use gopacket
	parts := strings.Fields(line)
	if len(parts) < 8 {
		return nil
	}

	var queryName string
	for i, p := range parts {
		if (p == "A?" || p == "AAAA?" || p == "A") && i+1 < len(parts) {
			queryName = strings.TrimSuffix(parts[i+1], ".")
			break
		}
	}

	if queryName == "" {
		return nil
	}

	qtype := "A"
	if strings.Contains(line, "AAAA?") {
		qtype = "AAAA"
	}

	return &collector.DNSEvent{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		Query:     queryName,
		QueryType: qtype,
	}
}
