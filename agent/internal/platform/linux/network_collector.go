//go:build linux

package linux

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/edr-platform/agent/internal/collector"
	"github.com/google/uuid"
)

// ProcNetCollector implements collector.NetworkCollector by polling /proc/net.
type ProcNetCollector struct {
	known map[string]struct{} // srcIP:srcPort:dstIP:dstPort
}

// NewProcNetCollector creates a new /proc/net-based network collector.
func NewProcNetCollector() *ProcNetCollector {
	return &ProcNetCollector{
		known: make(map[string]struct{}),
	}
}

// Start begins polling /proc/net and sends new connections to out.
func (c *ProcNetCollector) Start(ctx context.Context, out chan<- collector.NetworkEvent) error {
	go c.poll(ctx, out)
	return nil
}

// Stop is a no-op for the proc net collector.
func (c *ProcNetCollector) Stop() error {
	return nil
}

func (c *ProcNetCollector) poll(ctx context.Context, out chan<- collector.NetworkEvent) {
	// Send initial snapshot immediately
	c.scanFile(ctx, "/proc/net/tcp", "tcp", false, out)
	c.scanFile(ctx, "/proc/net/tcp6", "tcp", true, out)
	c.scanFile(ctx, "/proc/net/udp", "udp", false, out)
	c.scanFile(ctx, "/proc/net/udp6", "udp", true, out)

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.scanFile(ctx, "/proc/net/tcp", "tcp", false, out)
			c.scanFile(ctx, "/proc/net/tcp6", "tcp", true, out)
			c.scanFile(ctx, "/proc/net/udp", "udp", false, out)
			c.scanFile(ctx, "/proc/net/udp6", "udp", true, out)
		}
	}
}

func (c *ProcNetCollector) scanFile(ctx context.Context, path, proto string, ipv6 bool, out chan<- collector.NetworkEvent) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	// Skip header line
	scanner.Scan()

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// fields[3] is state in hex; 01 = ESTABLISHED
		if fields[3] != "01" {
			continue
		}

		localAddr := fields[1]
		remoteAddr := fields[2]

		srcIP, srcPort, err := parseHexAddr(localAddr, ipv6)
		if err != nil {
			continue
		}
		dstIP, dstPort, err := parseHexAddr(remoteAddr, ipv6)
		if err != nil {
			continue
		}

		key := fmt.Sprintf("%s:%d:%s:%d", srcIP, srcPort, dstIP, dstPort)
		if _, exists := c.known[key]; exists {
			continue
		}
		c.known[key] = struct{}{}

		evt := collector.NetworkEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			SrcIP:     srcIP,
			SrcPort:   uint16(srcPort),
			DstIP:     dstIP,
			DstPort:   uint16(dstPort),
			Protocol:  proto,
			Direction: "outbound",
		}

		select {
		case out <- evt:
		case <-ctx.Done():
			return
		default:
		}
	}
	if err := scanner.Err(); err != nil {
		slog.Warn("ネットワーク接続スキャン中にエラー", "path", path, "error", err)
	}
}

// parseHexAddr parses a hex address in the format "XXXXXXXX:PPPP" or IPv6 variant.
func parseHexAddr(hexAddr string, ipv6 bool) (string, int, error) {
	parts := strings.SplitN(hexAddr, ":", 2)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid address: %s", hexAddr)
	}

	addrHex := parts[0]
	portHex := parts[1]

	// Parse port
	port64, err := strconv.ParseInt(portHex, 16, 32)
	if err != nil {
		return "", 0, fmt.Errorf("parse port: %w", err)
	}

	// Parse IP
	addrBytes, err := hex.DecodeString(addrHex)
	if err != nil {
		return "", 0, fmt.Errorf("decode addr hex: %w", err)
	}

	var ip net.IP
	if ipv6 {
		if len(addrBytes) != 16 {
			return "", 0, fmt.Errorf("invalid ipv6 addr length: %d", len(addrBytes))
		}
		// IPv6 is stored as 4 little-endian 32-bit words
		b := make([]byte, 16)
		for i := 0; i < 4; i++ {
			b[i*4+0] = addrBytes[i*4+3]
			b[i*4+1] = addrBytes[i*4+2]
			b[i*4+2] = addrBytes[i*4+1]
			b[i*4+3] = addrBytes[i*4+0]
		}
		ip = net.IP(b)
	} else {
		if len(addrBytes) != 4 {
			return "", 0, fmt.Errorf("invalid ipv4 addr length: %d", len(addrBytes))
		}
		// IPv4 is stored in little-endian byte order
		ip = net.IPv4(addrBytes[3], addrBytes[2], addrBytes[1], addrBytes[0])
	}

	return ip.String(), int(port64), nil
}
