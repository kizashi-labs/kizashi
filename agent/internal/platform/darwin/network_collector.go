//go:build darwin

package darwin

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/edr-platform/agent/internal/collector"
	"github.com/google/uuid"
)

// DarwinNetworkCollector monitors network connections on macOS.
// Uses lsof for process-to-connection correlation.
// For production: use Network Extension framework via CGo.
type DarwinNetworkCollector struct {
	cancel context.CancelFunc
	seen   map[string]darwinConnInfo
}

type darwinConnInfo struct {
	key       string
	srcIP     string
	dstIP     string
	srcPort   uint16
	dstPort   uint16
	protocol  string
	pid       uint32
	procName  string
	state     string
	firstSeen time.Time
}

func NewDarwinNetworkCollector() *DarwinNetworkCollector {
	return &DarwinNetworkCollector{
		seen: make(map[string]darwinConnInfo),
	}
}

func (c *DarwinNetworkCollector) Start(ctx context.Context, out chan<- collector.NetworkEvent) error {
	ctx, c.cancel = context.WithCancel(ctx)
	go c.poll(ctx, out)
	return nil
}

func (c *DarwinNetworkCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}

func (c *DarwinNetworkCollector) poll(ctx context.Context, out chan<- collector.NetworkEvent) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			conns := c.listConnections()

			// Report new connections
			for key, conn := range conns {
				if _, exists := c.seen[key]; !exists {
					evt := collector.NetworkEvent{
						ID:          uuid.New().String(),
						Timestamp:   time.Now(),
						SrcIP:       conn.srcIP,
						SrcPort:     conn.srcPort,
						DstIP:       conn.dstIP,
						DstPort:     conn.dstPort,
						Protocol:    conn.protocol,
						Direction:   "outbound",
						PID:         conn.pid,
						ProcessName: conn.procName,
					}
					select {
					case out <- evt:
					case <-ctx.Done():
						return
					}
				}
			}

			c.seen = conns
		}
	}
}

// listConnections uses lsof to get network connections with PID info.
func (c *DarwinNetworkCollector) listConnections() map[string]darwinConnInfo {
	result := make(map[string]darwinConnInfo)

	// lsof -i -n -P: all internet connections, no hostname resolution, no port names
	cmd := exec.Command("lsof", "-i", "-n", "-P", "-F", "pfnPcT")
	out, err := cmd.Output()
	if err != nil {
		return result
	}

	var currentPID uint32
	var currentName string
	var conn darwinConnInfo

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 2 {
			continue
		}

		field := line[0]
		value := line[1:]

		switch field {
		case 'p': // PID
			pid, _ := strconv.ParseUint(value, 10, 32)
			currentPID = uint32(pid)
		case 'c': // command name
			currentName = value
		case 'P': // protocol
			conn.protocol = strings.ToLower(value)
		case 'T': // connection state (TST=...)
			if strings.HasPrefix(value, "ST=") {
				conn.state = strings.TrimPrefix(value, "ST=")
			}
		case 'n': // name: src->dst or src
			if strings.Contains(value, "->") {
				parts := strings.Split(value, "->")
				if len(parts) == 2 {
					conn.srcIP, conn.srcPort = parseLsofAddr(parts[0])
					conn.dstIP, conn.dstPort = parseLsofAddr(parts[1])
					conn.pid = currentPID
					conn.procName = currentName

					if conn.dstIP != "" && conn.srcIP != "" {
						key := fmt.Sprintf("%d-%s:%d->%s:%d",
							conn.pid, conn.srcIP, conn.srcPort,
							conn.dstIP, conn.dstPort)
						conn.key = key
						conn.firstSeen = time.Now()
						result[key] = conn
					}
					conn = darwinConnInfo{}
				}
			}
		}
	}

	return result
}

func parseLsofAddr(addr string) (string, uint16) {
	// Handle IPv6 [::1]:port and IPv4 1.2.3.4:port
	if strings.HasPrefix(addr, "[") {
		// IPv6
		bracketEnd := strings.LastIndex(addr, "]")
		if bracketEnd < 0 {
			return "", 0
		}
		ip := addr[1:bracketEnd]
		portStr := ""
		if bracketEnd+2 < len(addr) {
			portStr = addr[bracketEnd+2:] // skip "]:"
		}
		port, _ := strconv.ParseUint(portStr, 10, 16)
		return ip, uint16(port)
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0
	}
	port, _ := strconv.ParseUint(portStr, 10, 16)
	return host, uint16(port)
}
