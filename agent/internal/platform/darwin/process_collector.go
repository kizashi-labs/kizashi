//go:build darwin && (!esf || !cgo)

// このファイルは ps コマンドによるポーリングを使用するフォールバック実装です。
//
// 制約に `|| !cgo` が入っているのは、ESF 実装が cgo ファイル（import "C"）で
// あるため。CGO_ENABLED=0 だと Go は cgo ファイルをビルド対象から丸ごと外すので、
// 「darwin && !esf」だけだと -tags esf かつ CGO_ENABLED=0 のときに ESF 実装も
// このフォールバックも両方消え、NewDarwinProcessCollector が未定義になる。
// 実際 `GOOS=darwin go build -tags esf` は長期間ビルド不能だった（CI が
// internal/platform/darwin だけを vet していて、未定義が露見する使用側
// cmd/agent を見ていなかったため気づけなかった）。
// Endpoint Security Framework (ESF) を使用する場合は -tags esf でビルドしてください。
// ESF ビルドには Apple の entitlement 承認と CGo が必要です。
// 参照: agent/internal/platform/darwin/process_collector_esf.go

package darwin

import (
	"bufio"
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/edr-platform/agent/internal/collector"
	"github.com/google/uuid"
)

// DarwinProcessCollector monitors processes on macOS using ps polling.
// For production, replace with Endpoint Security Framework (ESF) via CGo.
type DarwinProcessCollector struct {
	cancel context.CancelFunc
	seen   map[uint32]darwinProcInfo
}

type darwinProcInfo struct {
	pid         uint32
	ppid        uint32
	username    string
	name        string
	commandLine string
	imagePath   string
	firstSeen   time.Time
}

func NewDarwinProcessCollector() *DarwinProcessCollector {
	return &DarwinProcessCollector{
		seen: make(map[uint32]darwinProcInfo),
	}
}

func (c *DarwinProcessCollector) Start(ctx context.Context, out chan<- collector.ProcessEvent) error {
	ctx, c.cancel = context.WithCancel(ctx)
	go c.poll(ctx, out)
	return nil
}

func (c *DarwinProcessCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}

func (c *DarwinProcessCollector) poll(ctx context.Context, out chan<- collector.ProcessEvent) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current := c.listProcesses()

			// Detect new processes
			for pid, info := range current {
				if _, exists := c.seen[pid]; !exists {
					hashes := hashBinary(info.imagePath)
					evt := collector.ProcessEvent{
						ID:          uuid.New().String(),
						Timestamp:   time.Now(),
						PID:         info.pid,
						PPID:        info.ppid,
						ProcessName: info.name,
						CommandLine: info.commandLine,
						ImagePath:   info.imagePath,
						Username:    info.username,
						Hashes:      hashes,
						Action:      "create",
					}
					select {
					case out <- evt:
					case <-ctx.Done():
						return
					}
				}
			}

			// Detect exited processes
			for pid, info := range c.seen {
				if _, exists := current[pid]; !exists {
					evt := collector.ProcessEvent{
						ID:          uuid.New().String(),
						Timestamp:   time.Now(),
						PID:         info.pid,
						PPID:        info.ppid,
						ProcessName: info.name,
						CommandLine: info.commandLine,
						ImagePath:   info.imagePath,
						Username:    info.username,
						Action:      "terminate",
					}
					select {
					case out <- evt:
					case <-ctx.Done():
						return
					}
				}
			}

			c.seen = current
		}
	}
}

func (c *DarwinProcessCollector) listProcesses() map[uint32]darwinProcInfo {
	result := make(map[uint32]darwinProcInfo)

	// ps -axo pid,ppid,user,comm,args -ww
	cmd := exec.Command("ps", "-axo", "pid=,ppid=,user=,comm=,args=", "-ww")
	out, err := cmd.Output()
	if err != nil {
		return result
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Split: pid ppid user comm args...
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		pid64, err := strconv.ParseUint(fields[0], 10, 32)
		if err != nil {
			continue
		}
		ppid64, _ := strconv.ParseUint(fields[1], 10, 32)

		pid := uint32(pid64)
		ppid := uint32(ppid64)
		username := fields[2]
		name := filepath.Base(fields[3])
		cmdLine := strings.Join(fields[4:], " ")
		imagePath := fields[3]

		result[pid] = darwinProcInfo{
			pid:         pid,
			ppid:        ppid,
			username:    username,
			name:        name,
			commandLine: cmdLine,
			imagePath:   imagePath,
			firstSeen:   time.Now(),
		}
	}

	return result
}
