//go:build linux && ebpf

package linux

import "github.com/edr-platform/agent/internal/collector"

// NewFileCollector returns the eBPF-backed file collector when the agent is built
// with `-tags ebpf`. It attributes each file event to the acting process (pid/comm),
// which the ransomware mass-modification detector needs, and falls back to inotify
// internally if the eBPF program cannot load.
func NewFileCollector() collector.FileCollector { return NewEBPFFileCollector() }
