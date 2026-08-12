//go:build linux

package linux

import (
	"strings"
	"sync/atomic"
)

// procNoiseFiltered counts process events dropped at the source as known
// container-runtime scaffolding (see isRuntimeNoiseProc). Exposed as a counter so
// the suppression is measurable rather than a silent, invisible drop.
var procNoiseFiltered atomic.Uint64

// isRuntimeNoiseProc reports whether a process name is container-runtime
// scaffolding that fires a create+terminate for every container exec but carries
// no detection value. On a busy container host these dominate the process-event
// stream and starve the detection consumer — the process-event analogue of the
// /tmp/runc-* file churn removed by isRuntimeNoisePath.
//
// The actual workload process inside a container has its OWN comm (bash, python3,
// xmrig, …) and is deliberately NOT matched here, so in-container threat
// visibility is fully preserved; only the runtime helpers themselves are dropped.
//
// comm is bpf_get_current_comm / /proc/<pid>/comm, which the kernel truncates to
// 15 bytes (TASK_COMM_LEN-1). Matching is intentionally tight — exact names plus
// the runc/crun re-exec prefixes ("runc:[2:INIT]", "runc:[1:CHILD]") and the
// containerd-shim family ("containerd-shim-runc-v2" truncates to "containerd-shim")
// — so a real workload that merely starts with a similar string (e.g. "runcloud")
// is not swept up.
func isRuntimeNoiseProc(comm string) bool {
	switch comm {
	case "runc", "crun", "conmon":
		return true
	}
	if strings.HasPrefix(comm, "runc:") || strings.HasPrefix(comm, "crun:") {
		return true
	}
	if strings.HasPrefix(comm, "containerd-shim") {
		return true
	}
	return false
}

// isRuntimeNoiseCmd catches the one runtime helper that isRuntimeNoiseProc can't:
// runc's container-init re-exec, whose kernel comm is a bare "6" (the fd it
// re-execs through) rather than "runc", but whose command line is exactly
// "runc init". Matched on the full command line so nothing else is caught.
func isRuntimeNoiseCmd(cmdline string) bool {
	return cmdline == "runc init"
}

// benignCredTracers are processes that routinely read other processes' memory or
// /proc for legitimate reasons (process listing, container runtime setup, system
// inventory) and therefore trip the ptrace_access_check credential-access LSM
// (T1003/T1055) with no real credential theft. On a busy container host these are
// the dominant event source (measured: ps/runc/landscape-sysinfo made up the bulk
// of credential telemetry and ~half the whole event stream). comm is kernel-
// truncated to 15 bytes ("landscape-sysinfo" → "landscape-sysin").
//
// TRADEOFF: this is a comm allowlist, so a malicious process that renames itself
// to one of these names could evade the credential-access detector. Accepted to
// stop the false-positive flood; the tracer's actual behaviour is still visible to
// the process/behavioral pipeline.
// Entries are the exact comms observed tripping the detector in production, kept
// tight (no broad "systemd-*" prefix) so the allowlist stays evidence-based.
var benignCredTracers = map[string]struct{}{
	"ps": {}, "pgrep": {}, "pidof": {}, "top": {}, "htop": {},
	"runc": {}, "crun": {}, "conmon": {}, "containerd": {},
	"landscape-sysin": {}, // landscape-sysinfo, truncated to 15 bytes
	"systemd-journal": {}, "systemd": {},
	// Second wave, measured after the first allowlist landed: these were the
	// entire remaining false-positive population (~1150/day of bogus T1003).
	"needrestart":     {}, // scans /proc to find services needing restart
	"systemctl":       {}, // reads pid 1 (systemd) state
	"systemd-detect-": {}, // systemd-detect-virt, truncated to 15 bytes
	"cloud-id":        {}, // cloud metadata probe
}

// isBenignCredTracer reports whether a credential-access tracer comm is a known
// benign /proc reader (see benignCredTracers) that should not raise a T1003 alert.
func isBenignCredTracer(comm string) bool {
	if _, ok := benignCredTracers[comm]; ok {
		return true
	}
	if strings.HasPrefix(comm, "runc:") || strings.HasPrefix(comm, "crun:") || strings.HasPrefix(comm, "containerd-shim") {
		return true
	}
	return false
}

// benignCapsetProcs are processes whose whole job involves adjusting their own
// capability set, so they trip the capset tracepoint (T1548.001) on completely
// routine operation. Measured on the verification host: of the first capset
// events after the sensor went live, sshd (privilege separation on every
// connection) and sudo (dropping privileges before exec) accounted for nearly all
// of them, with ip (iproute2 raising CAP_NET_ADMIN for a config change) behind.
//
// setcap is deliberately NOT listed. Its own capset call is uninteresting, but
// leaving it visible costs one event per invocation and the interesting part of a
// setcap run — the file capability it grants — is caught by the separate
// "Linux File Capability Grant (setcap)" process_creation rule, so nothing is
// lost either way.
//
// TRADEOFF: this is a comm allowlist, the same shape (and the same weakness) as
// benignCredTracers — a process renamed to "sshd" could raise capabilities
// unseen by THIS sensor. Accepted for the same reason: without it the signal is
// buried in routine privilege separation. The renamed binary is still visible to
// the process, credential-access and behavioral pipelines.
var benignCapsetProcs = map[string]struct{}{
	"sshd": {}, // privilege separation forks on every connection
	"sudo": {}, // drops privileges before exec'ing the target command
	"ip":   {}, // iproute2 raises CAP_NET_ADMIN for a config change
}

// isBenignCapsetProc reports whether a capset caller is a known benign capability
// manipulator (see benignCapsetProcs). Applies ONLY to capset: kernel-module
// loads (T1547.006) are never filtered by process name, since nothing routine
// should be loading a module.
func isBenignCapsetProc(comm string) bool {
	_, ok := benignCapsetProcs[comm]
	return ok
}

// benignNamespaceProcs are the container-management daemons that create and enter
// namespaces as their core function, so they trip the unshare/setns tracepoints
// (T1611) continuously on any container host. isRuntimeNoiseProc already covers
// the per-container helpers (runc/crun/conmon/containerd-shim); these are the
// long-lived daemons above them, measured firing every ~30-60s on an idle host
// while dockerd polls its containers.
//
// The T1611 signal this sensor exists for — a process breaking OUT of a
// container into the host namespaces — comes from a process that is NOT one of
// these daemons (a shell, an interpreter, nsenter, a dropped binary), so it is
// unaffected. Same comm-allowlist tradeoff as benignCapsetProcs.
var benignNamespaceProcs = map[string]struct{}{
	"dockerd":    {}, // polls/manages container namespaces continuously
	"containerd": {}, // same, one layer down
}

// isBenignNamespaceProc reports whether an unshare/setns caller is a container
// daemon doing routine namespace management (see benignNamespaceProcs).
func isBenignNamespaceProc(comm string) bool {
	_, ok := benignNamespaceProcs[comm]
	return ok
}
