// Package tamper carries the agent's self-protection findings: something tried to
// stop, replace, or reconfigure the EDR agent itself.
//
// The package deliberately does not import the generated proto types. Both the
// agent and the watchdog produce tamper findings, and the watchdog is a
// deliberately thin supervisor — pulling the proto (and with it gRPC) into it to
// share a struct would be the wrong trade. Encoding to the wire format lives in
// internal/collector, which the agent already links.
package tamper

// Tamper types, carried in Payload.TamperType. These are what detection rules
// select on, so they are part of the wire contract — renaming one silently stops
// the corresponding rule from matching.
const (
	// TypeAgentKilled — the agent process was terminated by a signal. Unambiguous
	// external interference: nothing inside the agent sends itself SIGKILL.
	// Reported by the watchdog through the spool.
	TypeAgentKilled = "agent_killed"
	// TypeAgentExited — the agent exited without a signal and without the watchdog
	// asking it to. That is either a crash or a Windows TerminateProcess, which
	// cannot be told apart from the exit code (see exitreason_windows.go).
	//
	// It is a separate type rather than a field on agent_killed so rules can score
	// the two differently with a plain string match. Encoding the distinction as a
	// signal number would push it onto Sigma numeric matching, where the JSON
	// round-trip turns ints into float64 and a rule that looks correct quietly
	// stops matching.
	TypeAgentExited = "agent_exited"
	// TypeBinaryModified — the on-disk agent binary no longer matches the hash
	// recorded on first run.
	TypeBinaryModified = "binary_modified"
	// TypeConfigModified — the agent config file changed while the agent was
	// running.
	TypeConfigModified = "config_modified"
	// TypeWatchdogMissing — the agent is running but its supervising watchdog is
	// gone. Killing the watchdog first is the standard prelude to killing the
	// agent without it coming back.
	TypeWatchdogMissing = "watchdog_missing"
	// TypeKillAttempt — a kill/terminate was attempted against a protected PID.
	// Only observable with the kernel layer (Linux eBPF LSM task_kill).
	TypeKillAttempt = "kill_attempt"
	// TypeHandleOpenAttempt — a handle carrying terminate/inject rights was opened
	// against a protected PID (Windows ObRegisterCallbacks).
	TypeHandleOpenAttempt = "handle_open_attempt"
)

// Protected components, carried in Payload.Component.
const (
	ComponentAgent    = "edr-agent"
	ComponentWatchdog = "edr-watchdog"
	ComponentConfig   = "config"
	ComponentBinary   = "binary"
)

// Payload is the JSON body of a tamper event.
//
// Field names deliberately reuse the vocabulary already registered as
// field-supported for credential_access / memory (source_pid, source_image,
// target_pid, access_mask, enforced, reason) so most of this payload resolves in
// both Sigma engines without new aliases. Only tamper_type, component, signal,
// expected_hash and actual_hash are new.
//
// Enforced is not omitempty: false is the load-bearing value. It means the tamper
// was observed but could not be denied — exactly the case an analyst needs to
// see. Omitting it would make "not denied" indistinguishable from "field absent".
type Payload struct {
	TamperType string `json:"tamper_type"`
	Component  string `json:"component"`
	Enforced   bool   `json:"enforced"`

	Path        string `json:"path,omitempty"`
	TargetPID   int    `json:"target_pid,omitempty"`
	SourcePID   int    `json:"source_pid,omitempty"`
	SourceImage string `json:"source_image,omitempty"`
	Username    string `json:"username,omitempty"`
	Signal      int    `json:"signal,omitempty"`
	AccessMask  string `json:"access_mask,omitempty"`
	ExitCode    int    `json:"exit_code,omitempty"`

	ExpectedHash string `json:"expected_hash,omitempty"`
	ActualHash   string `json:"actual_hash,omitempty"`
	Reason       string `json:"reason,omitempty"`
}

// New constructs the minimal payload for a tamper finding. Optional attribution
// (who did it, which signal, which hashes) is added by the With* helpers so each
// call site sets only what it can actually observe. A zero PID or an empty image
// is worse than an absent field: rules selecting on it would match the
// placeholder.
func New(tamperType, component string, enforced bool) Payload {
	return Payload{
		TamperType: tamperType,
		Component:  component,
		Enforced:   enforced,
	}
}

// WithPath records the file the finding concerns (binary or config path).
func (p Payload) WithPath(path string) Payload {
	p.Path = path
	return p
}

// WithTarget records the PID of the protected process that was targeted.
func (p Payload) WithTarget(pid int) Payload {
	p.TargetPID = pid
	return p
}

// WithSource records the attributed originator. Call sites that cannot attribute
// must not call this — the watchdog only sees that its child died, not who killed
// it.
func (p Payload) WithSource(pid int, image, username string) Payload {
	p.SourcePID = pid
	p.SourceImage = image
	p.Username = username
	return p
}

// WithSignal records the POSIX signal that terminated the process.
func (p Payload) WithSignal(sig int) Payload {
	p.Signal = sig
	return p
}

// WithExitCode records the process exit code.
func (p Payload) WithExitCode(code int) Payload {
	p.ExitCode = code
	return p
}

// WithAccessMask records the Windows desired-access mask of the opened handle.
func (p Payload) WithAccessMask(mask string) Payload {
	p.AccessMask = mask
	return p
}

// WithHashes records the expected/actual digests behind an integrity mismatch.
func (p Payload) WithHashes(expected, actual string) Payload {
	p.ExpectedHash = expected
	p.ActualHash = actual
	return p
}

// WithReason records a short human-readable qualifier.
func (p Payload) WithReason(reason string) Payload {
	p.Reason = reason
	return p
}
