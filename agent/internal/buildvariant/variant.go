// Package buildvariant reports which build variant of the agent binary is
// running, so the agent can ask the server to update it to the *same* variant.
//
// Two Linux agent binaries are published from this repo:
//
//	edr-agent-linux-amd64        -tags ebpf              telemetry only
//	edr-agent-linux-amd64-ebpf   -tags "ebpf prevention" telemetry + LSM enforcement
//
// The prevention hooks (exec prevention, tamper protection, credential-access
// auditing) exist only in the second. Self-update used to be variant-blind and
// always fetched the first, so an endpoint deliberately installed with
// enforcement would silently drop to the telemetry-only build at its next
// update — losing prevention with no error and no alert. Name is what closes
// that hole: it travels on the update check and on the download request.
package buildvariant

// Name is the variant identifier for this build: "" for the default
// (telemetry-only) build, "ebpf" for the LSM-enforcing Linux build. It is a
// build-tag-selected constant rather than a runtime probe on purpose — what
// matters for update selection is which code was compiled in, not whether the
// current kernel happens to let it load.
const Name = name

// Suffix is Name rendered as a filename suffix ("" or "-ebpf"), matching the
// published binary names.
func Suffix() string {
	if name == "" {
		return ""
	}
	return "-" + name
}
