//go:build linux && ebpf && prevention

package buildvariant

// The enforcing Linux build (edr-agent-linux-amd64-ebpf): eBPF LSM exec
// prevention, tamper protection and credential-access auditing are compiled in.
const name = "ebpf"
