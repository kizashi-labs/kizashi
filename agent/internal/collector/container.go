package collector

import "strings"

// Container context for a process, derived on the endpoint.
//
// server/internal/cloudruntime read container_id, container_name, image_name,
// privileged and host_network off process events, and the agent collected none
// of them. So privileged-container detection, host-network detection and the
// "containers monitored" figure were structurally zero, and the crypto-miner and
// container-escape rules — which do work on an ordinary process event — had no
// way to say WHICH container a hit came from.
//
// The obvious way to get this is to talk to the container runtime: mount the
// Docker socket, or dial containerd, or ask the kubelet. That is a large
// dependency on a moving target (Docker, containerd, CRI-O, Podman, each with
// its own API and its own socket path and its own permissions), and mounting a
// runtime socket into an agent is itself a privilege the agent should not want.
//
// Almost all of it is in /proc already, because containment is a kernel
// property rather than a runtime one:
//
//	container id   /proc/<pid>/cgroup       the cgroup path names the container
//	privileged     /proc/<pid>/status       CapEff — a privileged container's
//	                                        process keeps the full capability set
//	host_network   /proc/<pid>/ns/net       identical to PID 1's when the
//	                                        container shares the host's netns
//
// So three of the five need no runtime API, no socket, and no new privilege.
//
// container_name and image_name are NOT derivable this way — they are runtime
// bookkeeping, not kernel state — and are deliberately left uncollected rather
// than guessed at from the cgroup path, which encodes them only sometimes and
// differently per runtime. They stay in the server's known-dead list, which
// names the runtime client as what they would need.

// ContainerContext is what the endpoint could determine about a process's
// containment. A zero value means "not in a container, or could not tell",
// which is the same thing from the outside and is reported as absence rather
// than as false.
type ContainerContext struct {
	// ID is the container's ID as the kernel knows it: the 64-hex-character
	// identifier embedded in the cgroup path. "" when the process is not in a
	// container.
	ID string
	// Privileged reports that the process holds the full capability set, which
	// is what `docker run --privileged` produces. Only meaningful when ID != "".
	Privileged bool
	// HostNetwork reports that the process shares PID 1's network namespace —
	// `--network=host`, which removes the network isolation the container
	// otherwise has. Only meaningful when ID != "".
	HostNetwork bool
}

// InContainer reports whether the process was found to be in a container.
func (c ContainerContext) InContainer() bool { return c.ID != "" }

// containerIDFromCgroup extracts a container ID from the contents of
// /proc/<pid>/cgroup.
//
// The formats differ per runtime and per cgroup version, and all of them end
// the path with the ID:
//
//	docker      12:devices:/docker/<64 hex>
//	containerd  0::/system.slice/containerd.service/kubepods-...:cri-containerd:<64 hex>
//	kubepods    0::/kubepods.slice/kubepods-burstable.slice/...-<64 hex>.scope
//	podman      0::/machine.slice/libpod-<64 hex>.scope
//
// Rather than model each, take the last path segment, strip the decorations
// they add around the ID, and accept it only if what remains is a 64-character
// hex string. A hostname or a systemd unit name does not survive that test,
// which is what keeps this from labelling ordinary host processes as contained.
func containerIDFromCgroup(cgroupFile string) string {
	for _, line := range strings.Split(cgroupFile, "\n") {
		// Each line is "hierarchy:controllers:path".
		parts := strings.SplitN(strings.TrimSpace(line), ":", 3)
		if len(parts) != 3 {
			continue
		}
		path := parts[2]
		if path == "" || path == "/" {
			continue
		}
		seg := path
		if i := strings.LastIndexByte(seg, '/'); i >= 0 {
			seg = seg[i+1:]
		}
		seg = strings.TrimSuffix(seg, ".scope")
		seg = strings.TrimSuffix(seg, ".service")
		// Strip the runtime's prefix, whichever it is. Everything after the last
		// separator is the candidate.
		for _, sep := range []string{"cri-containerd-", "cri-containerd:", "libpod-", "docker-", "crio-"} {
			if i := strings.LastIndex(seg, sep); i >= 0 {
				seg = seg[i+len(sep):]
			}
		}
		if isHex64(seg) {
			return seg
		}
	}
	return ""
}

// isHex64 reports whether s is exactly 64 hexadecimal characters — the shape of
// every container ID the runtimes above embed.
func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// fullCapabilitySet is CAP_LAST_CAP's worth of bits set. A privileged container
// keeps every capability; an ordinary one is dropped to a small subset (Docker's
// default is 14 of them), so "holds essentially everything" separates the two
// cleanly without hard-coding a kernel version's exact CAP_LAST_CAP.
//
// The threshold is deliberately a count rather than an exact mask: CAP_LAST_CAP
// grows with the kernel (37 on 4.x, 40 on 5.8+, 41 on 6.x), so an equality test
// against one kernel's full mask silently stops matching on the next.
const privilegedCapCount = 30

// capEffIsPrivileged reports whether an effective-capability mask, as the hex
// string /proc/<pid>/status prints after "CapEff:", represents a privileged
// container.
func capEffIsPrivileged(capEffHex string) bool {
	capEffHex = strings.TrimSpace(capEffHex)
	if capEffHex == "" {
		return false
	}
	var set int
	for i := 0; i < len(capEffHex); i++ {
		v := hexVal(capEffHex[i])
		if v < 0 {
			return false
		}
		for b := 0; b < 4; b++ {
			if v&(1<<b) != 0 {
				set++
			}
		}
	}
	return set >= privilegedCapCount
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// capEffFromStatus pulls the CapEff value out of /proc/<pid>/status.
func capEffFromStatus(status string) string {
	for _, line := range strings.Split(status, "\n") {
		if rest, ok := strings.CutPrefix(line, "CapEff:"); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}
