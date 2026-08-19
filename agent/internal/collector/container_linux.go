//go:build linux

package collector

import (
	"os"
	"strconv"
)

// hostNetNS is PID 1's network namespace, read once. A container that shares it
// was started with --network=host and has no network isolation at all.
//
// Read lazily rather than at init: on a host where /proc/1/ns/net is not
// readable (an unprivileged agent) every comparison simply fails to match,
// which reports "not host network" — the conservative answer, and better than
// refusing to collect the container ID as well.
var hostNetNS = func() string {
	target, err := os.Readlink("/proc/1/ns/net")
	if err != nil {
		return ""
	}
	return target
}()

// containerContextOf reads what /proc knows about a process's containment.
//
// Every read is best-effort and independent: a process that exits between the
// cgroup read and the status read still yields its container ID rather than
// nothing. The process may also simply not be in a container, which is the
// common case and costs one failed open.
func containerContextOf(pid uint32) ContainerContext {
	base := "/proc/" + strconv.FormatUint(uint64(pid), 10)

	cgroup, err := os.ReadFile(base + "/cgroup")
	if err != nil {
		return ContainerContext{}
	}
	id := containerIDFromCgroup(string(cgroup))
	if id == "" {
		return ContainerContext{}
	}
	ctx := ContainerContext{ID: id}

	if status, err := os.ReadFile(base + "/status"); err == nil {
		ctx.Privileged = capEffIsPrivileged(capEffFromStatus(string(status)))
	}

	if hostNetNS != "" {
		if target, err := os.Readlink(base + "/ns/net"); err == nil {
			ctx.HostNetwork = target == hostNetNS
		}
	}

	return ctx
}
