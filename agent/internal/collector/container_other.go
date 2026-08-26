//go:build !linux

package collector

// containerContextOf reports no containment on platforms where the agent cannot
// determine it.
//
// Containers are a Linux kernel construct. Windows and macOS run them inside a
// Linux VM (Docker Desktop, WSL2), so a process the agent sees on the host is by
// definition not the containerised one — the agent inside that VM is what would
// observe it. Returning a zero value here is the accurate answer, not a stub.
func containerContextOf(pid uint32) ContainerContext {
	return ContainerContext{}
}
