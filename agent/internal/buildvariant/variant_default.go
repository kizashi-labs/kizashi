//go:build !(linux && ebpf && prevention) && !(darwin && esf && cgo)

package buildvariant

// The default build: OS-native telemetry only, with no in-kernel enforcement
// and no ESF client compiled in. Every tag combination that is not one of the
// published variants lands here, so a new variant means adding its file *and*
// excluding it from this constraint — otherwise the package fails to build with
// a duplicate `name`, which is the intended way to notice.
const name = ""
