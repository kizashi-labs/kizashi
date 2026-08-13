//go:build darwin && esf && cgo

package buildvariant

// The macOS Endpoint Security build (edr-agent-darwin-<arch>-esf): process
// telemetry comes from ESF rather than ps polling, and with `-tags prevention`
// plus Apple's approved entitlement, AUTH_EXEC prevention is compiled in.
//
// The `cgo` term matters: the ESF collector is a cgo file, so with
// CGO_ENABLED=0 the esf tag alone produces a binary that is byte-for-byte the
// polling build. Reporting "esf" there would make the agent ask the server for
// an ESF binary it is not actually running.
const name = "esf"
