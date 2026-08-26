//go:build !linux && !windows

package main

// newPlatformTLSSensor is a no-op on platforms without a TLS-handshake capture sensor
// (Linux uses eBPF, Windows a raw-socket sniffer; both provide their own factory).
func newPlatformTLSSensor() tlsSensorStarter {
	return nil
}
