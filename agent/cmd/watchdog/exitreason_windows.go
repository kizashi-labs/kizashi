//go:build windows

package main

// classifyExit always reports "no signal" on Windows.
//
// Windows has no signals. TerminateProcess sets whatever exit code the caller
// chose — `taskkill /F` uses 1 — which is indistinguishable from an ordinary
// crash that exits 1. Guessing here would produce a confident attribution that is
// wrong about half the time, so instead the caller reports the exit code and says
// in the finding's reason that kill and crash cannot be told apart on this
// platform. The detection rules score an unattributed death lower than a
// signalled one for exactly that reason.
//
// Telling them apart on Windows needs the kernel layer (the prevention driver's
// ObRegisterCallbacks path, which sees the handle open), not more guesswork here.
func classifyExit(error) (int, bool) { return 0, false }
