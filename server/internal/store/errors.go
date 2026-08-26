package store

import "errors"

// ErrNotFound is a shared sentinel returned by store methods when no row matches
// the requested id. Handlers map it to HTTP 404 via errors.Is, distinguishing
// "the caller asked for something that does not exist" from an unexpected DB
// fault (500).
var ErrNotFound = errors.New("not found")
