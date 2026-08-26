//go:build !unix

package backup

// oNoFollow is a no-op on platforms without O_NOFOLLOW (e.g. Windows); the explicit
// Lstat symlink check in openForRead/Restore still guards against symlink redirection.
const oNoFollow = 0
