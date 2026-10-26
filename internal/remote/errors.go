package remote

import "errors"

var (
	// ErrHostKeyMismatch means the host presented a key other than the
	// pinned one. It is never retried and never re-pinned automatically.
	ErrHostKeyMismatch = errors.New("host key does not match the pinned key")
	// ErrNotAuthorized means the host refused the login: the plugin's key,
	// or an operator's admin login.
	ErrNotAuthorized = errors.New("host refused the ssh login")
	// ErrAdminAuth means an operator's admin login could not be used: an
	// unreadable key, or a key that needs a passphrase that was not given
	// or does not fit.
	ErrAdminAuth = errors.New("the admin login is unusable")
)
