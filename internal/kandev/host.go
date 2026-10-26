// Package kandev is how every layer reaches Kandev: the late-bound Host, the
// plugin-wide state documents, and the JSON responses an action returns. It
// knows nothing about sandbox hosts.
package kandev

import (
	"errors"

	"github.com/kandev/kandev/pkg/pluginsdk"
)

// ErrNoHost means the Host broker connection is not up yet. It is transient:
// Kandev dials the broker after the plugin starts serving.
var ErrNoHost = errors.New("kandev host is not connected yet")

// Provider defers Host resolution to call time. The Host is injected from a
// background goroutine after construction, so nothing may capture it earlier.
type Provider func() pluginsdk.Host

// Get returns the Host, or ErrNoHost while it has not arrived.
func (p Provider) Get() (pluginsdk.Host, error) {
	if p == nil {
		return nil, ErrNoHost
	}
	if host := p(); host != nil {
		return host, nil
	}
	return nil, ErrNoHost
}
