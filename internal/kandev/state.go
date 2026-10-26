package kandev

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/kandev/kandev/pkg/pluginsdk"
)

// Plugin-wide Host state is scope "instance" with an empty scope id: sandbox
// hosts, the egress policy and the secrets belong to no one workspace. (The
// design says "scope plugin"; Kandev has no such scope.)
const stateScope = "instance"

// ErrUnreadable means a stored document does not decode into its shape.
var ErrUnreadable = errors.New("stored document is unreadable")

// LoadDocument reads the plugin-wide document under key into into. found is
// false when nothing is stored. Host state round-trips through a protobuf
// Struct, so numbers come back as float64: the value is decoded by
// re-encoding it rather than by asserting Go types.
func LoadDocument(ctx context.Context, host pluginsdk.Host, key string, into any) (found bool, err error) {
	value, found, err := host.GetState(ctx, stateScope, "", key)
	if err != nil || !found {
		return false, err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return true, ErrUnreadable
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return true, ErrUnreadable
	}
	return true, nil
}

// SaveDocument replaces the plugin-wide document under key with value, which
// must encode as a JSON object.
func SaveDocument(ctx context.Context, host pluginsdk.Host, key string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		return err
	}
	return host.SetState(ctx, stateScope, "", key, object)
}
