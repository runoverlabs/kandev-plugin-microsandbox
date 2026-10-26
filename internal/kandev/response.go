package kandev

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/kandev/kandev/pkg/pluginsdk"
)

// Response is an action's reply before encoding: a status and a JSON body.
type Response struct {
	Status int
	Body   any
}

// OK is a 200 with body.
func OK(body any) Response { return Response{http.StatusOK, body} }

// Fail is an expected failure: a fixed message under an explicit status.
// Kandev masks a Go error from an action as a 503, so anything the operator
// can act on is returned this way.
func Fail(status int, message string) Response {
	return Response{status, map[string]any{"error": message}}
}

// Internal logs the cause and returns a fixed message naming what could not
// be read or saved: Host errors can carry details that do not belong in a
// browser response. A Host that is not connected yet is a 503 to retry.
func Internal(action, what string, err error) Response {
	if errors.Is(err, ErrNoHost) {
		return Fail(http.StatusServiceUnavailable, "the plugin is still starting; try again")
	}
	log.Printf("%s: %v", action, err)
	return Fail(http.StatusInternalServerError, what+" could not be read or saved")
}

// Encode is the response Kandev gets.
func (r Response) Encode() *pluginsdk.PluginActionResponse {
	body, err := json.Marshal(r.Body)
	if err != nil {
		r.Status, body = http.StatusInternalServerError, []byte(`{"error":"response encoding failed"}`)
	}
	return &pluginsdk.PluginActionResponse{
		Status: r.Status, Body: body, Headers: map[string]string{"Content-Type": "application/json"},
	}
}

// Decode reads an action body strictly: an unknown field is an error, and an
// empty body is an empty object.
func Decode(body []byte, into any) error {
	if len(strings.TrimSpace(string(body))) == 0 {
		body = []byte("{}")
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	return decoder.Decode(into)
}
