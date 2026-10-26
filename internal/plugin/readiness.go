package plugin

import (
	"context"
	"net/http"

	"kandev-plugin-microsandbox/internal/kandev"
	"kandev-plugin-microsandbox/internal/readiness"
)

// ActionSetupStatus reports the one-time setup of the Kandev server itself.
const ActionSetupStatus = "setup.status"

// readinessAction serves setup.status.
type readinessAction struct{ report readiness.Report }

func (a *readinessAction) routes() map[string]actionFunc {
	return map[string]actionFunc{ActionSetupStatus: a.status}
}

func (a *readinessAction) status(ctx context.Context, body []byte) kandev.Response {
	if err := kandev.Decode(body, &struct{}{}); err != nil {
		return kandev.Fail(http.StatusUnprocessableEntity, "this action takes no fields")
	}
	items, ready, err := a.report.Items(ctx)
	if err != nil {
		return kandev.Internal(ActionSetupStatus, "the plugin's settings", err)
	}
	return kandev.OK(map[string]any{"ready": ready, "items": items})
}
