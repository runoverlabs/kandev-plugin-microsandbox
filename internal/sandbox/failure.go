package sandbox

import (
	"errors"

	"kandev-plugin-microsandbox/internal/msbctl"
)

// Failure is a provider error as Kandev receives it: one of its codes, a
// fixed message id under provider.microsandbox, and for rate_limited a delay.
// The host's own message text is never used.
type Failure struct {
	Code              string
	MessageID         string
	RetryAfterSeconds uint32
}

// Fail is a failure with a fixed code.
func Fail(code, messageID string) *Failure { return &Failure{Code: code, MessageID: messageID} }

// FailureOf turns an msbctl or transport error into a failure: msbctl's own
// code when it sent one, unavailable otherwise.
func FailureOf(err error, messageID string) *Failure {
	var e *msbctl.Error
	if errors.As(err, &e) {
		out := Fail(e.Code, messageID)
		if e.Code == msbctl.CodeRateLimited {
			out.RetryAfterSeconds = uint32(e.RetryAfterSeconds)
		}
		return out
	}
	return Fail(msbctl.CodeUnavailable, messageID)
}
