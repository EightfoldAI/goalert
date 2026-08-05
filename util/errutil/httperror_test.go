package errutil

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/ctxlock"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/validation"
)

func TestHTTPError_Nil(t *testing.T) {
	rec := httptest.NewRecorder()
	assert.False(t, HTTPError(context.Background(), rec, nil))
	assert.Equal(t, 200, rec.Code, "no response should be written for a nil error")
}

// TestHTTPError_QueueFullAndTimeoutBothAnswer429 pins the app-wide 408->429
// change: ctxlock.ErrTimeout is back-pressure, the same condition as
// ErrQueueFull, not a slow client, so both must be retryable (429) rather than
// 408 -- which SNS treats as a permanent failure. The bodies must still differ
// so a caller can tell "queue full" from "timed out waiting" apart even though
// the status code no longer does.
func TestHTTPError_QueueFullAndTimeoutBothAnswer429(t *testing.T) {
	recQueueFull := httptest.NewRecorder()
	assert.True(t, HTTPError(context.Background(), recQueueFull, ctxlock.ErrQueueFull))
	assert.Equal(t, http.StatusTooManyRequests, recQueueFull.Code)

	recTimeout := httptest.NewRecorder()
	assert.True(t, HTTPError(context.Background(), recTimeout, ctxlock.ErrTimeout))
	assert.Equal(t, http.StatusTooManyRequests, recTimeout.Code)

	assert.NotEqual(t, recQueueFull.Body.String(), recTimeout.Body.String(),
		"the two conditions must remain distinguishable by body even though the status code is now shared")
}

func TestHTTPError_MaxBytesErrorIs413(t *testing.T) {
	rec := httptest.NewRecorder()
	err := &http.MaxBytesError{Limit: 1024}
	assert.True(t, HTTPError(context.Background(), rec, err))
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	assert.Contains(t, rec.Body.String(), "1024")
}

func TestHTTPError_PermissionErrors(t *testing.T) {
	rec := httptest.NewRecorder()
	assert.True(t, HTTPError(context.Background(), rec, permission.Unauthorized()))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	rec = httptest.NewRecorder()
	assert.True(t, HTTPError(context.Background(), rec, permission.NewAccessDenied("nope")))
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestHTTPError_ValidationErrorIs400(t *testing.T) {
	rec := httptest.NewRecorder()
	assert.True(t, HTTPError(context.Background(), rec, validation.NewFieldError("Foo", "bad")))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHTTPError_DeadlineExceededIs504(t *testing.T) {
	rec := httptest.NewRecorder()
	assert.True(t, HTTPError(context.Background(), rec, context.DeadlineExceeded))
	assert.Equal(t, http.StatusGatewayTimeout, rec.Code)
}

// TestHTTPError_UnexpectedErrorIs500 and TestHTTPErrorRetry_UnexpectedErrorIs503
// are the one behavioral difference between the two functions: an unclassified
// error is the only branch HTTPErrorRetry changes.
func TestHTTPError_UnexpectedErrorIs500(t *testing.T) {
	rec := httptest.NewRecorder()
	assert.True(t, HTTPError(context.Background(), rec, errors.New("boom")))
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestHTTPErrorRetry_UnexpectedErrorIs503(t *testing.T) {
	rec := httptest.NewRecorder()
	assert.True(t, HTTPErrorRetry(context.Background(), rec, errors.New("boom")))
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// TestHTTPErrorRetry_ClientErrorsUnchanged pins that HTTPErrorRetry only widens
// the unexpected-error branch -- every classified client error (permanent, by
// definition) must still answer exactly what HTTPError would, so a caller
// switching from HTTPError to HTTPErrorRetry cannot accidentally make SNS or
// Azure retry something that will never succeed.
func TestHTTPErrorRetry_ClientErrorsUnchanged(t *testing.T) {
	cases := []struct {
		name string
		err  error
		code int
	}{
		{"max bytes", &http.MaxBytesError{Limit: 10}, http.StatusRequestEntityTooLarge},
		{"queue full", ctxlock.ErrQueueFull, http.StatusTooManyRequests},
		{"ctxlock timeout", ctxlock.ErrTimeout, http.StatusTooManyRequests},
		{"unauthorized", permission.Unauthorized(), http.StatusUnauthorized},
		{"access denied", permission.NewAccessDenied("nope"), http.StatusForbidden},
		{"validation", validation.NewFieldError("Foo", "bad"), http.StatusBadRequest},
		{"deadline exceeded", context.DeadlineExceeded, http.StatusGatewayTimeout},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			recA := httptest.NewRecorder()
			require.True(t, HTTPError(context.Background(), recA, tt.err))

			recB := httptest.NewRecorder()
			require.True(t, HTTPErrorRetry(context.Background(), recB, tt.err))

			assert.Equal(t, tt.code, recA.Code)
			assert.Equal(t, recA.Code, recB.Code, "HTTPErrorRetry must not change a classified client error's status")
			assert.Equal(t, recA.Body.String(), recB.Body.String(), "HTTPErrorRetry must not change a classified client error's body")
		})
	}
}
