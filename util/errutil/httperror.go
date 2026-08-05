package errutil

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"

	"github.com/target/goalert/ctxlock"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/util/log"
	"github.com/target/goalert/util/sqlutil"
	"github.com/target/goalert/validation"
)

func isCancel(err error) bool {
	if errors.Is(err, context.Canceled) {
		return true
	}
	if errors.Is(err, sql.ErrTxDone) {
		return true
	}

	// 57014 = query_canceled
	// https://www.postgresql.org/docs/9.6/static/errcodes-appendix.html
	if e := sqlutil.MapError(err); e != nil && e.Code == "57014" {
		return true
	}

	return false
}

func unwrapAll(err error) error {
	for {
		next := errors.Unwrap(err)
		if next == nil {
			break
		}
		err = next
	}
	return err
}

// HTTPError will respond in a standard way when err != nil. If
// err is nil, false is returned, true otherwise.
func HTTPError(ctx context.Context, w http.ResponseWriter, err error) bool {
	return httpError(ctx, w, err, http.StatusInternalServerError)
}

// HTTPErrorRetry behaves like HTTPError, except an unexpected server-side error
// responds 503 rather than 500. Client errors are unchanged: those are permanent
// and must not be retried.
//
// This is for webhook ingress, where the status code is the only back-channel to
// the sender's retry logic and a dropped delivery is a dropped page. The two
// providers disagree about 500: SNS retries all 5xx and 429, while Azure Monitor
// retries only 408, 429, 503 and 504 -- so a 500 during a database outage loses
// the alert with zero retries. 503 is retried by both.
func HTTPErrorRetry(ctx context.Context, w http.ResponseWriter, err error) bool {
	return httpError(ctx, w, err, http.StatusServiceUnavailable)
}

// httpError maps err onto a response. unexpectedCode is used for errors that
// match no known classification.
func httpError(ctx context.Context, w http.ResponseWriter, err error, unexpectedCode int) bool {
	if err == nil {
		return false
	}

	err = MapDBError(err)
	var bodyLimit *http.MaxBytesError
	switch {
	case errors.As(err, &bodyLimit):
		http.Error(w, fmt.Sprintf("%s (max body: %v bytes)", http.StatusText(http.StatusRequestEntityTooLarge), bodyLimit.Limit), http.StatusRequestEntityTooLarge)
	case errors.Is(err, ctxlock.ErrQueueFull):
		// The queue is full meaning we have over 100 requests from the
		// same source.
		//
		// Because of the way the lock works, we can guarantee that
		// we will process one request at a time (per source), but we
		// may have to wait for a previous request to finish before we
		// can start processing the next one.
		//
		// This means only concurrent requests (per process/per key) have
		// the possibility to be rate limited, and not sequential requests,
		// even in the worst case scenario.
		http.Error(w, "Too many concurrent requests for this key or session", http.StatusTooManyRequests)
	case errors.Is(err, ctxlock.ErrTimeout):
		// Same status as ErrQueueFull above -- this is back-pressure, not a slow
		// client, so 408 is wrong: it means the *client* failed to send a complete
		// request in time (RFC 9110 15.5.9), the opposite of what happened, and
		// webhook senders treat the two very differently -- Amazon SNS retries 429
		// and all 5xx but treats 408 as a permanent failure, so 408 here silently
		// discards the delivery instead of backing off. This is an intentional,
		// application-wide change to every HTTPError caller, not scoped to ingress;
		// the body text differs from ErrQueueFull's so a client can still tell
		// "rejected immediately, queue full" from "waited and timed out" even
		// though the status code is now the same for both.
		http.Error(w, "Too many concurrent requests for this key or session; timed out waiting", http.StatusTooManyRequests)
	case isCancel(err):
		// Client disconnected, send 499 back so logs reflect that this
		// was a client-side problem.
		http.Error(w, "Client disconnected.", 499)
	case permission.IsUnauthorized(err):
		http.Error(w, unwrapAll(err).Error(), http.StatusUnauthorized)
	case permission.IsPermissionError(err):
		http.Error(w, unwrapAll(err).Error(), http.StatusForbidden)
	case validation.IsClientError(err):
		http.Error(w, unwrapAll(err).Error(), http.StatusBadRequest)
	case IsLimitError(err):
		http.Error(w, unwrapAll(err).Error(), http.StatusConflict)
	case errors.Is(err, context.DeadlineExceeded):
		// Timeout
		http.Error(w, http.StatusText(http.StatusGatewayTimeout), http.StatusGatewayTimeout)
	default:
		// For all other unexpected errors, log the error and send unexpectedCode.
		log.Log(ctx, err)
		http.Error(w, http.StatusText(unexpectedCode), unexpectedCode)
	}

	return true
}
