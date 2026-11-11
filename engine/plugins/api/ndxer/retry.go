// SPDX-License-Identifier: Apache-2.0

package ndxer

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strconv"
	"time"
)

// backoff is the retry policy the ndxer API documentation asks clients to
// follow: on 429 wait Retry-After, on 502/503/504 back off exponentially with
// jitter, and never retry another 4xx. Transport errors and an undecodable
// 200 body are retried too. The zero value is usable: one attempt, real sleep.
type backoff struct {
	maxAttempts int                                              // total attempts including the first; <1 means 1
	base        time.Duration                                    // first backoff step; 0 means 1s
	maxWait     time.Duration                                    // cap on any single wait; 0 means 60s
	sleep       func(ctx context.Context, d time.Duration) error // nil means sleepContext; tests replace it
	jitter      func() float64                                   // returns [0,1); nil means math/rand/v2 Float64
}

// defaultBackoff allows up to five attempts, doubling from one second,
// capped at a sixty-second wait.
func defaultBackoff() backoff {
	return backoff{
		maxAttempts: 5,
		base:        time.Second,
		maxWait:     60 * time.Second,
		sleep:       sleepContext,
		jitter:      rand.Float64,
	}
}

// sleepContext waits d, or returns ctx.Err() as soon as ctx is done.
func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// retryableStatus reports whether the status is transient: 429, 502, 503 and 504 only.
func retryableStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// retryableError marks an error as worth another attempt.
type retryableError struct {
	err        error
	retryAfter string
}

func (r *retryableError) Error() string { return r.err.Error() }
func (r *retryableError) Unwrap() error { return r.err }

// retryable marks err as worth another attempt. retryAfter is the response's
// Retry-After header value, "" when there is none. retryable(nil, x) is nil.
func retryable(err error, retryAfter string) error {
	if err == nil {
		return nil
	}
	return &retryableError{err: err, retryAfter: retryAfter}
}

// parseRetryAfter interprets a Retry-After header value: a positive number
// of seconds, or an HTTP date in the future. ok is false for anything else.
func parseRetryAfter(v string) (time.Duration, bool) {
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second, true
	}
	if ts, err := http.ParseTime(v); err == nil {
		if wait := time.Until(ts); wait > 0 {
			return wait, true
		}
	}
	return 0, false
}

// delay is the wait after the attempt numbered attempt (1-based) failed.
// A usable Retry-After wins; otherwise the step is base doubled (attempt-1)
// times, halved, plus a jittered half-step. The result is capped at maxWait.
func (b backoff) delay(attempt int, retryAfter string) time.Duration {
	base := b.base
	if base <= 0 {
		base = time.Second
	}
	maxWait := b.maxWait
	if maxWait <= 0 {
		maxWait = 60 * time.Second
	}
	jitter := b.jitter
	if jitter == nil {
		jitter = rand.Float64
	}

	if d, ok := parseRetryAfter(retryAfter); ok {
		return min(d, maxWait)
	}

	step := maxWait
	if n := max(attempt-1, 0); n < 30 {
		if shifted := base << n; shifted > 0 && shifted < maxWait {
			step = shifted
		}
	}
	d := step/2 + time.Duration(jitter()*float64(step/2))
	return min(d, maxWait)
}

// retry calls try until it returns nil, returns an error not marked
// retryable, or maxAttempts attempts have been used. The final retryable
// error is wrapped with the number of attempts made.
func (b backoff) retry(ctx context.Context, try func() error) error {
	attempts := max(b.maxAttempts, 1)
	sleep := b.sleep
	if sleep == nil {
		sleep = sleepContext
	}

	for attempt := 1; ; attempt++ {
		err := try()
		var re *retryableError
		if err == nil || !errors.As(err, &re) {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if attempt >= attempts {
			return fmt.Errorf("%w (gave up after %d attempts)", re.err, attempts)
		}
		if err := sleep(ctx, b.delay(attempt, re.retryAfter)); err != nil {
			return err
		}
	}
}

// pendingWait is the longest the plugin waits, per domain and endpoint, for
// ndxer to finish looking up a domain it has not seen before (HTTP 202).
const pendingWait = 120 * time.Second

// pendingDefaultWait is the wait between polls when a 202 has no usable Retry-After.
const pendingDefaultWait = 5 * time.Second

// pendingMaxWait caps one wait between polls.
const pendingMaxWait = 30 * time.Second

// pendingError is what one attempt returns when ndxer answered 202.
type pendingError struct{ retryAfter string }

func (e *pendingError) Error() string { return "ndxer: lookup still pending" }

// pendingDelay is the wait before polling again.
func pendingDelay(retryAfter string) time.Duration {
	d, ok := parseRetryAfter(retryAfter)
	if !ok {
		d = pendingDefaultWait
	}
	return min(d, pendingMaxWait)
}

// await runs b.retry and, while its result is a *pendingError, waits and
// runs it again. Each retry call has its own attempt budget, so polls of a
// pending lookup never use up the error retries. *waited is the pending
// wait already spent for this subject, shared across its pages.
func (b backoff) await(ctx context.Context, subject string, waited *time.Duration, try func() error) error {
	if waited == nil {
		local := time.Duration(0)
		waited = &local
	}
	sleep := b.sleep
	if sleep == nil {
		sleep = sleepContext
	}
	for {
		err := b.retry(ctx, try)
		var pe *pendingError
		if err == nil || !errors.As(err, &pe) {
			return err
		}
		remaining := pendingWait - *waited
		if remaining <= 0 {
			return fmt.Errorf("ndxer is still looking up %s; run again shortly", subject)
		}
		d := min(pendingDelay(pe.retryAfter), remaining)
		if err := sleep(ctx, d); err != nil {
			return err
		}
		*waited += d
	}
}
