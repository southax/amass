// SPDX-License-Identifier: Apache-2.0

package ndxer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	"golang.org/x/time/rate"
)

const (
	defaultBaseURL = "https://api.ndxer.com"
	hostnamesPath  = "/v1/hostnames/"
	relatedPath    = "/v1/related/"
	// requestTimeout bounds one HTTP request; retries and pending polls get their own.
	requestTimeout = 60 * time.Second
	userAgent      = "amass"
)

// errNotFound is returned by one request when ndxer holds no data for the query (404).
var errNotFound = errors.New("ndxer: no data")

// apiError is a non-2xx answer from the ndxer API, with the error body's fields.
type apiError struct {
	Status    int
	Code      string
	Message   string
	RequestID string
}

func (e *apiError) Error() string {
	if e.Code != "" {
		if e.RequestID != "" {
			return fmt.Sprintf("ndxer API: %s: %s (HTTP %d, request_id=%s)", e.Code, e.Message, e.Status, e.RequestID)
		}
		return fmt.Sprintf("ndxer API: %s: %s (HTTP %d)", e.Code, e.Message, e.Status)
	}
	return fmt.Sprintf("ndxer API: HTTP %d", e.Status)
}

// fatal reports whether the error will repeat for every further request with this key.
func (e *apiError) fatal() bool {
	switch e.Status {
	case http.StatusUnauthorized, http.StatusPaymentRequired, http.StatusForbidden:
		return true
	}
	return false
}

// isFatal reports whether err carries an API status that every further request repeats.
func isFatal(err error) bool {
	var ae *apiError
	return errors.As(err, &ae) && ae.fatal()
}

type errorBody struct {
	Error struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	} `json:"error"`
}

// client talks to the ndxer API for one handler invocation.
type client struct {
	baseURL string
	key     string
	http    *http.Client
	limiter *rate.Limiter       // nil means no rate limit
	sem     et.SessionSemaphone // nil means no session network semaphore
	retry   backoff
}

// redactString removes the API key from s.
func (c *client) redactString(s string) string {
	if c.key == "" {
		return s
	}
	return strings.ReplaceAll(s, c.key, "[redacted]")
}

// redact removes the API key from an error's text.
func (c *client) redact(err error) error {
	if err == nil || c.key == "" || !strings.Contains(err.Error(), c.key) {
		return err
	}
	return errors.New(c.redactString(err.Error()))
}

// get requests path with params and decodes a 200 body into out, following
// the retry and pending policy. It returns errNotFound on 404.
func (c *client) get(ctx context.Context, subject, path string, params url.Values, out any, pendingWaited *time.Duration) error {
	return c.retry.await(ctx, subject, pendingWaited, func() error {
		return c.getOnce(ctx, path, params, out)
	})
}

func (c *client) getOnce(ctx context.Context, path string, params url.Values, out any) error {
	if c.limiter != nil {
		if err := c.limiter.Wait(ctx); err != nil {
			return err
		}
	}

	hc := c.http
	if hc == nil {
		hc = amasshttp.DefaultClient
	}

	if c.sem != nil {
		c.sem.Acquire()
	}
	rctx, cancel := context.WithTimeout(ctx, requestTimeout)
	resp, err := amasshttp.RequestWebPage(rctx, hc, &amasshttp.Request{
		URL: c.baseURL + path + "?" + params.Encode(),
		Header: amasshttp.Header{
			"Authorization": []string{"Bearer " + c.key},
			"Accept":        []string{"application/json"},
			"User-Agent":    []string{userAgent},
		},
	})
	cancel()
	if c.sem != nil {
		c.sem.Release()
	}
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return retryable(c.redact(err), "")
	}

	retryAfter := headerValue(resp.Header, "Retry-After")
	switch resp.StatusCode {
	case http.StatusOK:
		if err := json.Unmarshal([]byte(resp.Body), out); err != nil {
			return retryable(fmt.Errorf("ndxer API: decode response: %w", err), "")
		}
		return nil
	case http.StatusAccepted:
		return &pendingError{retryAfter: retryAfter}
	case http.StatusNotFound:
		return errNotFound
	}

	ae := &apiError{Status: resp.StatusCode}
	var body errorBody
	if json.Unmarshal([]byte(resp.Body), &body) == nil {
		ae.Code, ae.Message, ae.RequestID = body.Error.Code, c.redactString(body.Error.Message), body.Error.RequestID
	}
	if retryableStatus(resp.StatusCode) {
		return retryable(ae, retryAfter)
	}
	return ae
}

func headerValue(h amasshttp.Header, name string) string {
	if v := h[http.CanonicalHeaderKey(name)]; len(v) > 0 {
		return v[0]
	}
	for k, v := range h {
		if strings.EqualFold(k, name) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}
