// SPDX-License-Identifier: Apache-2.0

package ndxer

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// hostnamesPageLimit asks for the largest page any plan allows; the API
// clamps it to the plan's page size, so fewer pages (and units) are spent.
const hostnamesPageLimit = 1000

type hostnamesPage struct {
	Meta struct {
		NextCursor      *string `json:"next_cursor"`
		UnitsCharged    int     `json:"units_charged"`
		UnitsToComplete *int    `json:"units_to_complete"`
		UnitsRemaining  *int    `json:"units_remaining"`
	} `json:"meta"`
	Matches []struct {
		Name string `json:"name"`
	} `json:"matches"`
}

// hostnamesResult is what one domain's hostnames listing produced. It is
// returned with an error too, so the names already received are never lost.
type hostnamesResult struct {
	Names []string
	Pages int
	Units int
	// FailFast is set when the listing stopped after the first page because
	// this month's allowance cannot pay for the rest.
	FailFast        bool
	UnitsToComplete int
	UnitsRemaining  int
}

// normaliseName lower-cases and trims a name, strips a trailing dot and any
// leading wildcard labels. It returns "" for a name with nothing left.
func normaliseName(s string) string {
	n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	for strings.HasPrefix(n, "*.") {
		n = strings.TrimPrefix(n, "*.")
	}
	if n == "*" {
		return ""
	}
	return n
}

// hostnames lists every hostname ndxer has observed under domain, following
// the cursor to the end. keep decides which normalised names are kept (nil
// keeps all). Names are deduplicated and returned in API order.
func (c *client) hostnames(ctx context.Context, domain string, keep func(string) bool) (*hostnamesResult, error) {
	res := &hostnamesResult{}
	seen := make(map[string]struct{})
	var pendingWaited time.Duration
	cursor := ""

	for {
		if err := ctx.Err(); err != nil {
			return res, err
		}

		params := url.Values{"q": {domain}}
		params.Set("limit", strconv.Itoa(hostnamesPageLimit))
		if cursor != "" {
			params.Set("cursor", cursor)
		}

		var page hostnamesPage
		if err := c.get(ctx, domain, hostnamesPath, params, &page, &pendingWaited); err != nil {
			if errors.Is(err, errNotFound) {
				return res, nil
			}
			return res, err
		}
		res.Pages++
		res.Units += page.Meta.UnitsCharged

		for _, m := range page.Matches {
			n := normaliseName(m.Name)
			if n == "" {
				continue
			}
			if _, dup := seen[n]; dup {
				continue
			}
			seen[n] = struct{}{}
			if keep == nil || keep(n) {
				res.Names = append(res.Names, n)
			}
		}

		meta := page.Meta
		next := meta.NextCursor
		if next == nil || *next == "" || *next == cursor {
			return res, nil
		}
		// Fail fast: a listing the month's allowance cannot finish would
		// spend every unit left and still be partial. Keep the first page.
		if cursor == "" && meta.UnitsToComplete != nil && meta.UnitsRemaining != nil && *meta.UnitsToComplete > *meta.UnitsRemaining {
			res.FailFast = true
			res.UnitsToComplete = *meta.UnitsToComplete
			res.UnitsRemaining = *meta.UnitsRemaining
			return res, nil
		}
		cursor = *next
	}
}
