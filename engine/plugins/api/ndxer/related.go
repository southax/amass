// SPDX-License-Identifier: Apache-2.0

package ndxer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	classSubject        = "subject"
	classReview         = "review"
	classInfrastructure = "infrastructure"

	envNoRelated      = "NDXER_NO_RELATED"
	envRelatedClasses = "NDXER_RELATED_CLASSES"

	investigationURL = "https://ndxer.com/app/investigations/?q="
)

type relatedPage struct {
	Meta struct {
		NextCursor      *string `json:"next_cursor"`
		UnitsCharged    int     `json:"units_charged"`
		UnitsToComplete *int    `json:"units_to_complete"`
		UnitsRemaining  *int    `json:"units_remaining"`
	} `json:"meta"`
	Seed struct {
		Signals []struct {
			Class string `json:"class"`
		} `json:"signals"`
	} `json:"seed"`
	Matches []struct {
		Apex     string `json:"apex"`
		Class    string `json:"class"`
		Evidence []struct {
			Kind         string  `json:"kind"`
			Key          string  `json:"key"`
			NApexes      int     `json:"n_apexes"`
			ProviderName *string `json:"provider_name"`
		} `json:"evidence"`
		Reasons []struct {
			Code string `json:"code"`
			Text string `json:"text"`
		} `json:"reasons"`
	} `json:"matches"`
}

// evidence is one value a related domain shares with the seed.
type evidence struct {
	Kind     string
	Key      string
	NApexes  int
	Provider string
}

// relatedMatch is one domain ndxer links to the seed.
type relatedMatch struct {
	Domain   string
	Class    string
	Why      string
	Evidence []evidence
}

// relatedResult is everything one seed's related lookup produced.
type relatedResult struct {
	// Matches holds every matched domain once, in API order.
	Matches []relatedMatch
	// InfrastructureSignals counts seed signals that belong to a provider.
	InfrastructureSignals int
	Units                 int
	Pages                 int
	// Stopped is set when paging ended early; it says why.
	Stopped string
	// Partial is set when the list was read while more was still being added
	// for the seed; PartialCapped when that was after the whole wait.
	Partial       bool
	PartialCapped bool
}

// related follows the cursor to the end. Every further page costs a unit, so
// it stops, keeping what it has, when the allowance cannot cover the rest.
func (c *client) related(ctx context.Context, seed string) (*relatedResult, error) {
	res := &relatedResult{}
	seen := make(map[string]struct{})
	var pendingWaited time.Duration
	cursor := ""

	for {
		if err := ctx.Err(); err != nil {
			return res, err
		}

		params := url.Values{"q": {seed}}
		if cursor != "" {
			params.Set("cursor", cursor)
		}

		var page relatedPage
		if err := c.get(ctx, seed, relatedPath, params, &page, &pendingWaited); err != nil {
			var pe *partialError
			var ae *apiError
			switch {
			case errors.Is(err, errNotFound):
				return res, nil
			case errors.As(err, &pe):
				res.Partial, res.PartialCapped = true, pe.capped
			case res.Pages > 0 && errors.As(err, &ae) && ae.Code == "quota_exceeded":
				res.Stopped = "the monthly allowance ran out while paging; kept the pages fetched so far"
				return res, nil
			default:
				return res, err
			}
		}
		res.Pages++
		res.Units += page.Meta.UnitsCharged

		if res.Pages == 1 {
			for _, s := range page.Seed.Signals {
				if strings.EqualFold(s.Class, classInfrastructure) {
					res.InfrastructureSignals++
				}
			}
		}

		for _, m := range page.Matches {
			domain := normaliseName(m.Apex)
			if domain == "" {
				continue
			}
			if _, dup := seen[domain]; dup {
				continue
			}
			seen[domain] = struct{}{}

			rm := relatedMatch{Domain: domain, Class: strings.ToLower(strings.TrimSpace(m.Class))}
			if len(m.Reasons) > 0 {
				rm.Why = m.Reasons[0].Text
			}
			for _, ev := range m.Evidence {
				e := evidence{Kind: ev.Kind, Key: ev.Key, NApexes: ev.NApexes}
				if ev.ProviderName != nil {
					e.Provider = *ev.ProviderName
				}
				rm.Evidence = append(rm.Evidence, e)
			}
			res.Matches = append(res.Matches, rm)
		}

		meta := page.Meta
		next := meta.NextCursor
		if next == nil || *next == "" || *next == cursor {
			return res, nil
		}
		if meta.UnitsRemaining != nil && meta.UnitsToComplete != nil && *meta.UnitsToComplete > *meta.UnitsRemaining {
			res.Stopped = fmt.Sprintf("the remaining pages need %d more units and %d are left this month; kept the pages fetched so far",
				*meta.UnitsToComplete, *meta.UnitsRemaining)
			return res, nil
		}
		if meta.UnitsRemaining != nil && *meta.UnitsRemaining < 1 {
			res.Stopped = "no units are left this month for further pages; kept the pages fetched so far"
			return res, nil
		}
		cursor = *next
	}
}

// relatedConfig is the related-scope behaviour chosen through the environment.
type relatedConfig struct {
	enabled bool
	classes []string
	// notes are said once per session in the session log.
	notes []string
}

// parseRelatedConfig reads NDXER_NO_RELATED and NDXER_RELATED_CLASSES values.
// The default is enabled with the subject class only.
func parseRelatedConfig(noRelated, classes string) relatedConfig {
	cfg := relatedConfig{enabled: true}

	if v := strings.TrimSpace(noRelated); v != "" {
		if off, err := strconv.ParseBool(v); err != nil || off {
			cfg.enabled = false
			cfg.notes = append(cfg.notes, "ndxer related scope is OFF ("+envNoRelated+" is set): only hostnames under the domains already in scope are listed, and domains ndxer links to the same owner are not added")
			return cfg
		}
	}

	for _, c := range strings.Split(classes, ",") {
		c = strings.ToLower(strings.TrimSpace(c))
		switch c {
		case "":
		case classSubject, classReview:
			if !slices.Contains(cfg.classes, c) {
				cfg.classes = append(cfg.classes, c)
			}
		case classInfrastructure:
			cfg.notes = append(cfg.notes, envRelatedClasses+": infrastructure is never added; it belongs to a provider, not to the subject (use subject or review)")
		default:
			cfg.notes = append(cfg.notes, fmt.Sprintf("%s: unknown class %q ignored (use subject or review)", envRelatedClasses, c))
		}
	}
	if len(cfg.classes) == 0 {
		cfg.classes = []string{classSubject}
	}
	return cfg
}

// selectMatches returns the matches of the configured classes, ordered by
// class as configured then API order, without the seed itself, and the review
// matches that were not selected.
func selectMatches(seed string, res *relatedResult, classes []string) (selected, reviewNotSelected []relatedMatch) {
	for _, class := range classes {
		for _, m := range res.Matches {
			if m.Class == class && m.Domain != seed {
				selected = append(selected, m)
			}
		}
	}
	if !slices.Contains(classes, classReview) {
		for _, m := range res.Matches {
			if m.Class == classReview && m.Domain != seed {
				reviewNotSelected = append(reviewNotSelected, m)
			}
		}
	}
	return selected, reviewNotSelected
}

// formatEvidence renders shared values as "kind key + kind key".
func formatEvidence(values []evidence) string {
	if len(values) == 0 {
		return "no listed values"
	}
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = v.Kind + " " + v.Key
	}
	return strings.Join(parts, " + ")
}

func domainsOf(ms []relatedMatch) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = m.Domain
	}
	return out
}

// addFunc puts a domain in the session scope and queues it for enumeration.
// It returns false with a nil error when the domain was already in scope,
// false with an error when it could not be added, and true with an error
// when it was added but something after that failed.
type addFunc func(domain string) (bool, error)

// expandRelated acts on one seed's related result: it adds the selected
// domains to the scope (unless rigid) and says loudly what it did, what it
// did not do, and why. It returns the domains added.
func expandRelated(log *slog.Logger, st *sessionState, seed string, res *relatedResult, cfg relatedConfig, rigid bool, add addFunc) []string {
	selected, reviewNotSelected := selectMatches(seed, res, cfg.classes)
	inspect := investigationURL + seed

	var added []relatedMatch
	var already []string
	if rigid {
		if len(selected) > 0 {
			log.Info(fmt.Sprintf("ndxer related scope for %s: found %d domains ndxer links to the same owner; NOT added because rigid boundaries are on", seed, len(selected)),
				"seed", seed, "found", len(selected), "domains", strings.Join(domainsOf(selected), " "), "inspect", inspect)
			for _, m := range selected {
				log.Info("ndxer related domain not added (rigid boundaries)", "seed", seed, "domain", m.Domain,
					"class", m.Class, "reason", m.Why, "evidence", formatEvidence(m.Evidence))
			}
		}
	} else {
		for _, m := range selected {
			if !st.reserve(m.Domain, seed) {
				continue // already added through another seed
			}
			ok, err := add(m.Domain)
			if err != nil && !ok {
				st.release(m.Domain)
				log.Error(fmt.Sprintf("ndxer related scope for %s: could not add %s: %v", seed, m.Domain, err),
					"seed", seed, "domain", m.Domain, "class", m.Class)
				continue
			}
			if err != nil {
				log.Warn(fmt.Sprintf("ndxer related scope for %s: %s: %v", seed, m.Domain, err),
					"seed", seed, "domain", m.Domain, "class", m.Class)
			}
			if !ok {
				st.release(m.Domain)
				already = append(already, m.Domain)
				continue
			}
			added = append(added, m)
		}

		log.Info(fmt.Sprintf("ndxer related scope for %s: added %d domains ndxer links to the same owner; amass enumerates them with every data source", seed, len(added)),
			"seed", seed, "added", len(added), "classes", strings.Join(cfg.classes, ","),
			"domains", strings.Join(domainsOf(added), " "), "inspect", inspect)
		for _, m := range added {
			log.Info("ndxer related domain added", "seed", seed, "domain", m.Domain,
				"class", m.Class, "reason", m.Why, "evidence", formatEvidence(m.Evidence))
		}
		if len(already) > 0 {
			log.Info(fmt.Sprintf("ndxer related scope for %s: %d related domains were already in scope", seed, len(already)),
				"seed", seed, "domains", strings.Join(already, " "))
		}
	}

	if n := len(reviewNotSelected); n > 0 {
		log.Info(fmt.Sprintf("ndxer related scope for %s: NOT added: %d review domains (weaker evidence of the same owner); include them with %s=subject,review", seed, n, envRelatedClasses),
			"seed", seed, "review", n, "domains", strings.Join(domainsOf(reviewNotSelected), " "))
		for _, m := range reviewNotSelected {
			log.Info("ndxer related domain not added (review)", "seed", seed, "domain", m.Domain,
				"class", m.Class, "reason", m.Why, "evidence", formatEvidence(m.Evidence))
		}
	}
	if n := res.InfrastructureSignals; n > 0 {
		log.Info(fmt.Sprintf("ndxer related scope for %s: %d shared signals belong to infrastructure providers, not to the subject; never added", seed, n),
			"seed", seed, "infrastructure_signals", n)
	}
	if res.Stopped != "" {
		log.Warn(fmt.Sprintf("ndxer related scope for %s is INCOMPLETE: %s", seed, res.Stopped), "seed", seed)
	}
	pages := "pages"
	if res.Pages == 1 {
		pages = "page"
	}
	log.Info(fmt.Sprintf("ndxer related scope for %s: %d units charged (%d %s); each added domain's hostnames listing is charged on top", seed, res.Units, res.Pages, pages),
		"seed", seed, "units", res.Units, "pages", res.Pages, "turn_off", envNoRelated+"=1")

	return domainsOf(added)
}
