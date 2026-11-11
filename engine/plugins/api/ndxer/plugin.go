// SPDX-License-Identifier: Apache-2.0

// Package ndxer is the ndxer data source: every hostname ndxer has observed
// under an in-scope domain and, by default, the domains ndxer links to the
// same owner, added to the session scope so every data source enumerates them.
package ndxer

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"golang.org/x/time/rate"
)

const (
	pluginName = "ndxer"
	envAPIKey  = "NDXER_API_KEY"
)

type ndxerPlugin struct {
	name    string
	log     *slog.Logger
	rlimit  *rate.Limiter
	source  *et.Source
	baseURL string
	related relatedConfig
	noWait  bool
	envKey  string
	state   *tracker
	retry   backoff
}

// NewNdxer returns the ndxer data source plugin.
func NewNdxer() et.Plugin {
	return &ndxerPlugin{
		name: pluginName,
		// an authenticated API: a couple of requests per second
		rlimit: rate.NewLimiter(rate.Every(500*time.Millisecond), 2),
		source: &et.Source{
			Name:       pluginName,
			Confidence: 80,
		},
		baseURL: defaultBaseURL,
		state:   newTracker(),
		retry:   defaultBackoff(),
	}
}

func (p *ndxerPlugin) Name() string {
	return p.name
}

func (p *ndxerPlugin) Start(r et.Registry) error {
	p.log = r.Log().WithGroup("plugin").With("name", p.name)
	p.envKey = strings.TrimSpace(os.Getenv(envAPIKey))
	p.related = parseRelatedConfig(os.Getenv(envNoRelated), os.Getenv(envRelatedClasses))
	p.noWait = parseNoWait(os.Getenv(envNoWait))
	if p.noWait {
		p.related.notes = append(p.related.notes, noWaitNote)
	}

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       p,
		Name:         p.name + "-Handler",
		Position:     21,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     p.check,
	}); err != nil {
		return err
	}

	for _, note := range p.related.notes {
		p.log.Info(note)
	}
	p.log.Info("Plugin started")
	return nil
}

func (p *ndxerPlugin) Stop() {
	p.log.Info("Plugin stopped")
}

// apiKey returns the key from the ndxer data source config, else from NDXER_API_KEY.
func (p *ndxerPlugin) apiKey(cfg *config.Config) string {
	if cfg != nil {
		if ds := cfg.GetDataSourceConfig(p.name); ds != nil {
			for _, cr := range ds.Creds {
				if cr != nil && strings.TrimSpace(cr.Apikey) != "" {
					return strings.TrimSpace(cr.Apikey)
				}
			}
		}
	}
	return p.envKey
}

func (p *ndxerPlugin) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !support.HasSLDInScope(e) {
		return nil
	}

	key := p.apiKey(e.Session.Config())
	if key == "" {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), p.name)
	if err != nil {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, p.source, since) {
		return nil
	}

	domain := normaliseName(fqdn.Name)
	log := e.Session.Log().With(slog.Group("plugin", "name", p.name, "handler", p.name+"-Handler"))
	st := p.state.get(e.Session.ID().String(), e.Session.Done)
	if st.announce() {
		for _, note := range p.related.notes {
			log.Info(note)
		}
	}

	c := &client{
		baseURL: p.baseURL,
		key:     key,
		http:    e.Session.Clients().General,
		limiter: p.rlimit,
		sem:     e.Session.NetSem(),
		retry:   p.retry,
		noWait:  p.noWait,
		onWait: func(subject, path string, partial bool) {
			log.Info(waitMessage(subject, path, partial), "domain", subject, "wait_max", pendingWait.String())
		},
	}

	p.hostnames(e, log, st, c, domain)
	p.relatedStep(e, log, st, c, domain)

	support.MarkAssetMonitored(e.Session, e.Entity, p.source)
	return nil
}

func (p *ndxerPlugin) hostnames(e *et.Event, log *slog.Logger, st *sessionState, c *client, domain string) {
	keep := func(name string) bool {
		_, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: name}, 0)
		return conf > 0
	}

	res, err := c.hostnames(e.Session.Ctx(), domain, keep)
	if res != nil && len(res.Names) > 0 {
		if ents := support.StoreFQDNsWithSource(e.Session, res.Names, p.source, p.name, p.name+"-Handler"); len(ents) > 0 {
			support.ProcessFQDNsWithSource(e, ents, p.source)
		}
	}

	if err != nil {
		if e.Session.Ctx().Err() != nil {
			return
		}
		log.Error(fmt.Sprintf("ndxer hostnames for %s: %v; kept the %d names received before the error", domain, err, len(res.Names)),
			"domain", domain, "kept", len(res.Names))
		p.maybeTurnRelatedOff(log, st, err)
		return
	}
	if res.Partial {
		log.Warn(partialMessage("hostnames", domain, len(res.Names), res.PartialCapped),
			"domain", domain, "kept", len(res.Names), "partial", true)
	}
	if res.FailFast {
		log.Warn(fmt.Sprintf("ndxer hostnames for %s: kept %d names from the first page; listing every hostname under %s needs %d more units and %d are left this month",
			domain, len(res.Names), domain, res.UnitsToComplete, res.UnitsRemaining),
			"domain", domain, "kept", len(res.Names), "units_to_complete", res.UnitsToComplete, "units_remaining", res.UnitsRemaining)
	}
}

func (p *ndxerPlugin) relatedStep(e *et.Event, log *slog.Logger, st *sessionState, c *client, domain string) {
	if !shouldLookupRelated(p.related, st, domain) {
		return
	}

	res, err := c.related(e.Session.Ctx(), domain)
	if err != nil {
		if e.Session.Ctx().Err() != nil {
			return
		}
		if !p.maybeTurnRelatedOff(log, st, err) {
			log.Error(fmt.Sprintf("ndxer related scope for %s: %v; only the names under %s are listed for this domain", domain, err, domain),
				"seed", domain)
		}
		// matches received before the error are still acted on and reported
		if res == nil || len(res.Matches) == 0 {
			return
		}
	}

	add := func(d string) (bool, error) { return p.addToScope(e, d) }
	expandRelated(log, st, domain, res, p.related, e.Session.Config().Rigid, add)
	if res.Partial {
		log.Warn(partialMessage("related domains", domain, len(res.Matches), res.PartialCapped),
			"seed", domain, "kept", len(res.Matches), "partial", true)
	}
}

// shouldLookupRelated reports whether domain gets a related lookup. One hop
// only: a domain this plugin added gets its hostnames, not another lookup.
func shouldLookupRelated(cfg relatedConfig, st *sessionState, domain string) bool {
	if !cfg.enabled || st.isRelatedOff() {
		return false
	}
	_, added := st.wasAdded(domain)
	return !added
}

// maybeTurnRelatedOff turns the related step off for the session after a
// fatal API status, logging once. It reports whether err was fatal.
func (p *ndxerPlugin) maybeTurnRelatedOff(log *slog.Logger, st *sessionState, err error) bool {
	if !isFatal(err) {
		return false
	}
	if st.turnRelatedOff() && p.related.enabled {
		log.Error(fmt.Sprintf("ndxer related scope: %v. Related-scope expansion is off for the rest of this session; set %s=1 to turn it off explicitly", err, envNoRelated))
	}
	return true
}

// addToScope stores the domain, adds it to the session scope and queues it,
// the way horizontals widens the scope.
func (p *ndxerPlugin) addToScope(e *et.Event, domain string) (bool, error) {
	if a, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: domain}, 0); conf > 0 && a != nil && strings.EqualFold(a.Key(), domain) {
		return false, nil
	}

	ents := support.StoreFQDNsWithSource(e.Session, []string{domain}, p.source, p.name, p.name+"-Handler")
	if len(ents) == 0 {
		return false, errors.New("the domain could not be stored")
	}
	ent := ents[0]

	if !e.Session.Scope().Add(ent.Asset) {
		if a, conf := e.Session.Scope().IsAssetInScope(ent.Asset, 0); conf > 0 && a != nil && strings.EqualFold(a.Key(), domain) {
			return false, nil
		}
		return false, errors.New("amass accepts only registered domains into its scope")
	}
	if err := e.Session.Backlog().Enqueue(ent); err != nil {
		return true, fmt.Errorf("added to scope but not queued: %w", err)
	}
	return true, nil
}
