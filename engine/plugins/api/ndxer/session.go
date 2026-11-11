// SPDX-License-Identifier: Apache-2.0

package ndxer

import "sync"

// sessionState is what the plugin remembers about one amass session.
type sessionState struct {
	mu sync.Mutex
	// added maps each domain this plugin put in scope to the seed it came from.
	added map[string]string
	// relatedOff is set after an API status every further request repeats.
	relatedOff bool
	// announced is set once the configuration notes were logged.
	announced bool
	done      func() bool
}

// reserve claims domain as added by this plugin for seed. It returns false
// when the domain was already claimed.
func (s *sessionState) reserve(domain, seed string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.added[domain]; ok {
		return false
	}
	s.added[domain] = seed
	return true
}

// release drops a claim made by reserve that did not lead to an addition.
func (s *sessionState) release(domain string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.added, domain)
}

// wasAdded reports whether this plugin put domain in scope, and from which seed.
func (s *sessionState) wasAdded(domain string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	seed, ok := s.added[domain]
	return seed, ok
}

// turnRelatedOff sets relatedOff and reports whether this call changed it.
func (s *sessionState) turnRelatedOff() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.relatedOff {
		return false
	}
	s.relatedOff = true
	return true
}

func (s *sessionState) isRelatedOff() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.relatedOff
}

// announce reports true the first time it is called.
func (s *sessionState) announce() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.announced {
		return false
	}
	s.announced = true
	return true
}

// tracker holds the state of every live session, keyed by session ID.
type tracker struct {
	mu       sync.Mutex
	sessions map[string]*sessionState
}

func newTracker() *tracker {
	return &tracker{sessions: make(map[string]*sessionState)}
}

// get returns the state for the session id, creating it on first use, and
// forgets sessions that have finished.
func (t *tracker) get(id string, done func() bool) *sessionState {
	t.mu.Lock()
	defer t.mu.Unlock()

	for k, s := range t.sessions {
		if k != id && s.done != nil && s.done() {
			delete(t.sessions, k)
		}
	}

	s, ok := t.sessions[id]
	if !ok {
		s = &sessionState{added: make(map[string]string), done: done}
		t.sessions[id] = s
	}
	return s
}
