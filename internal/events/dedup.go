package events

import "sync"

// seenSet is a concurrency-safe set of event IDs. It is the anti-loop
// mechanism: an ID is delivered at most once per run, so A -> B -> A
// discovery cycles terminate.
type seenSet struct {
	mu  sync.Mutex
	ids map[string]struct{}
}

func newSeenSet() *seenSet { return &seenSet{ids: make(map[string]struct{})} }

func (s *seenSet) has(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.ids[id]
	return ok
}

// add records id and reports whether it was new.
func (s *seenSet) add(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.ids[id]; ok {
		return false
	}
	s.ids[id] = struct{}{}
	return true
}
