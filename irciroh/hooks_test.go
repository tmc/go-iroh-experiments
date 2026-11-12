package irciroh

import "time"

// Accessors for tests, which must not reach into a sealed channel's
// fields while its receive loop is using them.

// epoch returns the group's current epoch.
func (s *sealed) epoch() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.group.Epoch()
}

// staged returns the number of proposals waiting for a commit.
func (s *sealed) staged() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending)
}

// setResyncEvery sets the rejoin interval.
func (s *sealed) setResyncEvery(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resyncEvery = d
}
