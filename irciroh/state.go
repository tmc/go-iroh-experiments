package irciroh

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/tmc/go-iroh/key"
)

// A state is a node's durable state: the channels it founded and the
// endpoints it kicked from them.
//
// Almost nothing in a node is durable. There is no backlog, no roster on
// disk, and in particular no MLS group state: an epoch's secrets live
// only in memory, so a disk anyone later reads does not open anything
// anyone said. These two things are here because without them a kick
// does not survive the founder's process, and a kick that a restart
// forgets is not a kick.
//
// Two files, each one "channel value" pair per line, sorted. A channel
// name cannot contain a space (see checkChannel), so a pair needs no
// quoting, and each file is rewritten and renamed into place on every
// change: there are a handful of lines, and an operator should be able
// to read and edit them.
//
//	bans      a folded channel name and a banned endpoint id
//	secrets   a folded channel name and its invite secret, in hex
//
// The secrets file is a credential store. Its secret is what derives a
// sealed channel's topic and what the founder checks at the invite, so
// anyone who reads it can both find the swarm and ask to join. It is
// written 0600 inside a 0700 directory, and a node that would rather
// keep no such file simply does not pass [WithStateDir] - at the cost of
// founding a different channel on every restart.
type state struct {
	dir string

	mu      sync.Mutex
	banned  map[string][]key.EndpointID // by folded channel name
	secrets map[string][]byte           // by folded channel name
}

// secretSize is the length of the invite secret a founder mints.
const secretSize = 32

// openState reads the state in dir. Neither dir nor the files in it are
// created until something needs writing. A nil *state is usable
// throughout and simply remembers nothing.
func openState(dir string) (*state, error) {
	s := &state{
		dir:     dir,
		banned:  make(map[string][]key.EndpointID),
		secrets: make(map[string][]byte),
	}
	if err := s.read("bans", func(ch, value string) error {
		id, err := key.ParseEndpointID(value)
		if err != nil {
			return err
		}
		s.banned[ch] = append(s.banned[ch], id)
		return nil
	}); err != nil {
		return nil, err
	}
	if err := s.read("secrets", func(ch, value string) error {
		b, err := hex.DecodeString(value)
		if err != nil {
			return err
		}
		if len(b) != secretSize {
			return fmt.Errorf("secret is %d bytes, want %d", len(b), secretSize)
		}
		s.secrets[ch] = b
		return nil
	}); err != nil {
		return nil, err
	}
	return s, nil
}

// read parses one state file, calling add for each pair. A file that is
// not there is not an error; a file that is there and malformed is,
// because guessing at a ban list is worse than refusing to start.
func (s *state) read(name string, add func(ch, value string) error) error {
	path := filepath.Join(s.dir, name)
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		ch, value, ok := strings.Cut(line, " ")
		if !ok {
			return fmt.Errorf("%s:%d: want \"channel value\"", path, n)
		}
		name, err := checkChannel(ch)
		if err != nil {
			return fmt.Errorf("%s:%d: %w", path, n, err)
		}
		if err := add(name, strings.TrimSpace(value)); err != nil {
			return fmt.Errorf("%s:%d: %w", path, n, err)
		}
	}
	return sc.Err()
}

// bans returns the endpoints banned from a channel.
func (s *state) bans(channel string) []key.EndpointID {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.banned[Fold(channel)])
}

// ban records a ban. An error means it was not written down: the caller
// must not treat the kick as durable, and the ban is not held in memory
// either, so that asking again tries the write again.
func (s *state) ban(channel string, id key.EndpointID) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	name := Fold(channel)
	if slices.Contains(s.banned[name], id) {
		return nil
	}
	lines := []string{name + " " + id.String()}
	for ch, ids := range s.banned {
		for _, id := range ids {
			lines = append(lines, ch+" "+id.String())
		}
	}
	if err := s.write("bans", lines); err != nil {
		return err
	}
	s.banned[name] = append(s.banned[name], id)
	return nil
}

// secret returns the stored invite secret for a channel, or nil.
func (s *state) secret(channel string) []byte {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.secrets[Fold(channel)])
}

// setSecret records the invite secret a founder minted, so that the next
// run of the same node founds the same channel rather than a new one
// nobody holding an old ticket can reach. The secret is held in memory
// only once it is written.
func (s *state) setSecret(channel string, secret []byte) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	name := Fold(channel)
	lines := []string{name + " " + hex.EncodeToString(secret)}
	for ch, b := range s.secrets {
		if ch != name {
			lines = append(lines, ch+" "+hex.EncodeToString(b))
		}
	}
	if err := s.write("secrets", lines); err != nil {
		return err
	}
	s.secrets[name] = slices.Clone(secret)
	return nil
}

// write replaces one state file. The caller holds s.mu.
//
// The new contents are synced before the rename and the directory after
// it, so that once write returns the change survives a crash as well as
// a restart: a rename that is not yet on disk can come back as the old
// file, which for a ban is the kick undone.
func (s *state) write(name string, lines []string) error {
	slices.Sort(lines)
	body := []byte(strings.Join(lines, "\n") + "\n")
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(s.dir, name+"-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(body); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(s.dir, name)); err != nil {
		return err
	}
	d, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
