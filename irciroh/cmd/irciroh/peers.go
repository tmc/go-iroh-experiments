package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/tmc/go-iroh-experiments/irciroh"
	"github.com/tmc/go-iroh/key"
)

// The pin store binds endpoint keys to the people behind them.
//
// A nick is a claim: it rides inside a signed envelope, so a signature
// proves which key spoke and nothing about the name. What a reader can
// rely on is the key, and a pin is the one place a person says which
// key they mean by a name. The binding is not channel scoped - the same
// key in #go and in #mod2 is the same person - so there is one store
// per node, a peers file at the root of the chat directory beside nick
// and in:
//
//	<key> <name> <first seen>
//
// one line per pin, the key in full, the time RFC 3339. It is a plain
// file for the same reason the logs are: everything in a chat directory
// is something a person can read, and the trust decision least deserves
// a format they cannot. Nothing here writes it: the file is edited by
// hand until pinning has a design of its own.
//
// Authorization is a separate question with an existing answer. A
// sealed channel's roster already says who may speak in it; the pin
// says who they are. Trusted in a channel is both, and needs no state
// beyond these two.
const peersFile = "peers"

// A pinned peer is one binding, as the file records it.
type pinned struct {
	Name  string
	First time.Time
}

// peers is the pin store of one chat directory. The zero value is not
// usable; call loadPeers. It is safe for concurrent use.
type peers struct {
	path string

	mu     sync.Mutex
	byKey  map[key.EndpointID]pinned
	byName map[string]key.EndpointID // folded name
}

// loadPeers opens the store of the chat directory at root, treating a
// file that is not there as an empty one: a directory nobody has
// pinned in is not an error.
func loadPeers(root string) (*peers, error) {
	p := &peers{path: filepath.Join(root, peersFile)}
	if err := p.load(); err != nil {
		return nil, err
	}
	return p, nil
}

// reload reads the file again, so that a view holding a store sees a
// pin made since it last read it. A view that renders calls this
// rather than looking at the file itself, or the two of them disagree
// about the thing that decides trust.
func (p *peers) reload() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.load()
}

// load reads the file into the maps, discarding what was held. The
// caller holds mu, or has not yet shared p.
func (p *peers) load() error {
	b, err := os.ReadFile(p.path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("peers: %w", err)
	}
	byKey := make(map[key.EndpointID]pinned)
	byName := make(map[string]key.EndpointID)
	for n, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		id, pin, err := parsePin(line)
		if err != nil {
			return fmt.Errorf("peers %s:%d: %w", p.path, n+1, err)
		}
		byKey[id] = pin
		byName[irciroh.Fold(pin.Name)] = id
	}
	p.byKey, p.byName = byKey, byName
	return nil
}

// parsePin reads one line of the file.
func parsePin(line string) (key.EndpointID, pinned, error) {
	f := strings.Fields(line)
	if len(f) != 3 {
		return key.EndpointID{}, pinned{}, fmt.Errorf("want %q, got %d fields", "<key> <name> <first seen>", len(f))
	}
	id, err := key.ParseEndpointID(f[0])
	if err != nil {
		return key.EndpointID{}, pinned{}, fmt.Errorf("key %q: %w", f[0], err)
	}
	if err := okName(f[1]); err != nil {
		return key.EndpointID{}, pinned{}, err
	}
	first, err := time.Parse(time.RFC3339, f[2])
	if err != nil {
		return key.EndpointID{}, pinned{}, fmt.Errorf("first seen %q: %w", f[2], err)
	}
	return id, pinned{Name: f[1], First: first}, nil
}

// A verdict is what the store can say about a line: whether the key
// that signed it is the one pinned to the name it claims. It is the
// classification only - how it reads is the view's business, and the
// views disagree about that on purpose. What they must not disagree
// about is the rule, which is why this is here rather than three times
// over.
//
// A verdict is derived, never stored. It is a fact about the store as
// it is now, not about the moment a line was written: pinning somebody
// settles every line they have ever said, and a log that recorded the
// old answer would go on asserting it. So a log carries the key, and a
// view asks again every time it renders.
type verdict int

const (
	// unattributed is a line with no key behind it at all: everything
	// logged before the key tag, and every server notice, which nobody
	// signed. It is the zero value on purpose. A verdict travels as a
	// field now, and a field nobody set must not be the one that lets a
	// view print a bare name - an older line, a decode that dropped the
	// field, a struct built in a hurry. The safe end of this type is
	// where the zero value falls, and the trusting end has to be asked
	// for.
	unattributed verdict = iota
	// unknown is a key nobody has pinned, claiming a name nobody has
	// pinned. It is the ordinary state of a stranger, and the default
	// in a channel where nothing has been pinned yet.
	unknown
	// renamed is a key we have pinned, claiming some other name.
	renamed
	// claimed is a key we have not pinned, claiming a name pinned to
	// another key - the impersonation case, and the only verdict that
	// reports an attempt rather than an absence.
	claimed
	// pinnedAs is the only verdict that lets a view show a bare name:
	// the key is pinned, under the name it is claiming.
	pinnedAs
)

func (v verdict) String() string {
	switch v {
	case unknown:
		return "unknown"
	case renamed:
		return "renamed"
	case claimed:
		return "claimed"
	case pinnedAs:
		return "pinned"
	}
	return "unattributed"
}

// verdict classifies a line signed by id and claiming name. The name it
// returns alongside is the one the store holds for id, which a view
// needs for the renamed case and which is empty otherwise.
//
// A line with no key is unattributed rather than unknown: nobody signed
// it, so there is no claim to weigh, and a view has nothing to say
// about it beyond what it says. Unknown is a statement about a
// stranger; unattributed is the absence of a speaker.
func (p *peers) verdict(id key.EndpointID, name string) (verdict, string) {
	if id.IsZero() {
		return unattributed, ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	pin, pinned := p.byKey[id]
	switch {
	case pinned && irciroh.Fold(pin.Name) == irciroh.Fold(name):
		return pinnedAs, pin.Name
	case pinned:
		return renamed, pin.Name
	}
	if _, taken := p.byName[irciroh.Fold(name)]; taken {
		return claimed, ""
	}
	return unknown, ""
}

// okName rejects a name that must not become a pin.
//
// A pin is the one thing that lets a view print a bare name, so the
// gate is not about what a nick may be - the network carries whatever
// SetNick was handed - but about what a person can be asked to tell
// apart. Two rules follow from that, and both are about [irciroh.Fold]
// rather than about taste.
//
// A name outside ASCII is refused. Fold maps ASCII and passes
// everything else through, so a name with a Cyrillic a in it folds to
// itself, never collides with the ASCII name it is a picture of, and
// would be pinned as a second, separate person - rendering bare under a
// name a reader cannot distinguish from the first. That is the one
// attack the render rule cannot survive, because the last check in it
// is somebody's eye. Refusing the pin leaves such a name unpinnable and
// therefore always suffixed, which is the safe direction: a name nobody
// can vouch for is shown as one.
//
// The rest is the nick charset the bridge's casemapping implies -
// letters, digits, and the punctuation Fold knows how to fold - plus
// NICKLEN, which the bridge advertises as 32.
func okName(name string) error {
	if name == "" {
		return fmt.Errorf("peers: name is required")
	}
	if len(name) > nickLen {
		return fmt.Errorf("peers: name %q is longer than %d", name, nickLen)
	}
	if r, bad := badNameRune(name); bad {
		if r > unicode.MaxASCII {
			return fmt.Errorf("peers: name %q: %w", name, errNotASCII)
		}
		return fmt.Errorf("peers: name %q holds %q", name, r)
	}
	return nil
}

// badNameRune returns the first character of name that keeps it from
// being pinned, if there is one. It is what okName refuses, for a
// caller that would rather show the character than name the rule.
func badNameRune(name string) (rune, bool) {
	for _, r := range name {
		if r > unicode.MaxASCII || !okNameRune(r) {
			return r, true
		}
	}
	return 0, false
}

// errNotASCII reports a name that cannot be pinned because it cannot be
// told apart from one that can.
var errNotASCII = errors.New("a pinned name must be ASCII, so that no two pins look alike")

// nickLen is NICKLEN, as the bridge advertises it.
const nickLen = 32

// okNameRune reports whether r may appear in a pinned name: a letter, a
// digit, or one of the special characters RFC 2812 allows in a nick,
// which are also the ones Fold folds.
func okNameRune(r rune) bool {
	switch {
	case 'a' <= r && r <= 'z', 'A' <= r && r <= 'Z', '0' <= r && r <= '9':
		return true
	}
	return strings.ContainsRune("[]\\`_^{|}~-", r)
}
