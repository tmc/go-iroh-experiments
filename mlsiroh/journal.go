package mlsiroh

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/tmc/mls"
)

// A Journal records which key packages a directory has served.
//
// MLS means a key package to be used once (RFC 9420, Section 10). A
// directory that forgets what it has served re-serves it after a
// restart, and two groups then encrypt their Welcome to the same init
// key: one compromise of that key yields the joiner secret of both
// (Section 16.8). The journal is what makes the rule survive a crash.
// It also routes a Welcome for a key package served before a restart,
// which is why an [Entry] keeps the key package's lifetime.
//
// Record must not return until the record is durable, because the
// directory calls it before it writes the response. Implementations
// must be safe for concurrent use. Each journal belongs to exactly one
// Directory; Consumed and Record are not an atomic claim across directories.
type Journal interface {
	// Record notes that the key package e describes has been
	// served. Recording an entry twice is not an error.
	Record(e Entry) error

	// Consumed reports whether a key package with e's reference or
	// e's init key has been recorded. The init key is what the
	// consume-once rule protects: a key package re-signed with a new
	// lifetime has a new reference and the same init key.
	Consumed(e Entry) (bool, error)

	// Lookup returns the entry recorded for the key package named
	// by ref, and false if there is none.
	Lookup(ref mls.HashReference) (Entry, bool, error)
}

// An Entry is what a journal keeps about one served key package.
type Entry struct {
	Ref      mls.HashReference
	InitKey  mls.HPKEPublicKey
	NotAfter uint64 // the end of the key package's lifetime, in Unix seconds
}

// entry returns the journal entry for kp.
func entry(kp *mls.KeyPackage) (Entry, error) {
	ref, err := kp.Ref()
	if err != nil {
		return Entry{}, fmt.Errorf("mlsiroh: key package reference: %w", err)
	}
	return Entry{Ref: ref, InitKey: kp.InitKey, NotAfter: kp.LeafNode.Lifetime.NotAfter}, nil
}

// entries is the index both journals keep: entries by reference, and
// the init keys they hold.
type entries struct {
	refs  map[string]Entry
	inits map[string]bool
}

func (x *entries) add(e Entry) {
	if x.refs == nil {
		x.refs = make(map[string]Entry)
		x.inits = make(map[string]bool)
	}
	x.refs[string(e.Ref)] = e
	if len(e.InitKey) > 0 {
		x.inits[string(e.InitKey)] = true
	}
}

func (x *entries) consumed(e Entry) bool {
	_, ok := x.refs[string(e.Ref)]
	return ok || len(e.InitKey) > 0 && x.inits[string(e.InitKey)]
}

// MemoryJournal is a Journal that keeps its records in memory.
//
// It is for tests. A directory using one re-serves every key package
// it had served before a restart, which is the failure the Journal
// exists to prevent.
//
// The zero MemoryJournal is ready to use.
type MemoryJournal struct {
	mu sync.Mutex
	x  entries
}

// Record notes e in memory.
func (j *MemoryJournal) Record(e Entry) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.x.add(e)
	return nil
}

// Consumed reports whether e's reference or init key has been
// recorded.
func (j *MemoryJournal) Consumed(e Entry) (bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.x.consumed(e), nil
}

// Lookup returns the entry recorded for ref.
func (j *MemoryJournal) Lookup(ref mls.HashReference) (Entry, bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	e, ok := j.x.refs[string(ref)]
	return e, ok, nil
}

// Sizes of the fields a FileJournal stores. Both are fixed by [Suite]:
// a reference is a SHA-256 hash and an init key an X25519 public key.
const (
	refSize     = 32
	initKeySize = 32
)

// A FileJournal is a Journal backed by an append-only file with one
// line per served key package: its hex reference, its hex init key,
// and the end of its lifetime in decimal Unix seconds, separated by
// spaces. Each line is synced before Record returns.
//
// The format is deliberately dull. A consumed key package is a fact
// that must outlive the process that recorded it, and a text file
// that a person can read and an operator can back up is a better fit
// for that than a database. Exactly one Directory in one process may own
// the file; opening another writer is outside this implementation's contract.
type FileJournal struct {
	mu   sync.Mutex
	f    *os.File
	x    entries
	size int64 // bytes of whole lines in f
}

// OpenJournal opens or creates the journal at name and reads the
// entries it already holds.
//
// A crash can leave the last line incomplete. OpenJournal cuts it off,
// so that the next record starts on a line of its own; the key package
// it described was never served, because Record had not returned.
func OpenJournal(name string) (*FileJournal, error) {
	_, statErr := os.Stat(name)
	f, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("mlsiroh: opening journal: %w", err)
	}
	if errors.Is(statErr, os.ErrNotExist) {
		// A new file is durable only once its directory entry is.
		if err := syncDir(filepath.Dir(name)); err != nil {
			f.Close()
			return nil, err
		}
	}
	j := &FileJournal{f: f}
	if err := j.load(); err != nil {
		f.Close()
		return nil, err
	}
	return j, nil
}

func syncDir(name string) error {
	d, err := os.Open(name)
	if err != nil {
		return fmt.Errorf("mlsiroh: syncing journal directory: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("mlsiroh: syncing journal directory: %w", err)
	}
	return nil
}

// load reads the existing entries and truncates an incomplete last
// line.
//
// A malformed complete line is an error: forgetting a consumption record
// could allow an init key to be served twice. Legacy reference-only lines
// remain supported. A file must have exactly one writer process.
func (j *FileJournal) load() error {
	if _, err := j.f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("mlsiroh: reading journal: %w", err)
	}
	r := bufio.NewReader(j.f)
	var off int64
	for {
		line, err := r.ReadBytes('\n')
		if err == io.EOF {
			j.size = off
			if len(line) > 0 {
				if err := j.f.Truncate(off); err != nil {
					return fmt.Errorf("mlsiroh: truncating journal: %w", err)
				}
				if err := j.f.Sync(); err != nil {
					return fmt.Errorf("mlsiroh: syncing journal: %w", err)
				}
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("mlsiroh: reading journal: %w", err)
		}
		off += int64(len(line))
		e, ok := parseEntry(line[:len(line)-1])
		if !ok {
			return fmt.Errorf("mlsiroh: malformed journal record ending at byte %d", off)
		}
		j.x.add(e)
	}
}

// parseEntry parses one journal line without its newline.
func parseEntry(line []byte) (Entry, bool) {
	f := bytes.Fields(line)
	if len(f) != 1 && len(f) != 3 {
		return Entry{}, false
	}
	var e Entry
	var ok bool
	if e.Ref, ok = decodeHex(f[0], refSize); !ok {
		return Entry{}, false
	}
	if len(f) == 1 {
		return e, true
	}
	if e.InitKey, ok = decodeHex(f[1], initKeySize); !ok {
		return Entry{}, false
	}
	n, err := strconv.ParseUint(string(f[2]), 10, 64)
	if err != nil {
		return Entry{}, false
	}
	e.NotAfter = n
	return e, true
}

func decodeHex(s []byte, size int) ([]byte, bool) {
	if len(s) != 2*size {
		return nil, false
	}
	b := make([]byte, size)
	if _, err := hex.Decode(b, s); err != nil {
		return nil, false
	}
	return b, true
}

// Record appends e to the file and syncs it.
func (j *FileJournal) Record(e Entry) error {
	if len(e.Ref) != refSize || len(e.InitKey) != initKeySize {
		return fmt.Errorf("mlsiroh: journal entry has a %d-byte reference and a %d-byte init key", len(e.Ref), len(e.InitKey))
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if old, ok := j.x.refs[string(e.Ref)]; ok && bytes.Equal(old.InitKey, e.InitKey) && old.NotAfter == e.NotAfter {
		return nil
	}
	// One write of a whole line, not a buffered one: a crash then
	// leaves at most one incomplete line, at the end, which load
	// removes. A write that fails without a crash can leave the same
	// fragment, and this line would be glued onto it, so anything past
	// the last whole line is cut off first.
	fi, err := j.f.Stat()
	if err != nil {
		return fmt.Errorf("mlsiroh: writing journal: %w", err)
	}
	if fi.Size() != j.size {
		if err := j.f.Truncate(j.size); err != nil {
			return fmt.Errorf("mlsiroh: truncating journal: %w", err)
		}
	}
	line := fmt.Sprintf("%x %x %d\n", []byte(e.Ref), []byte(e.InitKey), e.NotAfter)
	if _, err := j.f.WriteString(line); err != nil {
		return fmt.Errorf("mlsiroh: writing journal: %w", err)
	}
	if err := j.f.Sync(); err != nil {
		return fmt.Errorf("mlsiroh: syncing journal: %w", err)
	}
	j.size += int64(len(line))
	j.x.add(e)
	return nil
}

// Consumed reports whether e's reference or init key has been
// recorded.
func (j *FileJournal) Consumed(e Entry) (bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.x.consumed(e), nil
}

// Lookup returns the entry recorded for ref.
func (j *FileJournal) Lookup(ref mls.HashReference) (Entry, bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	e, ok := j.x.refs[string(ref)]
	return e, ok, nil
}

// Close closes the journal file.
func (j *FileJournal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.f.Close()
}
