package mlsiroh

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/tmc/mls"
)

func testJournals(t *testing.T) map[string]func() Journal {
	return map[string]func() Journal{
		"memory": func() Journal { return new(MemoryJournal) },
		"file": func() Journal {
			j, err := OpenJournal(filepath.Join(t.TempDir(), "journal"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { j.Close() })
			return j
		},
	}
}

// testEntry returns a journal entry whose reference and init key are
// derived from n, so that distinct n give distinct fields.
func testEntry(n int) Entry {
	return Entry{
		Ref:      mls.HashReference(fill(refSize, 'r', n)),
		InitKey:  mls.HPKEPublicKey(fill(initKeySize, 'i', n)),
		NotAfter: 1 << 40,
	}
}

func fill(size int, tag byte, n int) []byte {
	b := bytes.Repeat([]byte{tag}, size)
	copy(b, fmt.Sprint(n))
	return b
}

func TestJournal(t *testing.T) {
	e := testEntry(1)
	for name, open := range testJournals(t) {
		t.Run(name, func(t *testing.T) {
			j := open()
			if ok, err := j.Consumed(e); err != nil || ok {
				t.Fatalf("Consumed on a fresh journal = %v, %v", ok, err)
			}
			if err := j.Record(e); err != nil {
				t.Fatal(err)
			}
			if got, ok, err := j.Lookup(e.Ref); err != nil || !ok || got.NotAfter != e.NotAfter || !bytes.Equal(got.InitKey, e.InitKey) {
				t.Fatalf("Lookup = %+v, %v, %v; want %+v", got, ok, err, e)
			}
			// Either field alone marks a key package consumed.
			for _, probe := range []Entry{
				{Ref: e.Ref},
				{Ref: testEntry(2).Ref, InitKey: e.InitKey},
			} {
				if ok, err := j.Consumed(probe); err != nil || !ok {
					t.Fatalf("Consumed(%+v) = %v, %v; want true", probe, ok, err)
				}
			}
			if ok, _ := j.Consumed(testEntry(2)); ok {
				t.Fatal("Consumed reports an entry that was never recorded")
			}
			// Recording twice is not an error.
			if err := j.Record(e); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestFileJournalSurvivesRestart is the reason the Journal exists: a
// directory rebuilt from one must refuse to re-serve a spent key
// package, and must still route a Welcome for it.
func TestFileJournalSurvivesRestart(t *testing.T) {
	name := filepath.Join(t.TempDir(), "journal")
	e := testEntry(1)

	j, err := OpenJournal(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Record(e); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenJournal(name)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if ok, err := reopened.Consumed(e); err != nil || !ok {
		t.Fatalf("Consumed after reopen = %v, %v; the record did not survive", ok, err)
	}
	if got, ok, _ := reopened.Lookup(e.Ref); !ok || got.NotAfter != e.NotAfter {
		t.Fatalf("Lookup after reopen = %+v, %v; the lifetime did not survive", got, ok)
	}
}

// TestFileJournalTornTail checks that a record written after a crash
// that tore the previous one is not glued onto the fragment, where it
// would parse as some other reference or not at all, and the key
// package it records could then be served again after a restart.
func TestFileJournalTornTail(t *testing.T) {
	good := testEntry(1)
	line := fmt.Sprintf("%x %x %d\n", []byte(good.Ref), []byte(good.InitKey), good.NotAfter)
	torn := testEntry(2)
	tornLine := fmt.Sprintf("%x %x %d\n", []byte(torn.Ref), []byte(torn.InitKey), torn.NotAfter)
	for _, tt := range []struct {
		name string
		file string
	}{
		{"short fragment", "a1b2c3"},
		{"after a good line", line + "a1b2"},
		{"half a reference", line + tornLine[:refSize]},
		{"whole reference", line + tornLine[:2*refSize]},
		{"cut in the lifetime", line + tornLine[:len(tornLine)-3]},
	} {
		t.Run(tt.name, func(t *testing.T) {
			name := filepath.Join(t.TempDir(), "journal")
			if err := os.WriteFile(name, []byte(tt.file), 0o600); err != nil {
				t.Fatal(err)
			}
			j, err := OpenJournal(name)
			if err != nil {
				t.Fatal(err)
			}
			e := testEntry(3)
			if err := j.Record(e); err != nil {
				t.Fatal(err)
			}
			j.Close()

			j, err = OpenJournal(name)
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			if got, ok, _ := j.Lookup(e.Ref); !ok || got.NotAfter != e.NotAfter {
				b, _ := os.ReadFile(name)
				t.Fatalf("record after a torn tail lost: Lookup = %+v, %v; file %q", got, ok, b)
			}
			if ok, _ := j.Consumed(torn); ok {
				t.Error("a torn record was read back as a whole one")
			}
		})
	}
}

// TestFileJournalTornWhileOpen checks the torn tail a write can leave
// without a crash: a write that fails part way, on a full disk, say,
// leaves a fragment behind that load never gets the chance to cut off.
// The next record was appended to the fragment, the merged line did not
// parse on the next open, and the key package it recorded was served
// again.
func TestFileJournalTornWhileOpen(t *testing.T) {
	name := filepath.Join(t.TempDir(), "journal")
	j, err := OpenJournal(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Record(testEntry(1)); err != nil {
		t.Fatal(err)
	}
	// What a short write leaves: part of a line, and no newline.
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(fmt.Sprintf("%x", []byte(testEntry(2).Ref))); err != nil {
		t.Fatal(err)
	}
	f.Close()

	e := testEntry(3)
	if err := j.Record(e); err != nil {
		t.Fatal(err)
	}
	j.Close()

	j, err = OpenJournal(name)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	for _, want := range []Entry{testEntry(1), e} {
		if ok, _ := j.Consumed(want); !ok {
			b, _ := os.ReadFile(name)
			t.Fatalf("entry %x lost after a torn write; file %q", want.Ref[:4], b)
		}
	}
	if ok, _ := j.Consumed(testEntry(2)); ok {
		t.Error("a torn record was read back as a whole one")
	}
}

// TestFileJournalLines checks what load accepts: a whole line of the
// current format, a line of the older reference-only format, and
// nothing whose fields are the wrong size.
func TestFileJournalLines(t *testing.T) {
	e := testEntry(1)
	old := testEntry(2)
	short := testEntry(3)
	file := fmt.Sprintf("%x %x %d\n", []byte(e.Ref), []byte(e.InitKey), e.NotAfter) +
		fmt.Sprintf("%x\n", []byte(old.Ref))
	name := filepath.Join(t.TempDir(), "journal")
	if err := os.WriteFile(name, []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	j, err := OpenJournal(name)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	for _, tt := range []struct {
		name string
		e    Entry
		want bool
	}{
		{"current format", e, true},
		{"reference-only format", Entry{Ref: old.Ref}, true},
		{"short reference", Entry{Ref: short.Ref[1:]}, false},
	} {
		if ok, _ := j.Consumed(tt.e); ok != tt.want {
			t.Errorf("%s: Consumed = %v, want %v", tt.name, ok, tt.want)
		}
	}
	if err := j.Record(Entry{Ref: mls.HashReference("short")}); err == nil {
		t.Error("Record accepted an entry that load would not read back")
	}
}

func TestJournalConcurrent(t *testing.T) {
	for name, open := range testJournals(t) {
		t.Run(name, func(t *testing.T) {
			j := open()
			const n = 64
			var wg sync.WaitGroup
			for i := range n {
				wg.Go(func() {
					if err := j.Record(testEntry(i)); err != nil {
						t.Error(err)
					}
				})
			}
			wg.Wait()
			for i := range n {
				if ok, err := j.Consumed(testEntry(i)); err != nil || !ok {
					t.Fatalf("entry %d: Consumed = %v, %v", i, ok, err)
				}
			}
		})
	}
}

func TestJournalCorruption(t *testing.T) {
	for _, line := range []string{"not hex at all\n", "\n", "abcd\n"} {
		name := filepath.Join(t.TempDir(), "journal")
		if err := os.WriteFile(name, []byte(line), 0600); err != nil {
			t.Fatal(err)
		}
		if j, err := OpenJournal(name); err == nil {
			j.Close()
			t.Fatalf("accepted corrupt record %q", line)
		}
	}
}
