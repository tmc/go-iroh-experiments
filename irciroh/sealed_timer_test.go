package irciroh

import (
	"context"
	"testing"
	"time"
)

// TestNetworkSealedRotationRoles stages a founder proposal at a member
// before its timer fires. The member must leave committing to the founder.
func TestNetworkSealedRotationRoles(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	for _, name := range []string{"timer", "flush"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			founder, member := sealedPair(t, ctx)
			memberEvents := events(t, member)
			before := founder.seal.epoch()
			proposal, err := founder.seal.proposeRotation()
			if err != nil {
				t.Fatal(err)
			}
			member.seal.mu.Lock()
			member.seal.open(proposal, time.Now())
			member.seal.mu.Unlock()
			if got := member.seal.staged(); got != 1 {
				t.Fatalf("member staged %d leaves, want 1", got)
			}
			switch name {
			case "timer":
				member.rotateSoon()
			case "flush":
				if err := member.seal.flush(ctx); err != nil {
					t.Fatal(err)
				}
			}
			if got := member.seal.epoch(); got != before {
				t.Fatalf("member committed a founder proposal: epoch %d, want %d", got, before)
			}
			// The founder's timer must still commit a member's pending rotation.
			proposal, err = member.seal.proposeRotation()
			if err != nil {
				t.Fatal(err)
			}
			founder.seal.mu.Lock()
			founder.seal.open(proposal, time.Now())
			founder.seal.mu.Unlock()
			founder.rotateSoon()
			waitFor(t, ctx, func() bool { return member.seal.epoch() == before+1 }, "member applying founder timer commit")
			if got := founder.seal.epoch(); got != before+1 {
				t.Fatalf("founder epoch %d, want %d", got, before+1)
			}
			if err := founder.Say(ctx, "after timer rotation"); err != nil {
				t.Fatal(err)
			}
			ev := await(t, ctx, memberEvents, ofKind(Message), "member reading after timer rotation")
			if ev.Text != "after timer rotation" {
				t.Fatalf("message %q", ev.Text)
			}
		})
	}
}
