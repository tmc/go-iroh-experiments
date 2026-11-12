package main

import (
	"bytes"
	"context"
	"testing"
	"time"
)

// TestBridgeProcessBanSurvivesRestart checks moderation through real IRC
// commands. Surviving members exchange messages after the removal commit,
// and a restarted founder still refuses the kicked endpoint while admitting
// an unbanned holder of the same invitation.
func TestBridgeProcessBanSurvivesRestart(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	founderState := t.TempDir()
	addr, stopFounder := startServeProcessState(t, ctx, founderState)
	alice := dialIRC(t, addr)
	alice.register("alice")
	alice.send("JOIN #moderated seal")
	alice.expect("alice!", "JOIN #moderated")
	ticket := processTicket(t, alice, "#moderated")

	memberState := t.TempDir()
	addr, stopBob := startServeProcessState(t, ctx, memberState)
	bob := dialIRC(t, addr)
	bob.register("bob")
	bob.send("JOIN #moderated " + ticket.String())
	bob.expect("bob!", "JOIN #moderated")
	alice.expect("NICK", "bob")
	carol := dialIRC(t, startServeProcess(t, ctx))
	carol.register("carol")
	carol.send("JOIN #moderated " + ticket.String())
	carol.expect("carol!", "JOIN #moderated")
	alice.expect("NICK", "carol")
	bob.send("PRIVMSG #moderated :admitted before kick")
	alice.expect("bob!", "PRIVMSG #moderated", "admitted before kick")

	alice.send("KICK #moderated bob :removed by founder")
	alice.expect("KICK #moderated bob", "removed by founder")
	alice.send("PRIVMSG #moderated :remaining members after kick")
	carol.expect("alice!", "PRIVMSG #moderated", "remaining members after kick")
	carol.send("PRIVMSG #moderated :reply after removal commit")
	alice.expect("carol!", "PRIVMSG #moderated", "reply after removal commit")
	stopBob()
	stopFounder()

	addr, _ = startServeProcessState(t, ctx, founderState)
	alice = dialIRC(t, addr)
	alice.register("alice")
	alice.send("JOIN #moderated")
	alice.expect(" 353 ", "#moderated", "@alice")
	after := processTicket(t, alice, "#moderated")
	if ticket.Founder != after.Founder || !bytes.Equal(ticket.Secret, after.Secret) {
		t.Fatal("founder restart changed the channel identity")
	}
	// Retain the credential, updating only the restarted transport's hints.
	ticket.Peers = after.Peers
	addr, _ = startServeProcessState(t, ctx, memberState)
	bob = dialIRC(t, addr)
	bob.register("bob")
	bob.send("JOIN #moderated " + ticket.String())
	bob.expect(" 403 ", "#moderated", "not invited")

	// Refusal alone could mean the restarted founder is unreachable. This
	// live, unbanned member must successfully rejoin with the same ticket.
	carol.send("PART #moderated")
	carol.expect("carol!", "PART #moderated")
	carol.send("JOIN #moderated " + ticket.String())
	carol.expect("carol!", "JOIN #moderated")
	carol.send("PRIVMSG #moderated :unbanned holder after restart")
	alice.expect("carol!", "PRIVMSG #moderated", "unbanned holder after restart")
	alice.send("PRIVMSG #moderated :ban retained and channel live")
	carol.expect("alice!", "PRIVMSG #moderated", "ban retained and channel live")
}

// TestBridgeProcessRejoinAfterMembershipChanges checks the documented
// recovery path: a stopped member misses membership commits and explicitly
// rejoins, using its existing endpoint identity and invitation to obtain the
// current group rather than replaying its absent MLS state.
func TestBridgeProcessRejoinAfterMembershipChanges(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	alice := dialIRC(t, startServeProcess(t, ctx))
	alice.register("alice")
	alice.send("JOIN #epochs seal")
	alice.expect("alice!", "JOIN #epochs")
	ticket := processTicket(t, alice, "#epochs")
	state := t.TempDir()
	addr, stopBob := startServeProcessState(t, ctx, state)
	bob := dialIRC(t, addr)
	bob.register("bob")
	bob.send("JOIN #epochs " + ticket.String())
	bob.expect("bob!", "JOIN #epochs")
	alice.expect("NICK", "bob")
	bob.send("PRIVMSG #epochs :before missed commits")
	alice.expect("bob!", "PRIVMSG #epochs", "before missed commits")
	stopBob()

	carol := dialIRC(t, startServeProcess(t, ctx))
	carol.register("carol")
	carol.send("JOIN #epochs " + ticket.String())
	carol.expect("carol!", "JOIN #epochs")
	alice.expect("NICK", "carol")
	carol.send("PRIVMSG #epochs :first membership change")
	alice.expect("carol!", "PRIVMSG #epochs", "first membership change")
	carol.send("PART #epochs")
	carol.expect("carol!", "PART #epochs")
	carol.send("JOIN #epochs " + ticket.String())
	carol.expect("carol!", "JOIN #epochs")
	carol.send("PRIVMSG #epochs :second membership change")
	alice.expect("carol!", "PRIVMSG #epochs", "second membership change")

	addr, _ = startServeProcessState(t, ctx, state)
	bob = dialIRC(t, addr)
	bob.register("bob")
	bob.send("JOIN #epochs " + ticket.String())
	bob.expect("bob!", "JOIN #epochs")
	bob.send("PRIVMSG #epochs :rejoined current group")
	alice.expect("bob!", "PRIVMSG #epochs", "rejoined current group")
	carol.expect("bob!", "PRIVMSG #epochs", "rejoined current group")
	alice.send("PRIVMSG #epochs :founder reply in current group")
	bob.expect("alice!", "PRIVMSG #epochs", "founder reply in current group")
	carol.send("PRIVMSG #epochs :member reply in current group")
	bob.expect("carol!", "PRIVMSG #epochs", "member reply in current group")
}
