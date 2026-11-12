package irciroh

import (
	"encoding/base32"
	"errors"
	"fmt"
	"strings"

	"github.com/tmc/go-iroh/endpointticket"
	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/postcard"
	"lukechampine.com/blake3"
)

// TicketKind is the string prefix of an irciroh channel ticket.
const TicketKind = "irciroh"

var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// ErrTicket is returned when a string is not a valid channel ticket.
var ErrTicket = errors.New("invalid channel ticket")

// TopicID returns the gossip topic for a channel. Every member of the
// channel derives the same topic from the folded name and the secret; a
// public channel has an empty secret.
func TopicID(channel string, secret []byte) gossip.TopicID {
	b := make([]byte, 0, 64+len(channel)+len(secret))
	b = append(b, "irciroh/channel/v1\n"...)
	b = append(b, Fold(channel)...)
	b = append(b, '\n')
	b = append(b, secret...)
	return gossip.TopicID(blake3.Sum256(b))
}

// SealedTopicID returns the gossip topic for a sealed channel, derived
// from the folded name, the founder, and the invite secret.
//
// The secret is in the derivation because the swarm does not hide who
// is in it, although the group's messages do: commits and proposals are
// encrypted like the text, but a subscriber is a gossip peer, learns the
// endpoint ids of the peers it connects to, and sees the timing, size,
// epoch and content type of every message. Deriving the topic from
// something only invitees hold is what keeps that from anyone without a
// ticket, and it is the same thing that hides a public channel with a
// secret.
//
// It costs the property an address-like topic had. A joiner the founder
// refuses gets an answer, because it reached the swarm; someone who
// never had the secret gets silence it cannot tell from a channel that
// does not exist. Members must also agree on the secret to meet at all,
// so rotating it is a new channel rather than a new key.
//
// The founder stays in the derivation so that two channels of the same
// name are distinct even if a secret is ever reused.
func SealedTopicID(channel string, founder key.EndpointID, secret []byte) gossip.TopicID {
	id := founder.Bytes()
	b := make([]byte, 0, 64+len(channel)+len(id)+len(secret))
	b = append(b, "irciroh/sealed/v2\n"...)
	b = append(b, Fold(channel)...)
	b = append(b, '\n')
	b = append(b, id[:]...)
	b = append(b, '\n')
	b = append(b, secret...)
	return gossip.TopicID(blake3.Sum256(b))
}

// names reports whether t identifies a particular channel rather than
// just a name. A ticket carrying a secret or a founder was given to
// this node for one channel; a bare one was made from a name somebody
// typed, and every channel of that name answers to it.
func (t Ticket) names() bool { return t.Sealed() || len(t.Secret) > 0 }

// topic returns the gossip topic the ticket names.
func (t Ticket) topic() gossip.TopicID {
	if t.Sealed() {
		return SealedTopicID(t.Channel, t.Founder, t.Secret)
	}
	return TopicID(t.Channel, t.Secret)
}

// A Ticket carries everything needed to join one channel: its name, the
// secret its topic is derived from, and addresses of peers already on it.
// A ticket for a public channel has no secret, so it is only a bootstrap
// hint; a ticket for a channel with a secret is an invitation.
//
// A ticket that names a Founder is for a sealed channel. The secret is
// both half of the topic derivation and what the founder checks before
// letting the holder into the group, so without it a holder can neither
// find the swarm nor be admitted to it. Such a ticket is a credential,
// and passing it on adds a member.
type Ticket struct {
	Channel string
	Secret  []byte
	Founder key.EndpointID
	Peers   []netaddr.EndpointAddr
}

// Sealed reports whether the ticket is for a sealed channel.
func (t Ticket) Sealed() bool { return !t.Founder.IsZero() }

// ticketWire is the postcard form of a Ticket. Peers are carried as
// endpoint-ticket payloads so addresses share go-iroh's codec. Founder
// is empty for a public channel.
type ticketWire struct {
	Version uint8
	Channel string
	Secret  []byte
	Founder []byte
	Peers   [][]byte
}

// Kind returns the ticket's kind prefix. It implements
// [endpointticket.TicketCodec].
func (t Ticket) Kind() string { return TicketKind }

// EncodeBytes returns the ticket's byte representation: a version, then
// the ticket's fields, in postcard.
func (t Ticket) EncodeBytes() []byte {
	var e postcard.Encoder
	e.Uint(wireVersion)
	e.String(t.Channel)
	e.BytesValue(t.Secret)
	if t.Sealed() {
		id := t.Founder.Bytes()
		e.BytesValue(id[:])
	} else {
		e.BytesValue(nil)
	}
	e.Uint(uint64(len(t.Peers)))
	for _, p := range t.Peers {
		e.BytesValue(endpointticket.New(p).EncodeBytes())
	}
	return e.Bytes()
}

// EncodeString returns the ticket's canonical string form: the kind prefix
// followed by lowercase base32 without padding.
func (t Ticket) EncodeString() string {
	return TicketKind + strings.ToLower(base32NoPad.EncodeToString(t.EncodeBytes()))
}

// String returns the encoded ticket string.
func (t Ticket) String() string { return t.EncodeString() }

// MarshalText implements [encoding.TextMarshaler].
func (t Ticket) MarshalText() ([]byte, error) { return []byte(t.String()), nil }

// UnmarshalText implements [encoding.TextUnmarshaler].
func (t *Ticket) UnmarshalText(text []byte) error {
	parsed, err := ParseTicket(string(text))
	if err != nil {
		return err
	}
	*t = parsed
	return nil
}

// ParseTicket parses the string form of a channel ticket. Every error
// it returns wraps [ErrTicket].
func ParseTicket(s string) (Ticket, error) {
	t, err := parseTicket(s)
	if err != nil {
		return Ticket{}, fmt.Errorf("parse ticket: %w: %w", ErrTicket, err)
	}
	return t, nil
}

func parseTicket(s string) (Ticket, error) {
	rest, ok := strings.CutPrefix(s, TicketKind)
	if !ok {
		return Ticket{}, fmt.Errorf("missing %q prefix", TicketKind)
	}
	b, err := base32NoPad.DecodeString(strings.ToUpper(rest))
	if err != nil {
		return Ticket{}, fmt.Errorf("base32: %w", err)
	}
	var w ticketWire
	if err := postcard.Unmarshal(b, &w); err != nil {
		return Ticket{}, err
	}
	if w.Version != wireVersion {
		return Ticket{}, fmt.Errorf("version %d", w.Version)
	}
	name, err := checkChannel(w.Channel)
	if err != nil {
		return Ticket{}, err
	}
	t := Ticket{Channel: name}
	if len(w.Secret) > 0 {
		t.Secret = w.Secret
	}
	if len(w.Founder) > 0 {
		id, err := key.EndpointIDFromSlice(w.Founder)
		if err != nil {
			return Ticket{}, fmt.Errorf("founder: %w", err)
		}
		t.Founder = id
	}
	for _, p := range w.Peers {
		et, err := endpointticket.DecodeBytes(p)
		if err != nil {
			return Ticket{}, fmt.Errorf("peer: %w", err)
		}
		t.Peers = append(t.Peers, et.Addr())
	}
	return t, nil
}
