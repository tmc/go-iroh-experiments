package tlogiroh

import (
	"github.com/tmc/go-iroh/gossip"
	"lukechampine.com/blake3"
)

// TopicID derives the gossip topic for a log from its origin string.
// All operators, witnesses, and clients of a log join the same topic.
func TopicID(origin string) gossip.TopicID {
	return gossip.TopicID(blake3.Sum256([]byte("tlogiroh/v1/" + origin)))
}

// Gossip envelope types. A topic message is one type byte followed by the
// payload: a signed checkpoint note message, or a marshaled Equivocation.
const (
	envCheckpoint   = 0x01
	envEquivocation = 0x02
)

func envelope(kind byte, payload []byte) []byte {
	msg := make([]byte, 1+len(payload))
	msg[0] = kind
	copy(msg[1:], payload)
	return msg
}

// openEnvelope splits a topic message into its type byte and payload.
// It reports ok=false for empty or unknown-type messages, which peers
// ignore.
func openEnvelope(msg []byte) (kind byte, payload []byte, ok bool) {
	if len(msg) < 2 {
		return 0, nil, false
	}
	switch msg[0] {
	case envCheckpoint, envEquivocation:
		return msg[0], msg[1:], true
	}
	return 0, nil, false
}
