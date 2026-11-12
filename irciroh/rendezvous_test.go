package irciroh

import "testing"

func TestRendezvousKey(t *testing.T) {
	pub := rendezvousKey("#go", nil).Public().EndpointID()

	if got := rendezvousKey("#GO", nil).Public().EndpointID(); got != pub {
		t.Error("channel names differing only in case announce under different keys")
	}
	if got := rendezvousKey("#rust", nil).Public().EndpointID(); got == pub {
		t.Error("two channels announce under one key")
	}

	// A sealed channel must not be findable by name: the secret in the
	// derivation is what keeps its record readable only to those who
	// already hold a ticket, the same boundary the sealed topic draws.
	sealed := rendezvousKey("#go", []byte("invite secret")).Public().EndpointID()
	if sealed == pub {
		t.Fatal("a sealed channel announces under the key its name alone derives, publishing the roster the seal hides")
	}
	if other := rendezvousKey("#go", []byte("another secret")).Public().EndpointID(); other == sealed {
		t.Error("two sealed channels of one name announce under one key")
	}

	// The whole point is that everyone derives the same key from the
	// same inputs, without having talked to each other first.
	if again := rendezvousKey("#go", nil).Public().EndpointID(); again != pub {
		t.Error("derivation is not deterministic")
	}
}

func TestRendezvousKeyDiffersFromTopic(t *testing.T) {
	// The key is published; the topic is what the swarm gossips on.
	// Deriving one from the other would let anyone who can look up the
	// record derive the topic, which for a sealed channel is the thing
	// the secret is protecting.
	id := rendezvousKey("#go", []byte("s")).Public().EndpointID()
	topic := SealedTopicID("#go", id, []byte("s"))
	if [32]byte(topic) == id.Bytes() {
		t.Fatal("the rendezvous key and the topic are the same value")
	}
}
