package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The chat directory is the identity. It holds the nick and the key,
// and the node behind it belongs to the serve that opened it, so two
// agents pointed at one directory are not two speakers who collide -
// they are one speaker with two views, behaving as specified. Views
// are many per directory on purpose, because reading is safe; what is
// not safe is that nothing said so. An agent could not see its own
// nick, its own key, or that anything else was attached, which turned
// a doubled line into an exercise in reading somebody else's terminal.
//
// So this answers the three questions an agent has about itself, and
// is careful about the third: what it reports is what it counted.

type whoamiIn struct{}

type whoamiOut struct {
	Nick     string `json:"nick,omitempty" jsonschema:"the name this node answers to; a claim anybody can make, and not yours alone"`
	Key      string `json:"key,omitempty" jsonschema:"the endpoint this node speaks from, whole; the only identity that cannot be forged"`
	Dir      string `json:"dir" jsonschema:"the chat directory these tools are a view of; sharing it is sharing the identity above"`
	Chatting bool   `json:"chatting" jsonschema:"whether a chat is attached and sending what is written here"`
}

// whoami answers who this view speaks as. The nick and key are read
// from the directory rather than asked of the bridge, because not
// speaking IRC is the whole point of the directory.
func (m *mcpServer) whoami(ctx context.Context, req *mcp.CallToolRequest, in whoamiIn) (*mcp.CallToolResult, whoamiOut, error) {
	out := whoamiOut{Dir: m.root, Chatting: chatting(m.root)}
	// A directory no chat has attached to yet has neither file. That
	// is worth answering rather than failing: it is the same absence
	// the caller would otherwise discover by being nobody.
	if nick, err := chatNick(m.root); err == nil {
		out.Nick = nick
	}
	if key, err := chatKey(m.root); err == nil {
		out.Key = key
	}

	var b strings.Builder
	if out.Nick == "" && out.Key == "" {
		fmt.Fprintf(&b, "no chat has attached to %s yet, so this view has no identity\n", out.Dir)
		return text(b.String()), out, nil
	}
	fmt.Fprintf(&b, "%s[%s]\t%s\n", out.Nick, shortKey(out.Key), out.Dir)
	if !out.Chatting {
		b.WriteString("no chat is attached, so nothing sent from here leaves until one is\n")
	}
	// The count is the part that matters and the part that cannot be
	// had. A chat takes an exclusive lock on the directory, so one is
	// countable; a view takes nothing, so the views are not. Saying
	// how many are attached would be inventing a roster, and an agent
	// comparing an invented roster is the failure this tool exists to
	// end. So name what is true: anything else reading this directory
	// speaks as the line above, indistinguishably.
	b.WriteString("this identity belongs to the directory, not to this session: any other view of it sends as the same nick and the same key, and its lines are not marked apart from yours\n")
	return text(b.String()), out, nil
}
