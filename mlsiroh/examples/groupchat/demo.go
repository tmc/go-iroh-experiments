// Groupchat demonstrates serialized external admission, signing-key rotation,
// and encrypted application messages over two local iroh endpoints.
package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"time"

	"github.com/tmc/go-iroh-experiments/mlsiroh"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/mls"
)

const demoALPN = "mlsiroh/example/groupchat/1"
const maxMessage = 1 << 20

type demoRequest struct {
	Op    string
	Token [32]byte
	Wire  []byte
}
type demoResponse struct {
	Admission *mlsiroh.Admission
	Receipt   *mlsiroh.Receipt
	Wire      []byte
	Error     string
}

func runDemo() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	aliceKey, err := key.GenerateSecretKey()
	if err != nil {
		return err
	}
	bobKey, err := key.GenerateSecretKey()
	if err != nil {
		return err
	}
	alice, err := iroh.Bind(ctx, iroh.WithSecretKey(aliceKey), iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		return err
	}
	defer alice.Shutdown(context.Background())
	bob, err := iroh.Bind(ctx, iroh.WithSecretKey(bobKey), iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		return err
	}
	defer bob.Shutdown(context.Background())
	ac, err := mlsiroh.NewClient(aliceKey, time.Hour)
	if err != nil {
		return err
	}
	bc, err := mlsiroh.NewClient(bobKey, time.Hour)
	if err != nil {
		return err
	}
	groupID := make([]byte, 32)
	if _, err := rand.Read(groupID); err != nil {
		return err
	}
	ag, err := ac.NewGroup(groupID, nil)
	if err != nil {
		return err
	}
	owner, err := mlsiroh.NewSession(ag)
	if err != nil {
		return err
	}
	handler := iroh.ProtocolHandlerFunc(func(ctx context.Context, c *iroh.Conn) error {
		select {
		case <-c.HandshakeComplete():
		case <-ctx.Done():
			return ctx.Err()
		}
		// This example has an explicit endpoint allowlist; transport authentication
		// alone grants no right to join or send MLS proposals.
		if !c.RemoteID().Equal(bob.ID()) {
			return mlsiroh.ErrWrongEndpoint
		}
		stream, err := c.AcceptStream(ctx)
		if err != nil {
			return err
		}
		defer stream.Close()
		stream.SetDeadline(time.Now().Add(10 * time.Second))
		wire, err := io.ReadAll(io.LimitReader(stream, maxMessage+1))
		if err != nil {
			return err
		}
		if len(wire) > maxMessage {
			return fmt.Errorf("demoRequest too large")
		}
		var req demoRequest
		if err := json.Unmarshal(wire, &req); err != nil {
			return err
		}
		res := demoResponse{}
		switch req.Op {
		case "reserve":
			a, e := owner.Reserve(c.RemoteID(), time.Now().Add(10*time.Second))
			err = e
			res.Admission = &a
		case "join":
			r, e := owner.Accept(req.Token, c.RemoteID(), req.Wire)
			err = e
			res.Receipt = &r
		case "rotate":
			var m mls.Message
			if err = mls.Unmarshal(req.Wire, &m); err == nil {
				_, err = owner.Handle(&m)
			}
			if err == nil {
				var commit *mls.Message
				commit, _, err = owner.Commit(nil)
				if err == nil {
					res.Wire, err = mls.Marshal(commit)
				}
			}
		case "message":
			var m mls.Message
			if err = mls.Unmarshal(req.Wire, &m); err == nil {
				var content *mls.AuthenticatedContent
				content, err = owner.Handle(&m)
				if err == nil && content.Content.ContentType != mls.ContentTypeApplication {
					err = fmt.Errorf("expected application message")
				}
				if err == nil {
					fmt.Printf("alice read: %s\n", content.Content.ApplicationData)
				}
			}
			if err == nil {
				var reply *mls.Message
				reply, err = owner.Protect([]byte("hello bob"))
				if err == nil {
					res.Wire, err = mls.Marshal(reply)
				}
			}
		default:
			err = fmt.Errorf("unknown operation")
		}
		if err != nil {
			res.Error = err.Error()
		}
		if err := json.NewEncoder(stream).Encode(res); err != nil {
			return err
		}
		return stream.CloseWrite()
	})
	router, err := iroh.NewRouter(alice, map[string]iroh.ProtocolHandler{demoALPN: handler}, nil)
	if err != nil {
		return err
	}
	defer router.Shutdown(context.Background())
	exchange := func(req demoRequest) (demoResponse, error) {
		c, err := bob.Connect(ctx, alice.Addr(), demoALPN)
		if err != nil {
			return demoResponse{}, err
		}
		defer c.Close()
		if !c.RemoteID().Equal(alice.ID()) {
			return demoResponse{}, mlsiroh.ErrWrongEndpoint
		}
		st, err := c.OpenStreamSync(ctx)
		if err != nil {
			return demoResponse{}, err
		}
		defer st.Close()
		st.SetDeadline(time.Now().Add(10 * time.Second))
		if err := json.NewEncoder(st).Encode(req); err != nil {
			return demoResponse{}, err
		}
		if err := st.CloseWrite(); err != nil {
			return demoResponse{}, err
		}
		wire, err := io.ReadAll(io.LimitReader(st, maxMessage+1))
		if err != nil {
			return demoResponse{}, err
		}
		if len(wire) > maxMessage {
			return demoResponse{}, fmt.Errorf("demoResponse too large")
		}
		var res demoResponse
		if err := json.Unmarshal(wire, &res); err != nil {
			return res, err
		}
		if res.Error != "" {
			return res, fmt.Errorf("owner: %s", res.Error)
		}
		return res, nil
	}
	res, err := exchange(demoRequest{Op: "reserve"})
	if err != nil {
		return err
	}
	if res.Admission == nil {
		return fmt.Errorf("missing admission")
	}
	admission := res.Admission
	// GroupInfo was obtained from the authenticated owner. Check its signer
	// binding too before using the MLS external-join machinery.
	var tree mls.RatchetTree
	if ok, err := admission.Info.Extensions.Decode(mls.ExtensionTypeRatchetTree, &tree); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("missing ratchet tree")
	}
	signer, err := mlsiroh.VerifyLeaf(tree.Leaf(mls.LeafIndex(admission.Info.Signer)))
	if err != nil {
		return err
	}
	if !signer.Equal(alice.ID()) {
		return mlsiroh.ErrWrongEndpoint
	}
	provisional, commit, err := bc.JoinExternal(admission.Info, tree, nil)
	if err != nil {
		return err
	}
	wire, err := mls.Marshal(commit)
	if err != nil {
		return err
	}
	res, err = exchange(demoRequest{Op: "join", Token: admission.Token, Wire: wire})
	if err != nil {
		return err
	}
	if res.Receipt == nil || !res.Receipt.Matches(provisional, wire) {
		return fmt.Errorf("commit was not acknowledged")
	}
	member, err := mlsiroh.NewSession(provisional)
	if err != nil {
		return err
	}
	fmt.Printf("bob joined accepted epoch %d\n", res.Receipt.Epoch)
	proposal, err := member.Rotate(bobKey)
	if err != nil {
		return err
	}
	wire, err = mls.Marshal(proposal)
	if err != nil {
		return err
	}
	res, err = exchange(demoRequest{Op: "rotate", Wire: wire})
	if err != nil {
		return err
	}
	var accepted mls.Message
	if err := mls.Unmarshal(res.Wire, &accepted); err != nil {
		return err
	}
	if _, err := member.Handle(&accepted); err != nil {
		return err
	}
	fmt.Println("bob activated fresh encryption and signing keys")
	message, err := member.Protect([]byte("hello alice after rotation"))
	if err != nil {
		return err
	}
	wire, err = mls.Marshal(message)
	if err != nil {
		return err
	}
	res, err = exchange(demoRequest{Op: "message", Wire: wire})
	if err != nil {
		return err
	}
	if err := mls.Unmarshal(res.Wire, &accepted); err != nil {
		return err
	}
	content, err := member.Handle(&accepted)
	if err != nil {
		return err
	}
	fmt.Printf("bob read: %s\n", content.Content.ApplicationData)
	return nil
}
