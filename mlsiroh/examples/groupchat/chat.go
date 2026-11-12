package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/tmc/go-iroh-experiments/mlsiroh"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/mls"
	"io"
	"net/netip"
	"os"
	"sync"
	"time"
)

const chatALPN = "mlsiroh/example/chat/1"
const queueLimit = 16

type invitation struct {
	Owner   key.EndpointID
	Member  key.EndpointID
	IPs     []netip.AddrPort
	Token   [32]byte
	Expires time.Time
	Info    []byte
}
type chatRequest struct {
	Seq   uint64
	Ack   uint64
	Op    string
	Token [32]byte
	Wire  []byte
}
type event struct {
	ID   uint64
	Wire []byte
}
type chatResponse struct {
	Receipt *mlsiroh.Receipt
	Events  []event
	Error   string
}
type ownerState struct {
	mu       sync.Mutex
	session  *mlsiroh.Session
	member   key.EndpointID
	token    [32]byte
	receipt  *mlsiroh.Receipt
	joinHash [32]byte
	seq      uint64
	lastHash [32]byte
	last     chatResponse
	events   []event
	eventID  uint64
	out      io.Writer
}

func runOwner(ctx context.Context, ep *iroh.Endpoint, sk key.SecretKey, member key.EndpointID, name string, in io.Reader, out io.Writer) error {
	client, err := mlsiroh.NewClient(sk, time.Hour)
	if err != nil {
		return err
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return err
	}
	g, err := client.NewGroup(id, nil)
	if err != nil {
		return err
	}
	session, err := mlsiroh.NewSession(g)
	if err != nil {
		return err
	}
	a, err := session.Reserve(member, time.Now().Add(10*time.Minute))
	if err != nil {
		return err
	}
	info, err := mls.Marshal(&mls.Message{Version: mls.Version10, WireFormat: mls.WireFormatGroupInfo, GroupInfo: a.Info})
	if err != nil {
		return err
	}
	inv := invitation{Owner: ep.ID(), Member: member, IPs: ep.Addr().IPAddrs(), Token: a.Token, Expires: a.Expires, Info: info}
	state := &ownerState{session: session, member: member, token: a.Token, out: out}
	router, err := iroh.NewRouter(ep, map[string]iroh.ProtocolHandler{chatALPN: iroh.ProtocolHandlerFunc(state.accept)}, nil)
	if err != nil {
		return err
	}
	defer router.Shutdown(context.Background())
	b, err := json.MarshalIndent(inv, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "invitation ready: %s\ncommands: /quit; type a message after member joins\n", name)
	lines := input(ctx, in)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case line, ok := <-lines:
			if !ok {
				return nil
			}
			if line.err != nil {
				return line.err
			}
			if line.text == "/quit" {
				return nil
			}
			if line.text == "" {
				continue
			}
			state.mu.Lock()
			if state.receipt == nil {
				fmt.Fprintln(out, "member has not joined")
			} else if len(state.events) >= queueLimit {
				fmt.Fprintln(out, "member is behind; wait for acknowledgment")
			} else {
				m, e := session.Protect([]byte(line.text))
				if e == nil {
					var wire []byte
					wire, e = mls.Marshal(m)
					if e == nil {
						state.enqueue(wire)
					}
				}
				if e != nil {
					fmt.Fprintln(out, e)
				}
			}
			state.mu.Unlock()
		}
	}
}
func (s *ownerState) enqueue(wire []byte) {
	s.eventID++
	s.events = append(s.events, event{ID: s.eventID, Wire: wire})
}
func (s *ownerState) accept(ctx context.Context, c *iroh.Conn) error {
	select {
	case <-c.HandshakeComplete():
	case <-ctx.Done():
		return ctx.Err()
	}
	if !c.RemoteID().Equal(s.member) {
		return mlsiroh.ErrWrongEndpoint
	}
	st, err := c.AcceptStream(ctx)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.SetDeadline(deadline(ctx)); err != nil {
		return err
	}
	var req chatRequest
	if err := readJSON(st, &req); err != nil {
		return err
	}
	s.mu.Lock()
	res := s.process(req)
	s.mu.Unlock()
	if err := json.NewEncoder(st).Encode(res); err != nil {
		return err
	}
	return st.CloseWrite()
}
func (s *ownerState) process(req chatRequest) chatResponse {
	fail := func(err error) chatResponse { return chatResponse{Error: err.Error()} }
	if req.Op == "join" {
		h := sha256.Sum256(req.Wire)
		if req.Token != s.token {
			return fail(fmt.Errorf("wrong invitation"))
		}
		if s.receipt != nil {
			if h != s.joinHash {
				return fail(fmt.Errorf("different join already accepted"))
			}
			return chatResponse{Receipt: s.receipt}
		}
		r, err := s.session.Accept(req.Token, s.member, req.Wire)
		if err != nil {
			return fail(err)
		}
		s.receipt = &r
		s.joinHash = h
		fmt.Fprintf(s.out, "member joined epoch %d\n", r.Epoch)
		return chatResponse{Receipt: &r}
	}
	if s.receipt == nil {
		return fail(fmt.Errorf("join first"))
	}
	b, _ := json.Marshal(req)
	h := sha256.Sum256(b)
	if req.Seq == s.seq {
		if h != s.lastHash {
			return fail(fmt.Errorf("request sequence reused"))
		}
		return s.last
	}
	if req.Seq != s.seq+1 {
		return fail(fmt.Errorf("request out of order"))
	}
	if req.Ack > s.eventID {
		return fail(fmt.Errorf("invalid acknowledgment"))
	}
	for len(s.events) > 0 && s.events[0].ID <= req.Ack {
		s.events = s.events[1:]
	}
	var err error
	switch req.Op {
	case "poll":
	case "message", "rotate":
		if req.Op == "rotate" && len(s.events) >= queueLimit {
			err = fmt.Errorf("delivery queue full")
			break
		}
		var m mls.Message
		if err = mls.Unmarshal(req.Wire, &m); err != nil {
			break
		}
		var content *mls.AuthenticatedContent
		kind := mls.ContentTypeApplication
		if req.Op == "rotate" {
			kind = mls.ContentTypeProposal
		}
		content, err = s.session.Receive(s.member, &m, kind)
		if err != nil {
			break
		}
		if req.Op == "message" {
			if content.Content.ContentType != mls.ContentTypeApplication {
				err = fmt.Errorf("expected application message")
				break
			}
			fmt.Fprintf(s.out, "member: %s\n", content.Content.ApplicationData)
		} else {
			if content.Content.ContentType != mls.ContentTypeProposal || content.Content.Proposal.Type != mls.ProposalTypeUpdate {
				err = fmt.Errorf("expected update proposal")
				break
			}
			var commit *mls.Message
			commit, _, err = s.session.Commit(nil)
			if err == nil {
				var wire []byte
				wire, err = mls.Marshal(commit)
				if err == nil {
					s.enqueue(wire)
				}
			}
		}
	default:
		err = fmt.Errorf("unknown operation")
	}
	res := chatResponse{Events: append([]event(nil), s.events...)}
	if err != nil {
		res.Error = err.Error()
	}
	// Handling may consume a ratchet even on error. Retry the cached response.
	s.seq = req.Seq
	s.lastHash = h
	s.last = res
	return res
}
func exchange(ctx context.Context, ep *iroh.Endpoint, addr netaddr.EndpointAddr, req chatRequest) (chatResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	c, err := ep.Connect(ctx, addr, chatALPN)
	if err != nil {
		return chatResponse{}, err
	}
	defer c.Close()
	if !c.RemoteID().Equal(addr.ID) {
		return chatResponse{}, mlsiroh.ErrWrongEndpoint
	}
	st, err := c.OpenStreamSync(ctx)
	if err != nil {
		return chatResponse{}, err
	}
	defer st.Close()
	if err := st.SetDeadline(deadline(ctx)); err != nil {
		return chatResponse{}, err
	}
	stop := context.AfterFunc(ctx, func() { st.CancelRead(0); st.CancelWrite(0) })
	defer stop()
	if err := json.NewEncoder(st).Encode(req); err != nil {
		return chatResponse{}, err
	}
	if err := st.CloseWrite(); err != nil {
		return chatResponse{}, err
	}
	var res chatResponse
	err = readJSON(st, &res)
	return res, err
}
func retry(ctx context.Context, ep *iroh.Endpoint, addr netaddr.EndpointAddr, req chatRequest, out io.Writer) (chatResponse, error) {
	announced := false
	for {
		res, err := exchange(ctx, ep, addr, req)
		if err == nil {
			if announced {
				fmt.Fprintln(out, "connection restored")
			}
			return res, nil
		}
		if ctx.Err() != nil {
			return chatResponse{}, ctx.Err()
		}
		if !announced {
			fmt.Fprintln(out, "connection interrupted; retrying same request")
			announced = true
		}
		select {
		case <-ctx.Done():
			return chatResponse{}, ctx.Err()
		case <-time.After(time.Second):
		}
	}
}
func runMember(ctx context.Context, ep *iroh.Endpoint, sk key.SecretKey, name string, in io.Reader, out io.Writer) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	var inv invitation
	err = readJSON(f, &inv)
	f.Close()
	if err != nil {
		return err
	}
	if !inv.Member.Equal(ep.ID()) {
		return mlsiroh.ErrWrongEndpoint
	}
	if !time.Now().Before(inv.Expires) {
		return fmt.Errorf("invitation expired")
	}
	addr := netaddr.NewEndpointAddr(inv.Owner)
	for _, ip := range inv.IPs {
		addr = addr.WithIP(ip)
	}
	var info mls.Message
	if err := mls.Unmarshal(inv.Info, &info); err != nil {
		return err
	}
	if info.GroupInfo == nil {
		return fmt.Errorf("missing group info")
	}
	var tree mls.RatchetTree
	if ok, err := info.GroupInfo.Extensions.Decode(mls.ExtensionTypeRatchetTree, &tree); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("missing ratchet tree")
	}
	leaf := tree.Leaf(mls.LeafIndex(info.GroupInfo.Signer))
	if leaf == nil {
		return fmt.Errorf("missing signer")
	}
	signer, err := mlsiroh.VerifyLeaf(leaf)
	if err != nil {
		return err
	}
	if !signer.Equal(inv.Owner) {
		return mlsiroh.ErrWrongEndpoint
	}
	client, err := mlsiroh.NewClient(sk, time.Hour)
	if err != nil {
		return err
	}
	provisional, commit, err := client.JoinExternal(info.GroupInfo, tree, nil)
	if err != nil {
		return err
	}
	wire, err := mls.Marshal(commit)
	if err != nil {
		return err
	}
	res, err := retry(ctx, ep, addr, chatRequest{Op: "join", Token: inv.Token, Wire: wire}, out)
	if err != nil {
		return err
	}
	if res.Error != "" {
		return fmt.Errorf("owner: %s", res.Error)
	}
	if res.Receipt == nil || !res.Receipt.Matches(provisional, wire) {
		return fmt.Errorf("join not acknowledged")
	}
	session, err := mlsiroh.NewSession(provisional)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "joined epoch %d\ncommands: /rotate, /quit; type a message\n", res.Receipt.Epoch)
	lines := input(ctx, in)
	poll := time.NewTicker(200 * time.Millisecond)
	defer poll.Stop()
	var seq, ack uint64
	for {
		req := chatRequest{Op: "poll"}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-poll.C:
		case line, ok := <-lines:
			if !ok {
				return nil
			}
			if line.err != nil {
				return line.err
			}
			if line.text == "/quit" {
				return nil
			}
			if line.text == "" {
				continue
			}
			var m *mls.Message
			if line.text == "/rotate" {
				req.Op = "rotate"
				m, err = session.Rotate(sk)
			} else {
				req.Op = "message"
				m, err = session.Protect([]byte(line.text))
			}
			if err != nil {
				return err
			}
			req.Wire, err = mls.Marshal(m)
			if err != nil {
				return err
			}
		}
		seq++
		req.Seq = seq
		req.Ack = ack
		res, err := retry(ctx, ep, addr, req, out)
		if err != nil {
			return err
		}
		if res.Error != "" {
			return fmt.Errorf("owner: %s", res.Error)
		}
		for _, e := range res.Events {
			if e.ID <= ack {
				continue
			}
			if e.ID != ack+1 {
				return fmt.Errorf("delivery gap")
			}
			var m mls.Message
			if err := mls.Unmarshal(e.Wire, &m); err != nil {
				return err
			}
			content, err := session.Handle(&m)
			if err != nil {
				return err
			}
			switch content.Content.ContentType {
			case mls.ContentTypeApplication:
				fmt.Fprintf(out, "owner: %s\n", content.Content.ApplicationData)
			case mls.ContentTypeCommit:
				fmt.Fprintln(out, "rotation accepted")
			default:
				return fmt.Errorf("unexpected delivery")
			}
			ack = e.ID
		}
	}
}
