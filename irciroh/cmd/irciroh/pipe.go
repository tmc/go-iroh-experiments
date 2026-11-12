package main

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// A pipe is one direction of an in-process connection: a queue of bytes
// with a reader at one end and a writer at the other, where the writer
// never waits.
//
// That is the whole reason this is not net.Pipe. A net.Pipe write
// blocks until somebody reads it, so two programs that each answer the
// other can stop: the bridge is writing a numeric that the chat has not
// read because the chat is writing a PONG that the bridge has not read.
// Over a socket the kernel's buffer hides this. Here the queue grows
// instead, which it can afford to do because the far end is a goroutine
// in this process rather than a network that can stall.
type pipe struct {
	mu     sync.Mutex
	wake   sync.Cond
	buf    []byte
	closed bool
}

func newPipe() *pipe {
	p := &pipe{}
	p.wake.L = &p.mu
	return p
}

func (p *pipe) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0, io.ErrClosedPipe
	}
	p.buf = append(p.buf, b...)
	p.wake.Broadcast()
	return len(b), nil
}

func (p *pipe) Read(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for len(p.buf) == 0 && !p.closed {
		p.wake.Wait()
	}
	// What was written before the close is still owed to the reader:
	// the last thing a bridge says is often the reason it is closing.
	if len(p.buf) == 0 {
		return 0, io.EOF
	}
	n := copy(b, p.buf)
	p.buf = p.buf[n:]
	return n, nil
}

func (p *pipe) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	p.wake.Broadcast()
	return nil
}

// A pipeConn is one end of a connection between two goroutines. It is
// what join and mcp put between their bridge and their chat, in place
// of the loopback socket the two would otherwise talk over: a socket on
// 127.0.0.1 is reachable by every other process on the machine, and the
// bridge has no authentication of its own, so an address is a way in
// that this arrangement does not need. A pipe has no address.
type pipeConn struct {
	r, w *pipe
}

// pipePair returns the two ends of one connection.
func pipePair() (net.Conn, net.Conn) {
	a, b := newPipe(), newPipe()
	return &pipeConn{r: a, w: b}, &pipeConn{r: b, w: a}
}

func (c *pipeConn) Read(b []byte) (int, error)  { return c.r.Read(b) }
func (c *pipeConn) Write(b []byte) (int, error) { return c.w.Write(b) }

// Close closes both directions, so that the far end reads what is left
// and then EOF.
func (c *pipeConn) Close() error {
	c.r.Close()
	return c.w.Close()
}

// pipeAddr is the address of something that has none.
type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

func (c *pipeConn) LocalAddr() net.Addr  { return pipeAddr{} }
func (c *pipeConn) RemoteAddr() net.Addr { return pipeAddr{} }

// errNoDeadline is returned rather than silently ignoring a deadline.
// Nothing on either side of this connection sets one - the bridge and
// the chat both read until the other end closes - and a connection that
// accepted a deadline and never honored it would be worse than one that
// says it cannot.
var errNoDeadline = errors.New("pipe: deadlines are not supported")

func (c *pipeConn) SetDeadline(time.Time) error      { return errNoDeadline }
func (c *pipeConn) SetReadDeadline(time.Time) error  { return errNoDeadline }
func (c *pipeConn) SetWriteDeadline(time.Time) error { return errNoDeadline }
