package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tmc/go-iroh-experiments/irciroh"
)

// A chat attaches to a running bridge and keeps what it hears in plain
// files, one directory per channel:
//
//	<dir>/out            server notices and anything not about a channel
//	<dir>/in             lines appended here are raw IRC commands
//	<dir>/nick           the name this node answers to
//	<dir>/key            the endpoint this node speaks from
//	<dir>/#go/out        one line per message, oldest first
//	<dir>/#go/in         lines appended here are sent to #go
//	<dir>/#go/in.sent    how much of in has been sent
//
// A line whose sender is known is stamped with the endpoint it came
// from, in front of the rest:
//
//	@k=<key> 2026-09-19T08:30:11Z <tmc> hi
//
// A nick is a claim anyone can make - three members may all answer to
// tmc - and the key is the one thing in the line nobody else can
// write, so it is what a program here should compare. It rides in
// front as an IRCv3 tag block rather than inside the text because the
// text is the part people and their greps already read, and a line
// with nothing to stamp is written exactly as it always was.
//
// An in file is a queue. Beside it, in.sent holds how far into it a
// chat has sent, so a chat that starts sends what was appended while
// none was running and nothing that an earlier one already sent. These
// lines are commands with effects - a replayed PART leaves a channel, a
// replayed line says a thing twice - so the offset is written before a
// line is sent rather than after: a chat that dies between the two
// loses that line instead of saying it twice.
//
// An in file with no in.sent beside it was written before there was
// one, and nothing tells a command that was executed there from one
// that was not; a chat skips what such a file holds when it starts and
// says so on standard error, naming the file.
//
// The point is that nothing has to speak IRC to take part. Reading is
// tail or grep, sending is a shell redirect, and the log outlives the
// reader - which matters most for the readers this is for, since an
// agent's memory of a conversation does not survive its context but a
// file does. It is the arrangement ii has used for twenty years, with
// regular files in place of named pipes: a pipe with no reader blocks
// its writer, and a blocked agent is worse than a dropped line.
type chat struct {
	root string

	// wmu guards w, and is separate from mu on purpose. A write here
	// blocks until the far side reads, and the goroutine filing what
	// the far side says must not be waiting behind it: one lock for
	// both would have a chat stop reading while it was blocked writing,
	// and a bridge blocked writing its reply would never read what
	// unblocks it - each end waiting for the other. Over a socket the
	// kernel's buffer hides that, which is the worst way for it to be
	// true; over the pipe join wires its two halves with, nothing does.
	wmu sync.Mutex
	w   *bufio.Writer

	mu   sync.Mutex // guards nick and key
	nick string
	key  string
}

// chatPoll is how often the in files are checked for new lines. It is
// short enough to feel immediate to whoever is typing and long enough
// that an idle channel costs a handful of stats a second.
const chatPoll = 200 * time.Millisecond

// wrapTag marks a logged line that continues the one before it. A
// message too long for one envelope is sent as several, and without
// this the log shows somebody saying two things where they said one -
// which a reader cannot tell from two deliberate messages, and which
// the sender is never told happened.
//
// It is only ever set on lines this program split itself. A remote
// sender's split arrives as separate envelopes with nothing marking
// them, because there is nowhere in an envelope to say so; the log can
// be honest about its own wrapping and no more.
const wrapTag = "w"

// runChat attaches to a bridge and serves the directory until the
// context is canceled.
func runChat(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("chat", flag.ExitOnError)
	server := fs.String("server", "127.0.0.1:6667", "address of a running bridge")
	dir := fs.String("dir", "", "directory to keep the conversation in")
	nick := fs.String("nick", "", "nick to register with; the node's own by default")
	join := fs.String("join", "", "comma-separated channels to join on connect")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return fmt.Errorf("chat: -dir is required")
	}
	conn, err := net.Dial("tcp", *server)
	if err != nil {
		return fmt.Errorf("dial %s: %w", *server, err)
	}
	defer conn.Close()
	return serveChat(ctx, conn, *dir, *nick, *join)
}

// serveChat keeps dir in step with the bridge on conn until the context
// is canceled, and owns the directory for as long as it runs: two chats
// on one directory would file every line twice, so the lock is taken
// here and dropped when this returns.
//
// The conn is an IRC connection and nothing more. Whether it crossed a
// loopback socket from another process or is one end of a pipe to a
// bridge in this one is not something the directory records or this
// needs to know.
func serveChat(ctx context.Context, conn net.Conn, dir, nick, join string) error {
	lock, err := keepDir(dir)
	if err != nil {
		return err
	}
	defer lock.Close()
	return serveChatLocked(ctx, conn, dir, nick, join)
}

// keepDir takes the claim on a chat directory, creating it if it is not
// there, and says on standard error that this process has it.
//
// It is separate from serving so that a caller with something expensive
// to set up can ask first. Join and mcp both have: binding an endpoint
// dials the public relays and publishes an address to a public DNS, and
// doing that for a directory somebody else turns out to be keeping is
// noise on somebody else's network as well as this one's.
//
// The line is here rather than at either caller because here is where
// it becomes true.
func keepDir(dir string) (*os.File, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	lock, err := lockChat(dir)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "irciroh: keeping %s\n", dir)
	return lock, nil
}

// serveChatLocked is serveChat with the claim already taken. The caller
// holds it for as long as this runs.
func serveChatLocked(ctx context.Context, conn net.Conn, dir, nick, join string) error {
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	c := &chat{root: dir, w: bufio.NewWriter(conn)}
	// The command file exists from the start, because the first thing
	// a reader is likely to want is to join somewhere, and that is a
	// command rather than something said.
	makeIn(c.root)
	// A nick is only a registration formality here: one bridge process
	// is one identity, so the node keeps the nick it has and this is
	// the name used only if it has none. Sending a different one would
	// rename the node for everyone attached to it.
	name := nick
	if name == "" {
		name = "chat"
	}
	// The reader starts before a byte of registration goes out.
	// Registering is a conversation rather than a monologue: the
	// bridge answers CAP REQ while USER is still being written, and a
	// chat that waited until it had finished writing before it began
	// reading would be waiting for a reply the bridge cannot finish
	// sending. A socket's buffer hides that, which is the worst way
	// for it to be hidden - it holds until the day the greeting is a
	// little longer or the buffer a little smaller.
	lines := make(chan error, 1)
	go func() { lines <- c.read(conn) }()

	// The capability is asked for before registering because that is
	// when a server will grant one, and it is asked for without
	// waiting to be told it exists: a bridge that has it answers ACK,
	// one that has not answers NAK, and either way the END below
	// finishes registration. Without it the log records names and no
	// keys, which is a worse log rather than a broken one.
	if err := c.sendf("CAP REQ :%s", capMessageTags); err != nil {
		return err
	}
	if err := c.sendf("NICK %s", name); err != nil {
		return err
	}
	if err := c.sendf("USER %s 0 * :%s", name, name); err != nil {
		return err
	}
	if err := c.sendf("CAP END"); err != nil {
		return err
	}
	for _, ch := range strings.Split(join, ",") {
		if ch = strings.TrimSpace(ch); ch != "" {
			if err := c.sendf("JOIN %s", ch); err != nil {
				return err
			}
		}
	}
	go c.outbox(ctx)
	err := <-lines
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// sendf writes one IRC line.
func (c *chat) sendf(format string, args ...any) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if _, err := fmt.Fprintf(c.w, format+"\r\n", args...); err != nil {
		return err
	}
	return c.w.Flush()
}

// read copies the server's traffic into the directory until the
// connection ends.
func (c *chat) read(conn net.Conn) error {
	r := bufio.NewReaderSize(conn, maxLine)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		c.record(strings.TrimRight(line, "\r\n"))
	}
}

// record files one line from the server.
func (c *chat) record(line string) {
	from, key, cmd, params := split(line)
	// A line this does not recognize is filed as it stands, but with
	// the tag block taken off: the key it held is being carried
	// alongside now, and a reader should not have to find it twice.
	if _, rest, ok := cutTags(line); ok {
		line = rest
	}
	switch cmd {
	case "001":
		// The welcome names the nick the bridge registered, which is
		// the node's own rather than the one asked for.
		if len(params) > 0 {
			c.mu.Lock()
			c.nick = params[0]
			c.mu.Unlock()
			// The name is written down because a program reading
			// this directory has to know which lines are its own,
			// and it cannot ask the bridge without speaking IRC -
			// which is the one thing this directory exists to
			// spare it.
			os.WriteFile(filepath.Join(c.root, "nick"), []byte(params[0]+"\n"), 0o600)
		}
	case "002":
		// The host line is where the node's own endpoint is named in
		// full. The welcome above carries only the six hex characters
		// of the hostmask, and those are for a person to read: the
		// file beside the nick has to hold something an impostor
		// cannot arrive at by grinding keys until the front of one
		// matches.
		if self := endpoint(params); self != "" {
			c.mu.Lock()
			c.key = self
			c.mu.Unlock()
			// The nick answers what this node is called and the key
			// answers which node it is. Only the second survives
			// somebody else registering the first.
			os.WriteFile(filepath.Join(c.root, "key"), []byte(self+"\n"), 0o600)
		}
	case "PING":
		arg := ""
		if len(params) > 0 {
			arg = params[0]
		}
		_ = c.sendf("PONG :%s", arg)
		return
	case "PRIVMSG", "NOTICE":
		if len(params) < 2 {
			return
		}
		text := params[len(params)-1]
		mark := "<" + from + "> "
		if cmd == "NOTICE" {
			mark = "-" + from + "- "
		}
		// A message to this node is filed under whoever sent it, so a
		// reply goes back the way everything else does: append to the
		// in file next to it. The server itself is the exception: it
		// is not someone to reply to, and an in file beside its
		// notices would promise a conversation that cannot happen.
		//
		// Only the server's own lines are the server's: a line that
		// names it and carries a key was relayed from somebody, and is
		// filed as theirs.
		target := params[0]
		if !strings.HasPrefix(target, "#") {
			if from == serverName && key == "" || from == "" {
				c.log("", key, mark+text)
				return
			}
			target = dmTarget(from, key)
		}
		c.log(target, key, mark+text)
		return
	case "JOIN", "PART", "KICK", "MODE", "TOPIC":
		if len(params) > 0 && strings.HasPrefix(params[0], "#") {
			c.log(params[0], key, "-!- "+event(from, cmd, params))
			return
		}
	}
	// A refusal that names a channel is filed in that channel, beside
	// whatever it was refusing.
	//
	// This node logs its own speech locally, because a bridge does not
	// send a message back to the client that said it. That log means
	// this node said this, and it cannot mean more: a PRIVMSG is
	// answered by nothing at all when it lands, so there is no
	// acknowledgement to wait for and no version of this that only
	// writes the line down once the room has it. What the network does
	// say is when it will not carry something, and that is the one
	// correction available - so it goes where the claim it corrects is
	// rather than in the root log one directory away, which is a file
	// nobody reading a channel is looking at.
	if ch, ok := refused(cmd, params); ok {
		c.log(ch, key, "-!- "+params[len(params)-1])
		return
	}
	c.log("", key, line)
}

// refused reports whether an error numeric names a channel, and which.
//
// The range is the whole of what identifies one: IRC numbers its
// replies and numbers the errors from 400 up, so a name for each of
// the handful this bridge sends today would be a list to keep in step
// with the bridge rather than a rule.
func refused(cmd string, params []string) (string, bool) {
	n, err := strconv.Atoi(cmd)
	if err != nil || len(cmd) != 3 || n < 400 || len(params) < 2 {
		return "", false
	}
	// The last parameter is the human sentence, not a name; the
	// channel is among the ones before it.
	for _, p := range params[:len(params)-1] {
		if strings.HasPrefix(p, "#") {
			return p, true
		}
	}
	return "", false
}

// endpoint returns the node's own key from the 002 numeric, which
// names it at the end of "your host is irciroh, running on endpoint
// <key>". A bridge that words it differently, or an older one, says
// nothing this can use, and an endpoint guessed from such a line
// would be worse than none.
func endpoint(params []string) string {
	if len(params) == 0 {
		return ""
	}
	_, rest, ok := strings.Cut(params[len(params)-1], "endpoint ")
	if !ok {
		return ""
	}
	return strings.TrimSpace(rest)
}

// event renders a line that is about a channel rather than said in it.
func event(from, cmd string, params []string) string {
	rest := strings.Join(params[1:], " ")
	switch cmd {
	case "JOIN":
		return from + " joined"
	case "PART":
		return strings.TrimSpace(from + " left " + rest)
	case "KICK":
		return strings.TrimSpace(from + " kicked " + rest)
	case "MODE":
		return strings.TrimSpace(from + " set " + rest)
	case "TOPIC":
		return strings.TrimSpace(from + " set the topic to " + rest)
	}
	return strings.TrimSpace(from + " " + cmd + " " + rest)
}

// split parses a line into its sender nick, the endpoint the bridge
// tagged it with, the command, and the parameters. [parseLine] drops
// both the tags and the prefix, and who spoke is the whole point of a
// log, so this keeps them. The hostmask's six hex characters are not
// the key: they are short enough to grind a collision for, so what is
// kept is the tag, which carries the whole of it or nothing.
func split(line string) (from, key, cmd string, params []string) {
	if tags, rest, ok := cutTags(line); ok {
		key = tag(tags, wireKeyTag)
		line = rest
	}
	if strings.HasPrefix(line, ":") {
		head, rest, ok := strings.Cut(line[1:], " ")
		if !ok {
			return "", "", "", nil
		}
		from, line = head, rest
		if nick, _, ok := strings.Cut(from, "!"); ok {
			from = nick
		}
	}
	cmd, params = parseLine(line)
	return from, key, cmd, params
}

// cutTags splits an IRCv3 tag block off the front of a line. A line
// that does not begin with one is returned whole, which is every line
// an ordinary server sends.
func cutTags(line string) (tags, rest string, ok bool) {
	if !strings.HasPrefix(line, "@") {
		return "", line, false
	}
	tags, rest, ok = strings.Cut(line[1:], " ")
	if !ok {
		return "", line, false
	}
	return tags, rest, true
}

// dmTarget returns the name a private message from nick is filed under.
// The name becomes a directory, so only a nick that is a plain name will
// do: a path, a channel's name or the server's would put somebody's
// words where somebody else's are expected, or outside the directory
// altogether. Such a sender is filed under its key instead, which is
// the one thing about it nobody else can claim, and a sender with
// neither goes to the directory's own log.
func dmTarget(nick, key string) string {
	switch {
	case okFileName(nick) && !strings.ContainsAny(nick[:1], "#&") && irciroh.Fold(nick) != irciroh.Fold(serverName):
		return nick
	case key != "":
		return "~" + shortKey(key)
	}
	return ""
}

// okFileName reports whether name can be one directory's name under a
// chat directory: not empty, not . or .., and holding no separator and
// no control character.
func okFileName(name string) bool {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return false
	}
	for _, r := range name {
		if r < ' ' || r == 0x7f {
			return false
		}
	}
	return true
}

// cleanLog removes from a logged line the characters a terminal acts on
// rather than shows: every C0 control but tab, which takes IRC's
// formatting codes and CTCP's \x01 with it, DEL, and the C1 controls.
// The log is read with tail, and what somebody else said must not be
// able to move the cursor or recolor the screen of whoever reads it.
func cleanLog(s string) string {
	return strings.Map(func(r rune) rune {
		if r < ' ' && r != '\t' || 0x7f <= r && r <= 0x9f {
			return -1
		}
		return r
	}, s)
}

// log appends one line to a target's out file, stamped with the time
// it arrived and, when the sender is known, with the endpoint it came
// from. An empty target is the directory's own out file, which is
// where everything not about a channel goes.
func (c *chat) log(target, key, text string, tags ...string) {
	dir := c.root
	if target != "" && !okFileName(target) {
		// Not a name this can make a directory of, so the line goes
		// to the directory's own log with the name it claimed.
		text, target = target+" "+text, ""
	}
	if target != "" {
		dir = filepath.Join(c.root, target)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return
		}
		// The in file is created with the directory so that a reader
		// can see where to write before anything has been said.
		makeIn(dir)
	}
	f, err := os.OpenFile(filepath.Join(dir, "out"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	// One write per line, under the pipe buffer, so that two writers
	// cannot interleave a line between them.
	//
	// The key goes in front of the timestamp rather than into the
	// text, so that a line with no key to show is the line this wrote
	// before there were keys at all, byte for byte, and the tail and
	// grep that read this directory go on working.
	stamp := time.Now().UTC().Format(time.RFC3339)
	if key != "" {
		tags = append([]string{logKeyTag + "=" + key}, tags...)
	}
	line := stamp + " " + text
	if len(tags) > 0 {
		line = "@" + strings.Join(tags, ";") + " " + line
	}
	io.WriteString(f, cleanLog(line)+"\n")
}

// outbox watches every in file and sends what is appended to it.
func (c *chat) outbox(ctx context.Context) {
	// Each in file is read from where the last pass stopped. A file
	// that shrinks was truncated by whoever owns it, which is the way
	// to say "start again" rather than an error.
	at := make(map[string]int64)
	c.skip(at, os.Stderr)
	t := time.NewTicker(chatPoll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		c.drain("", at)
		entries, err := os.ReadDir(c.root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			c.drain(e.Name(), at)
		}
	}
}

// skip starts every in file that exists now where the last chat left
// it, and says on w what that means: what is queued there is sent, and
// what an in file with no record of its own holds is not. Saying so
// matters more than it looks: a command skipped is not refused, it is
// simply never run, and a silent no-op is the one failure a person
// cannot tell from a command that did nothing visible.
func (c *chat) skip(at map[string]int64, w io.Writer) {
	if w == nil {
		w = io.Discard
	}
	mark := func(target string) {
		path := filepath.Join(c.root, target, "in")
		fi, err := os.Stat(path)
		if err != nil {
			return
		}
		if n, ok := loadSent(path); ok {
			if n > fi.Size() {
				n = 0
			}
			at[path] = n
			if q := fi.Size() - n; q > 0 {
				fmt.Fprintf(w, "irciroh: sending %d bytes queued in %s\n", q, path)
			}
			return
		}
		at[path] = fi.Size()
		saveSent(path, fi.Size())
		if fi.Size() > 0 {
			fmt.Fprintf(w, "irciroh: %s holds %d bytes written before it was a queue; they are not sent\n", path, fi.Size())
		}
	}
	mark("")
	entries, err := os.ReadDir(c.root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			mark(e.Name())
		}
	}
}

// drain sends whatever has been appended to one target's in file.
func (c *chat) drain(target string, at map[string]int64) {
	path := filepath.Join(c.root, target, "in")
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return
	}
	n, seen := at[path]
	if !seen {
		// A conversation that appeared since the chat started was
		// made by somebody who meant it to be sent from its start,
		// unless it says otherwise.
		n, _ = loadSent(path)
	}
	if fi.Size() < n {
		n = 0
	}
	at[path] = n
	if fi.Size() == n {
		return
	}
	if _, err := f.Seek(n, io.SeekStart); err != nil {
		return
	}
	r := bufio.NewReader(f)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			// A partial last line is left where it is: a writer that
			// has not finished its line has not sent it, and the next
			// pass reads it whole.
			break
		}
		at[path] += int64(len(line))
		if saveSent(path, at[path]) != nil {
			// A line whose sending cannot be recorded would be sent
			// again by the next chat, so it waits.
			at[path] -= int64(len(line))
			return
		}
		c.say(target, strings.TrimRight(line, "\r\n"))
	}
}

// makeIn creates dir's in file if there is none, with a record that
// none of it has been sent.
func makeIn(dir string) {
	path := filepath.Join(dir, "in")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	f.Close()
	saveSent(path, 0)
}

// queue appends lines to an in file, as a program does that is not the
// chat. An in file it creates is recorded as having had nothing sent,
// so the lines go when a chat next runs if none is running now.
func queue(path string, lines []string) error {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if err := saveSent(path, 0); err != nil {
			return err
		}
	}
	return appendLines(path, lines)
}

// loadSent reads how much of the in file at path has been sent, and
// reports whether that is recorded.
func loadSent(path string) (int64, bool) {
	b, err := os.ReadFile(path + ".sent")
	if err != nil {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// saveSent records how much of the in file at path has been sent. It
// replaces the record whole, so that a chat that dies while writing it
// leaves the old one rather than half of the new.
func saveSent(path string, n int64) error {
	tmp := path + ".sent.tmp"
	if err := os.WriteFile(tmp, []byte(strconv.FormatInt(n, 10)+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path+".sent")
}

// say sends one line written to an in file. A line starting with a
// slash is a raw IRC command, which is the whole of the escape hatch:
// everything IRC can do that this tool has no syntax for - inviting,
// kicking, setting a topic - is one slash away, and nothing here has to
// grow a subcommand for it. Two slashes send a line that starts with
// one.
func (c *chat) say(target, line string) {
	if target == "" {
		// The root in file is the command channel. There is nobody
		// there to say anything to, so a line written to it is IRC
		// itself and needs no slash to say so.
		if line != "" {
			c.raw(line)
		}
		return
	}
	switch {
	case line == "":
		return
	case strings.HasPrefix(line, "//"):
		line = line[1:]
	case strings.HasPrefix(line, "/"):
		c.raw(line[1:])
		return
	}
	for i, part := range splitText(line) {
		if err := c.sendf("PRIVMSG %s :%s", target, part); err != nil {
			return
		}
		// A bridge does not echo a message back to the client that
		// sent it, so the log would have every side of the
		// conversation but this one.
		nick, key := c.self()
		var tags []string
		if i > 0 {
			tags = append(tags, wrapTag+"=1")
		}
		c.log(target, key, "<"+nick+"> "+part, tags...)
	}
}

// raw sends one line of IRC this chat was handed verbatim, and writes
// it down if it was speech.
//
// The raw path is the escape hatch: everything this tool has no syntax
// for - a topic, a kick, a mode, the bridge's own TICKET - goes out
// this way, and what comes back of it is the server's answer, which
// [chat.read] logs like any other inbound line. That is the whole
// record a command needs.
//
// A PRIVMSG is not a command. It puts a line on a channel that every
// other member sees, and the bridge does not send it back to the
// client that spoke it, so a node driven this way said something the
// channel heard and its own directory does not hold - a log
// indistinguishable from the node having said nothing. Which is the
// same mistake as reading a local zero as a fact about the room, one
// layer down, and it is why this logs the message and not the command
// that carried it.
func (c *chat) raw(line string) {
	if err := c.sendf("%s", line); err != nil {
		return
	}
	cmd, params := parseLine(line)
	if cmd != "PRIVMSG" && cmd != "NOTICE" || len(params) < 2 {
		return
	}
	nick, key := c.self()
	mark := "<" + nick + "> "
	if cmd == "NOTICE" {
		mark = "-" + nick + "- "
	}
	c.log(params[0], key, mark+params[len(params)-1])
}

// self is how this node's own lines are logged: the nick the bridge
// welcomed this connection with, which is the node's own - one bridge
// process is one identity, whatever a client asked to be called - and
// the endpoint behind it, so that these lines are stamped the way
// everyone else's arrive and a reader can tell the node's own words
// from a stranger wearing its name.
func (c *chat) self() (nick, key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.nick == "" {
		return "me", c.key
	}
	return c.nick, c.key
}

// runWait blocks until a line matching a pattern is appended to a
// target's out file, and prints it. It is what turns the log into
// something to wait on rather than something to poll: a caller that
// would otherwise loop on tail sleeps here instead.
func runWait(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("wait", flag.ExitOnError)
	dir := fs.String("dir", "", "directory a chat is keeping")
	target := fs.String("target", "", "channel or nick to watch")
	match := fs.String("match", "", "regular expression to wait for; any line by default")
	for_ := fs.Duration("for", time.Minute, "how long to wait before giving up")
	history := fs.Bool("history", false, "match against lines already in the log too")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || *target == "" {
		return fmt.Errorf("wait: -dir and -target are required")
	}
	re, err := regexp.Compile(*match)
	if err != nil {
		return fmt.Errorf("wait: bad -match: %w", err)
	}
	path := filepath.Join(*dir, *target, "out")

	var at int64
	if !*history {
		if fi, err := os.Stat(path); err == nil {
			at = fi.Size()
		}
	}
	deadline := time.Now().Add(*for_)
	t := time.NewTicker(chatPoll)
	defer t.Stop()
	for {
		line, next, err := scan(path, at, re)
		if err == nil && line != "" {
			fmt.Println(line)
			return nil
		}
		at = next
		if time.Now().After(deadline) {
			return fmt.Errorf("wait %s: no line matching %q in %v", *target, *match, *for_)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

// scan reads a log from an offset and returns the first matching line
// and the offset to resume from.
func scan(path string, at int64, re *regexp.Regexp) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", at, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", at, err
	}
	if fi.Size() < at {
		at = 0
	}
	if _, err := f.Seek(at, io.SeekStart); err != nil {
		return "", at, err
	}
	r := bufio.NewReader(f)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return "", at, nil
		}
		at += int64(len(line))
		if got := strings.TrimRight(line, "\r\n"); re.MatchString(got) {
			return got, at, nil
		}
	}
}

// chatNick reads the name a chat registered with, which is the node's
// own. A program in this directory needs it to tell its own lines from
// everyone else's.
func chatNick(root string) (string, error) {
	b, err := os.ReadFile(filepath.Join(root, "nick"))
	if err != nil {
		return "", fmt.Errorf("no nick in %s: no chat has attached to it", root)
	}
	nick := strings.TrimSpace(string(b))
	if nick == "" {
		return "", fmt.Errorf("no nick in %s", root)
	}
	return nick, nil
}

// chatKey reads the endpoint a chat speaks from, whole. It is what a
// program in the directory should recognize itself by: the nick
// beside it can be registered by anyone, and the short form in a
// hostmask is short enough that a key matching it can be found.
func chatKey(root string) (string, error) {
	b, err := os.ReadFile(filepath.Join(root, "key"))
	if err != nil {
		return "", fmt.Errorf("no key in %s: no chat has attached to it", root)
	}
	key := strings.TrimSpace(string(b))
	if key == "" {
		return "", fmt.Errorf("no key in %s", root)
	}
	return key, nil
}

// since reads the complete lines appended to a log after an offset and
// reports the offset to resume from. A log that has shrunk was
// truncated, which is how its owner says to start again.
func since(path string, at int64) ([]string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, at, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, at, err
	}
	if fi.Size() < at {
		at = 0
	}
	if _, err := f.Seek(at, io.SeekStart); err != nil {
		return nil, at, err
	}
	var lines []string
	r := bufio.NewReader(f)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			// A partial last line is left for the next pass, the
			// same way an unfinished in line is.
			return lines, at, nil
		}
		at += int64(len(line))
		lines = append(lines, strings.TrimRight(line, "\r\n"))
	}
}

// speech splits a logged line into who spoke, the endpoint they spoke
// from, and what they said. A line that is not speech - a notice, or
// an event such as a join - has no speaker, because answering one
// would mean answering the server. A line the bridge could not stamp,
// and every line written before it stamped any, has an empty key, and
// a caller then has only the nick to go on.
func speech(line string) (nick, key, text string, ok bool) {
	if tags, rest, ok := cutTags(line); ok {
		key = tag(tags, logKeyTag)
		line = rest
	}
	_, rest, ok := strings.Cut(line, " ")
	if !ok || !strings.HasPrefix(rest, "<") {
		return "", "", "", false
	}
	nick, text, ok = strings.Cut(rest[1:], "> ")
	if !ok || nick == "" {
		return "", "", "", false
	}
	return nick, key, text, true
}

// tag reads one value out of an IRCv3 tag prefix, which is a
// ;-separated list of name=value.
func tag(tags, name string) string {
	for len(tags) > 0 {
		var t string
		t, tags, _ = strings.Cut(tags, ";")
		if k, v, ok := strings.Cut(t, "="); ok && k == name {
			return v
		}
	}
	return ""
}

// shortKey is as much of a key as a person will read.
func shortKey(key string) string {
	if len(key) > 6 {
		return key[:6]
	}
	return key
}

// appendLines adds lines to an in file, one write each so that two
// writers cannot interleave a line between them.
func appendLines(path string, lines []string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, line := range lines {
		if _, err := fmt.Fprintln(f, line); err != nil {
			return err
		}
	}
	return nil
}
