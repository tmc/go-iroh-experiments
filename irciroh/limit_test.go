package irciroh

import (
	"testing"
	"time"

	"github.com/tmc/go-iroh/key"
)

func TestBudgetSpend(t *testing.T) {
	id := testID(t)
	start := time.Unix(0, 0)

	// The cases are written in terms of sendBurst rather than spelled out,
	// so that tuning the burst does not mean rewriting what a burst means.
	burst := func(d time.Duration) (at []time.Duration, want []bool) {
		for range sendBurst {
			at, want = append(at, d), append(want, true)
		}
		return at, want
	}
	then := func(at []time.Duration, want []bool, d time.Duration, ok bool) ([]time.Duration, []bool) {
		return append(at, d), append(want, ok)
	}

	emptyAt, emptyWant := burst(0)
	emptyAt, emptyWant = then(emptyAt, emptyWant, 0, false)

	refillAt, refillWant := burst(0)
	refillAt, refillWant = then(refillAt, refillWant, 0, false)
	refillAt, refillWant = then(refillAt, refillWant, sendInterval, true)

	// A sender that spends one token and then goes quiet for an hour has
	// its bucket back, and no more than its bucket.
	bankAt, bankWant := then(nil, nil, 0, true)
	for range sendBurst {
		bankAt, bankWant = then(bankAt, bankWant, time.Hour, true)
	}
	bankAt, bankWant = then(bankAt, bankWant, time.Hour, false)

	tests := []struct {
		name string
		at   []time.Duration // when each message arrives
		want []bool          // whether each is allowed
	}{{
		name: "burst then empty",
		at:   emptyAt,
		want: emptyWant,
	}, {
		name: "refill lets one more through",
		at:   refillAt,
		want: refillWant,
	}, {
		name: "steady talk is never refused",
		at:   []time.Duration{0, 3 * time.Second, 6 * time.Second, 9 * time.Second, 12 * time.Second},
		want: []bool{true, true, true, true, true},
	}, {
		name: "a long silence does not bank more than the burst",
		at:   bankAt,
		want: bankWant,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := make(budgets)
			for i, d := range tt.at {
				ok, _ := b.spend(id, kindMessage, 0, start.Add(d), true)
				if ok != tt.want[i] {
					t.Errorf("message %d at %v: allowed=%v, want %v", i, d, ok, tt.want[i])
				}
			}
		})
	}
}

// TestBudgetChargesEnvelopesAndBytes checks both terms of the price of a
// message. Per envelope alone let a client's line length decide what a
// channel allowed; per byte alone would make the smallest message the
// cheapest flood, because verifying a signature costs the same whatever
// the frame holds.
func TestBudgetChargesEnvelopesAndBytes(t *testing.T) {
	now := time.Unix(0, 0)

	// The envelope term bounds a flood of the smallest message there is:
	// charging bytes alone would have let a one-byte sender send
	// bytesPerToken times as many.
	b := make(budgets)
	id := testID(t)
	tiny := 0
	for range 1000 {
		if ok, _ := b.spend(id, kindMessage, 1, now, true); !ok {
			break
		}
		tiny++
	}
	if tiny > sendBurst {
		t.Errorf("a settled sender sent %d one-byte messages back to back, want at most %d", tiny, sendBurst)
	}
	if tiny < sendBurst-1 {
		t.Errorf("a settled sender sent only %d one-byte messages, want about %d", tiny, sendBurst)
	}

	// The byte term makes a large message cost what it weighs: the
	// largest text the protocol carries is most of a settled sender's
	// burst, so it affords one and not two back to back, where an
	// unweighed charge would have allowed sendBurst of them.
	b = make(budgets)
	id = testID(t)
	if ok, _ := b.spend(id, kindMessage, MaxEnvelopeSize, now, true); !ok {
		t.Fatal("a settled sender was refused one full envelope")
	}
	if ok, _ := b.spend(id, kindMessage, MaxEnvelopeSize, now, true); ok {
		t.Error("a second full envelope back to back was allowed: bytes are not being charged")
	}

	// Splitting text to fit a client's line no longer multiplies what it
	// costs to say, which is the whole reason bytes are counted: four
	// pieces of one paragraph cost less than four times the one message.
	whole, piece := 1600, 400
	b = make(budgets)
	id = testID(t)
	b.spend(id, kindMessage, whole, now, true)
	one := sendBurst - b[id].tokens
	b = make(budgets)
	id = testID(t)
	for range whole / piece {
		b.spend(id, kindMessage, piece, now, true)
	}
	if split := sendBurst - b[id].tokens; split >= 4*one {
		t.Errorf("split cost %v against %v whole; splitting is still charged per piece", split, one)
	}

	// A newcomer's two tokens buy two ordinary lines, and a maximum one
	// spends both: the charge is weighed for a newcomer as it is for
	// anybody, up to what it can pay. What it may not do is exceed what
	// it can pay - see [TestBudgetNeverPricesOutAMessage].
	b = make(budgets)
	id = testID(t)
	for i := range newcomerBurst {
		if ok, _ := b.spend(id, kindMessage, piece, now, false); !ok {
			t.Errorf("a newcomer could not say ordinary line %d", i+1)
		}
	}
	b = make(budgets)
	id = testID(t)
	b.spend(id, kindMessage, MaxEnvelopeSize, now, false)
	if b[id].tokens > 0 {
		t.Errorf("the largest message left a newcomer %v tokens; it should cost everything it has", b[id].tokens)
	}
}

// TestBudgetNeverPricesOutAMessage checks the invariant that keeps the
// byte term a rate limit rather than a size limit: no message the
// protocol will carry may cost more than the burst it is charged
// against. A bucket fills to its burst and no further, so a message
// that costs more is not delayed by the limit - it is refused now and
// refused after any amount of waiting.
func TestBudgetNeverPricesOutAMessage(t *testing.T) {
	now := time.Unix(0, 0)

	// MaxEnvelopeSize is the whole frame and the charge weighs only the
	// text, so this is more than any message can actually weigh; if the
	// invariant holds here it holds for everything the protocol carries.
	for _, admitted := range []bool{false, true} {
		b := make(budgets)
		id := testID(t)
		if ok, _ := b.spend(id, kindMessage, MaxEnvelopeSize, now, admitted); !ok {
			t.Errorf("admitted=%v: the largest message the protocol carries is refused on a full bucket", admitted)
		}
	}

	// And waiting is what fixes the refusal, which is the difference
	// between a rate limit and a drop: a newcomer that spends everything
	// on one long line can say another once its allowance is back.
	b := make(budgets)
	id := testID(t)
	b.spend(id, kindMessage, MaxEnvelopeSize, now, false)
	if ok, _ := b.spend(id, kindMessage, MaxEnvelopeSize, now, false); ok {
		t.Error("two of the largest messages back to back: the cap made long lines cheap")
	}
	// Waiting is what fixes the refusal, and that is the whole difference
	// between a rate limit and a drop. It has to happen while the sender
	// is still a newcomer: once it has served the warm-up the question is
	// not about newcomers any more.
	waited := time.Duration(0)
	for d := time.Second; d < warmup; d += time.Second {
		if ok, _ := b.spend(id, kindMessage, MaxEnvelopeSize, now.Add(d), false); ok {
			waited = d
			break
		}
	}
	if waited == 0 {
		t.Errorf("a newcomer that spent everything on one long line cannot say another inside the %v warm-up", warmup)
	}
}

// TestBudgetFirstRefusal checks that a flood reports itself once rather
// than once per message: an event per dropped message would make the
// report as expensive as the flood.
func TestBudgetFirstRefusal(t *testing.T) {
	id := testID(t)
	now := time.Unix(0, 0)
	b := make(budgets)
	for range sendBurst {
		if ok, refused := b.spend(id, kindMessage, 0, now, true); !ok || refused != 0 {
			t.Fatalf("burst message refused")
		}
	}
	reports, total := 0, 0
	for range 10 {
		ok, refused := b.spend(id, kindMessage, 0, now, true)
		if ok {
			t.Fatal("allowed past the burst with no refill")
		}
		if refused > 0 {
			reports++
			total += refused
		}
	}
	if reports != 1 || total != 1 {
		t.Errorf("a run of 10 refusals in one instant reported %d times for %d envelopes, want 1 and 1", reports, total)
	}
	// A refill lands a message and the next is refused again. That is
	// not news twice inside one reporting interval, and it is the
	// shape a flood actually has: a bucket that is refusing is also
	// refilling, so it lets one through now and then.
	if ok, _ := b.spend(id, kindMessage, 0, now.Add(sendInterval), true); !ok {
		t.Fatal("refill did not restore a token")
	}
	if ok, refused := b.spend(id, kindMessage, 0, now.Add(sendInterval), true); ok || refused != 0 {
		t.Errorf("refused again %v in: allowed=%v refused=%v, want false 0", sendInterval, ok, refused)
	}
	// Once the interval is up it is news again, carrying what went
	// unsaid in the meantime.
	later, said := now.Add(refusalReport), 0
	for range sendBurst + 2 {
		ok, refused := b.spend(id, kindMessage, 0, later, true)
		if ok {
			continue
		}
		if said++; said == 1 && refused < 2 {
			t.Errorf("after %v the first refusal reported %d, want the count since", refusalReport, refused)
		}
	}
	if said == 0 {
		t.Errorf("after %v nothing was refused, so nothing was re-reported", refusalReport)
	}
}

// pingFlood announces presence four times every half a refill for four
// report intervals: a node whose neighbours keep churning announces
// itself on every NeighborUp, and once the allowance is spent most of
// what it sends is refused. Between rounds it calls speak, which is
// where a test says what else the sender is doing. It returns how many
// refusals were reported, how many envelopes those reports accounted
// for, and how many were refused in all.
func pingFlood(t *testing.T, b budgets, id key.EndpointID, now time.Time, speak func(at time.Time)) (reports, counted, refused int) {
	t.Helper()
	// The step is read off presenceRefill rather than picked, so that
	// announcing faster than the allowance refills is what this
	// measures whatever the timings are set to.
	step := presenceRefill() / 2
	for d := time.Duration(0); d < 4*refusalReport; d += step {
		// Whatever else the sender is doing goes first, so that a
		// report the two allowances would have to share is one the
		// presence announcements lose rather than win.
		if speak != nil {
			speak(now.Add(d))
		}
		for range 4 {
			if ok, n := b.spend(id, kindPing, 0, now.Add(d), true); !ok {
				refused++
				reports += min(n, 1)
				counted += n
			}
		}
	}
	return reports, counted, refused
}

// reportsForAFloodOf is how many refusal reports a flood lasting d may
// produce: one per interval, and one more for the interval it starts in.
func reportsForAFloodOf(d time.Duration) int { return int(d/refusalReport) + 1 }

// TestBudgetKeepsReportingALongRefusal checks that a refusal which goes
// on is reported for as long as it goes on, and no harder. With only
// the one line a run opens with, a sender being refused steadily and a
// sender with nothing to say look the same from outside, and they are
// not the same thing: it is how a live member is dropped from a roster
// with nothing said about it. With a line per envelope, reporting the
// flood costs what the flood costs.
func TestBudgetKeepsReportingALongRefusal(t *testing.T) {
	id := testID(t)
	now := time.Unix(0, 0)
	b := make(budgets)
	reports, counted, refused := pingFlood(t, b, id, now, nil)
	want := reportsForAFloodOf(4 * refusalReport)
	if reports < want-1 || reports > want {
		t.Errorf("%d announcements refused over %v reported %d times, want %d", refused, 4*refusalReport, reports, want)
	}
	// Everything refused is accounted for in some report but the tail
	// since the last one.
	if counted == 0 || counted > refused {
		t.Errorf("reports accounted for %d of %d refused announcements", counted, refused)
	}
}

// TestBudgetReportsPresenceThroughSpeech checks that a sender flooding
// one allowance does not use up the reporting of the other. Presence
// and speech are separate limits and separate news: the speech being
// refused is a nuisance, the presence being refused is this node
// dropping a member that is alive, meshed and talking, and a reader
// shown only the first has been told the wrong thing.
func TestBudgetReportsPresenceThroughSpeech(t *testing.T) {
	id := testID(t)
	now := time.Unix(0, 0)
	b := make(budgets)
	said := 0
	speak := func(at time.Time) {
		for range 4 {
			if ok, _ := b.spend(id, kindMessage, 0, at, true); !ok {
				said++
			}
		}
	}
	reports, _, refused := pingFlood(t, b, id, now, speak)
	if said == 0 {
		t.Fatal("the speech flood was never refused, so it cannot have crowded anything out")
	}
	want := reportsForAFloodOf(4 * refusalReport)
	if reports < want-1 || reports > want {
		t.Errorf("%d announcements refused alongside %d refused lines reported %d times, want %d", refused, said, reports, want)
	}
}

// TestBudgetPrune checks that the budget table forgets senders it has
// nothing left to remember, since the table is itself per-sender state
// an attacker would like to grow.
func TestBudgetPrune(t *testing.T) {
	now := time.Unix(0, 0)
	b := make(budgets)
	quiet, loud := testID(t), testID(t)
	b.spend(quiet, kindMessage, 0, now, true)
	for range sendBurst + 3 {
		b.spend(loud, kindMessage, 0, now, true)
	}
	if len(b) != 2 {
		t.Fatalf("tracking %d senders, want 2", len(b))
	}

	// Still recent: both are remembered, however they spent.
	b.prune(now.Add(budgetIdle))
	if len(b) != 2 {
		t.Errorf("forgot a sender still within the idle window: %d left, want 2", len(b))
	}

	// Past the window both budgets have long since refilled, so there
	// is nothing left to remember about either.
	b.prune(now.Add(budgetIdle + time.Second))
	if len(b) != 0 {
		t.Errorf("kept %d entries past the idle window, want 0", len(b))
	}
	// A forgotten sender comes back as a stranger, not as a blocked
	// one: forgetting may cost the sender and must never credit it.
	if ok, _ := b.spend(loud, kindMessage, 0, now.Add(time.Hour), false); !ok {
		t.Error("a forgotten sender could not say anything at all")
	}
	if got := b[loud].tokens; got >= newcomerBurst {
		t.Errorf("a forgotten sender came back holding %v tokens, want less than %v", got, float64(newcomerBurst))
	}
}

// TestBudgetWarmup checks the price of arriving. An endpoint id costs a
// keypair, so whatever a stranger may say on arrival is what a flood
// gets for each identity it mints; the warm-up is what makes minting one
// per message pointless.
func TestBudgetWarmup(t *testing.T) {
	now := time.Unix(0, 0)

	// A stranger arrives and says hello, and no more: newcomerBurst is
	// what those two envelopes cost together.
	b := make(budgets)
	id := testID(t)
	for i := range newcomerBurst {
		if ok, _ := b.spend(id, kindMessage, 0, now, false); !ok {
			t.Fatalf("a newcomer was refused envelope %d of %d", i+1, newcomerBurst)
		}
	}
	if ok, _ := b.spend(id, kindMessage, 0, now, false); ok {
		t.Errorf("a newcomer delivered %d envelopes back to back, want %d", newcomerBurst+1, newcomerBurst)
	}

	// It waits the newcomer interval, not the settled one, for the next.
	if ok, _ := b.spend(id, kindMessage, 0, now.Add(sendInterval), false); ok {
		t.Error("a newcomer refilled at the settled rate")
	}
	if ok, _ := b.spend(id, kindMessage, 0, now.Add(newcomerInterval), false); !ok {
		t.Error("a newcomer did not refill at the newcomer rate")
	}

	// Once warmed up it is an ordinary sender: a full burst back to back.
	settled := now.Add(warmup)
	for i := range sendBurst {
		if ok, _ := b.spend(id, kindMessage, 0, settled, false); !ok {
			t.Fatalf("a warmed-up sender was refused message %d of a burst of %d", i+1, sendBurst)
		}
	}

	// The ramp is monotone, so there is no cliff to time a burst against.
	x := &budget{first: now}
	prevSize, prevRefill := 0.0, time.Duration(1<<62)
	for d := time.Duration(0); d <= 2*warmup; d += warmup / 10 {
		size, refill := x.rate(now.Add(d))
		if size < prevSize || refill > prevRefill {
			t.Fatalf("at %v the ramp went backwards: size %v (was %v), refill %v (was %v)", d, size, prevSize, refill, prevRefill)
		}
		prevSize, prevRefill = size, refill
	}
	if prevSize != sendBurst || prevRefill != sendInterval {
		t.Errorf("the ramp settles at size %v refill %v, want %v and %v", prevSize, prevRefill, float64(sendBurst), sendInterval)
	}
}

// TestBudgetAdmittedSkipsWarmup checks that a sealed channel's members
// are not charged twice. The founder checked the invite secret before
// committing the member, so the identity was not free; the warm-up is
// the price of a door a public channel does not have.
func TestBudgetAdmittedSkipsWarmup(t *testing.T) {
	now := time.Unix(0, 0)
	b := make(budgets)
	id := testID(t)
	for i := range sendBurst {
		if ok, _ := b.spend(id, kindMessage, 0, now, true); !ok {
			t.Fatalf("an admitted member was refused message %d of a burst of %d", i+1, sendBurst)
		}
	}
}

// TestBudgetIdleOutlastsRefill holds the invariant prune depends on: a
// budget must refill completely before the table is allowed to forget
// it, or forgetting hands back tokens the sender had not yet earned.
func TestBudgetIdleOutlastsRefill(t *testing.T) {
	if refill := sendBurst * sendInterval; budgetIdle <= refill {
		t.Errorf("budgetIdle %v does not outlast a full refill %v", budgetIdle, refill)
	}
}

// TestChannelRosterCap checks that a public channel's roster is bounded,
// and with it everything this node keeps per sender. Its topic is
// derived from its name alone, so anyone can join and a member costs
// only a keypair; without a bound the member table, and the windows and
// budgets beside it, are a memory target that costs an attacker nothing
// to grow.
func TestChannelRosterCap(t *testing.T) {
	c := joinAlone(t, "#churn")
	first := newKey(t)
	deliver(t, c, first, kindPing, 1, "")
	// Each sender pings once, so no budget is ever exhausted and the
	// only thing that can turn one away is the cap.
	for range maxMembers + 10 {
		deliver(t, c, newKey(t), kindPing, 1, "")
	}
	heard(c)
	c.mu.Lock()
	members, windows, budgets := len(c.members), len(c.lastSeq), len(c.spent)
	c.mu.Unlock()
	if members != maxMembers {
		t.Errorf("roster holds %d members, want the cap of %d", members, maxMembers)
	}
	// This node is on its own roster and keeps no window or budget for
	// itself, so the tables hold one fewer.
	if windows > maxMembers-1 || budgets > maxMembers-1 {
		t.Errorf("after %d senders: %d windows and %d budgets, want at most %d", maxMembers+11, windows, budgets, maxMembers-1)
	}

	// An established member is not pushed out by the newcomers: the cap
	// refuses the new one instead, or a sender churning keys could
	// evict a channel's real members.
	deliver(t, c, first, kindMessage, 2, "still here")
	if got := heard(c); len(got) != 1 {
		t.Error("an established member was refused once the roster filled")
	}
}

// TestBudgetCoversArriving checks that a stranger can still say hello.
// A member announces itself with a join and a ping before it speaks, so
// a message budget that those two came out of would refuse the first
// word of everyone who ever joined a public channel.
func TestBudgetCoversArriving(t *testing.T) {
	c := &Channel{
		node:    &Node{},
		members: make(map[key.EndpointID]*member),
		lastSeq: make(seqSet),
		spent:   make(budgets),
	}
	now := time.Now()
	id := testID(t)
	c.apply(kindJoin, "bob", "", id, now, now, true)
	c.apply(kindPing, "bob", "", id, now, now, true)
	out := c.apply(kindMessage, "bob", "hello", id, now, now, true)
	if len(out) != 1 || out[0].Kind != Message {
		t.Errorf("a newcomer's first word produced %v, want one Message", out)
	}
}

// TestPresenceIsChargedSeparately checks that the two allowances are
// independent in both directions: a sender that has talked itself out
// can still say it is here, and one that has announced itself too often
// can still be heard.
func TestPresenceIsChargedSeparately(t *testing.T) {
	now := time.Now()
	id := testID(t)

	b := make(budgets)
	for range sendBurst {
		b.spend(id, kindMessage, 0, now, true)
	}
	if ok, _ := b.spend(id, kindMessage, 0, now, true); ok {
		t.Fatal("the message budget did not run out")
	}
	if ok, _ := b.spend(id, kindPing, 0, now, true); !ok {
		t.Error("a sender out of messages could not report presence")
	}

	b = make(budgets)
	for range presenceBurst {
		b.spend(id, kindPing, 0, now, true)
	}
	if ok, _ := b.spend(id, kindPing, 0, now, true); ok {
		t.Fatal("the presence allowance did not run out")
	}
	if ok, _ := b.spend(id, kindMessage, 0, now, true); !ok {
		t.Error("a sender out of presence could not be heard")
	}
}

// TestPresenceAllowanceOutlastsItsInterval checks that presence is never
// the thing that binds on an honest member, which pings on
// presenceInterval for as long as it stays on the channel.
func TestPresenceAllowanceOutlastsItsInterval(t *testing.T) {
	b := make(budgets)
	id := testID(t)
	now := time.Now()
	for i := range 100 {
		if ok, _ := b.spend(id, kindPing, 0, now, true); !ok {
			t.Fatalf("an honest member was refused presence %d of 100", i+1)
		}
		now = now.Add(presenceInterval)
	}
}

// TestPresenceCannotOutrunItsAllowance checks that a node cannot
// announce itself faster than every receiver refills the allowance it
// charges presence to. A node that could would be refused by everyone
// it was announcing itself to, and three refused announcements in a row
// is a presenceTimeout: it would talk itself out of their rosters while
// alive and meshed. Nothing sends on a schedule that fast, but a
// neighbor coming up sends one too and neighbors churn, which is a rate
// nothing else bounds.
func TestPresenceCannotOutrunItsAllowance(t *testing.T) {
	c := &Channel{}
	now := time.Unix(0, 0)
	b, id := make(budgets), testID(t)
	sent, refused := 0, 0
	// Announce on every churn for four presence timeouts, at ten times
	// the rate the allowance refills.
	step := presenceRefill() / 10
	for d := time.Duration(0); d < 4*presenceTimeout; d += step {
		if !c.mayPing(now.Add(d)) {
			continue
		}
		sent++
		if ok, _ := b.spend(id, kindPing, 0, now.Add(d), true); !ok {
			refused++
		}
	}
	if sent == 0 {
		t.Fatal("nothing was announced at all")
	}
	if refused > 0 {
		t.Errorf("%d of %d announcements would be refused by a receiver, want none", refused, sent)
	}
}
