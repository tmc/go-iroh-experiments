package irciroh

import (
	"time"

	"github.com/tmc/go-iroh/key"
)

// Abuse control on a serverless network has to be local: there is no
// server to complain to, no operator to appeal to, and no way for the
// members of a channel to agree on anything without a round of
// consensus nobody wants to pay for. So every limit here is one node
// deciding what it will spend on one sender, unilaterally. A channel is
// protected because every member independently refuses the same flood,
// not because anything was agreed.
//
// The limits apply to both kinds of channel. They sit in
// [Channel.apply], which is where a public channel's signed envelope
// and a sealed channel's note both arrive once the sender has been
// authenticated, and so is the one place that sees everything a member
// says.
const (
	// sendInterval is how fast a settled sender's message budget
	// refills. It is far above what a person types and far below what a
	// flood sends.
	sendInterval = 2 * time.Second

	// sendBurst is how many messages a settled sender may deliver back
	// to back before the refill rate binds. It absorbs a paste or a
	// reconnect without making a conversation stutter.
	//
	// It is deliberately larger than a person's burst, because the
	// senders that matter here are not people. An agent that has been
	// reading a log while it was not speaking answers all of it at once,
	// and a client that has to split one message across several lines
	// spends a token per line; both arrive as one burst that is not a
	// flood, and both were being refused at five. What bounds a flood is
	// the refill rate, which is unchanged: a burst is spent once, and
	// after that a sender gets sendInterval whatever this number is.
	sendBurst = 16

	// newcomerInterval and newcomerBurst are what a sender this node has
	// not heard before gets instead. An endpoint id costs a keypair, so
	// whatever a stranger is allowed on arrival is what a flood gets per
	// identity it mints; at the settled numbers that was five messages
	// each, for free, from as many identities as an attacker cared to
	// generate. One message and a slow refill is the price of arriving.
	//
	// The newcomer still says something at once. Refusing the first line
	// outright would tax the ordinary case - somebody joining a channel
	// and saying hello - to make an attacker wait six seconds.
	newcomerInterval = 6 * time.Second
	newcomerBurst    = 2

	// bytesPerToken is how many bytes of message text a token buys
	// beyond the one every message costs. Charging per message alone made
	// the limit depend on how the sender chose to cut its text up: one
	// paragraph split to fit an IRC client's 512-byte line spent four
	// tokens where the same paragraph in one envelope spent one, so a
	// client's line length decided what a channel allowed. Charging per
	// byte alone is worse in the other direction, because verifying a
	// signature costs the same whatever the frame holds, and the smallest
	// message would be the cheapest flood.
	//
	// So a message costs one token for existing and one more for every
	// whole bytesPerToken of text. The division is integer on purpose: a
	// fractional charge would make an ordinary twenty-byte line cost
	// 1.04 tokens, so a newcomer with two of them could afford one
	// message instead of two, and a refusal here is a drop rather than a
	// delay. A message may not cost more than the burst it is charged
	// against or it is not rate limited, it is undeliverable, so nothing
	// shorter than bytesPerToken may cost more than one.
	//
	// At this size the largest text the protocol carries is most of a
	// settled sender's burst, and a newcomer's two tokens buy ordinary
	// lines and not a maximum one.
	bytesPerToken = 512

	// presenceBurst is a separate allowance for announcing yourself,
	// which every sender spends from whatever its standing. Presence
	// and speech are different floods and charging them to one purse
	// forces a choice between them: a budget tight enough to be worth
	// having is spent by a member's own join and ping before it says a
	// word, and one loose enough to leave room is not tight.
	presenceBurst = 3

	// warmup is how long a sender takes to earn its way from the
	// newcomer numbers to the settled ones. It is short enough that a
	// conversation never notices and long enough that minting an
	// identity per message buys nothing.
	warmup = 90 * time.Second

	// maxMembers bounds a public channel's roster. A public channel's
	// topic is derived from its name alone, so anyone can join and a
	// member costs only a keypair; without a bound the member table is
	// a memory target that costs an attacker nothing to grow. A sealed
	// channel needs no such bound, because its roster is the MLS group
	// and only the founder admits.
	maxMembers = 512

	// refusalReport is how often one allowance's refusals are reported.
	// It is the whole reporting rule: at most one [Refused] event per
	// interval, carrying what was turned away since the last one. An
	// event per dropped envelope would make the report of a flood as
	// expensive as the flood, and a single event at the start of one
	// would leave a sender refused for an hour looking exactly like a
	// sender with nothing to say - which is the harder failure to
	// notice, because nothing appears.
	//
	// It is well inside presenceTimeout on purpose: the case this is
	// for is a member being rate limited out of a roster while alive,
	// and a report that arrived after the expiry would be describing
	// something already done.
	refusalReport = 30 * time.Second

	// budgetIdle is how long a sender is remembered after its last
	// message. It must exceed sendBurst*sendInterval, the time a spent
	// budget takes to refill completely, so that forgetting an entry
	// can never hand back tokens the sender had not yet earned.
	// TestBudgetIdleOutlastsRefill holds it to that.
	//
	// The floor leaves the ceiling free, and the ceiling should be well
	// above how long a channel goes quiet. Forgetting a sender charges
	// it the warm-up again, and the moment a member comes back from a
	// silence is exactly when it has the most to say - so a timeout
	// shorter than a lull turns standing earned over an hour into a
	// newcomer's two messages. An hour costs one small entry per sender
	// heard in the last hour. On a public channel a sender is written
	// down only while the roster has room for it, so the table is the
	// roster plus whoever left it within the hour: bounded by maxMembers
	// while members stay, and by how fast they leave when they do not.
	budgetIdle = time.Hour
)

// A budget is what one sender may still spend. It is a token bucket:
// tokens refill at one per [sendInterval] up to [sendBurst], and a
// message costs one. A sender that arrived less than [warmup] ago gets a
// smaller bucket and a slower refill - see [budget.rate].
type budget struct {
	tokens float64
	// pings is the separate allowance for join and ping envelopes. See
	// presenceBurst.
	pings float64
	last  time.Time
	// first is when this sender was first heard, which is the whole of
	// what it has to show for itself. Nothing else can be: on a public
	// channel every other signal an endpoint could offer is one it
	// writes about itself, and an endpoint is a keypair. Presence is
	// the one thing a fresh identity cannot have.
	first time.Time
	// speech and presence are the refusal state of the two allowances,
	// one each rather than one per sender: sharing would let a sender
	// flooding one of them use up the reporting interval and so
	// silence the other. The pair that matters is a member talking
	// hard enough to be rate limited whose presence is also being
	// refused - the speech is a nuisance and the presence is this node
	// dropping a live member from its roster, and a reader that is
	// shown only the nuisance has been told the wrong thing.
	speech, presence run
}

// A run is one allowance's refusals: how many envelopes it has turned
// away since it last said so, and when that was.
type run struct {
	refused  int
	reported time.Time
}

// refuse counts one refusal and returns how many to report, which is
// zero unless [refusalReport] has passed since the last report.
//
// What is rate limited is the reporting, not the refusing, and the
// clock is the only thing that governs it. The obvious alternative is
// an edge - report the first refusal after an envelope gets through -
// which sounds like once per flood and is not: a sender refused every
// other envelope is cleared by the ones it lands, so it reports every
// single refusal. A flood is exactly the traffic that alternates like
// that, because a bucket that is refusing is also refilling.
func (r *run) refuse(now time.Time) int {
	r.refused++
	if now.Sub(r.reported) < refusalReport {
		return 0
	}
	r.reported = now
	n := r.refused
	r.refused = 0
	return n
}

// presenceRefill is how fast the presence allowance refills. Presence is
// periodic by design, so the rate is read off the interval it is sent on
// rather than picked: at half of it an honest member's allowance is
// always full, and a sender that announces itself twice as often as the
// protocol asks is the first one this limit binds on.
func presenceRefill() time.Duration { return presenceInterval / 2 }

// budgets is the message allowance of every sender heard from lately.
type budgets map[key.EndpointID]*budget

// rate returns the bucket size and refill interval this sender has
// earned by now. They run from the newcomer numbers to the settled ones
// over [warmup], linearly, so there is no cliff for an attacker to time
// a burst against.
func (x *budget) rate(now time.Time) (size float64, refill time.Duration) {
	earned := min(1, now.Sub(x.first).Seconds()/warmup.Seconds())
	size = newcomerBurst + earned*(sendBurst-newcomerBurst)
	refill = newcomerInterval - time.Duration(earned*float64(newcomerInterval-sendInterval))
	return size, refill
}

// spend reports whether from may deliver an envelope of kind k holding
// size bytes of text at now, and how many refusals to report. It records
// the spend either way.
//
// The count is zero when there is nothing to say, one at the first
// refusal of a run, and however many were turned away since the last
// report each [refusalReport] the run goes on for. It is a count since
// the previous report rather than a total: what a run refused in its
// last unreported fraction of an interval is never said, because saying
// it would mean reporting on the path where the sender succeeded. Presence is charged to its own
// allowance; everything else comes out of the message budget, a token
// for the envelope and one more per [bytesPerToken].
//
// admitted says the sender passed a door on the way in: a sealed
// channel's founder checked the invite secret before committing the
// member, so the identity was not free and the warm-up would be
// charging twice. A public channel has no door, and there is no action
// on one that could serve as a substitute - every claim a stranger
// could make there is one it makes about itself.
func (b budgets) spend(from key.EndpointID, k kind, size int, now time.Time, admitted bool) (ok bool, refused int) {
	x := b[from]
	if x == nil {
		x = &budget{tokens: newcomerBurst, pings: presenceBurst, last: now, first: now}
		if admitted {
			x.tokens = sendBurst
		}
		b[from] = x
	}
	burst, refill := float64(sendBurst), sendInterval
	if !admitted {
		burst, refill = x.rate(now)
	}
	elapsed := now.Sub(x.last).Seconds()
	x.tokens = min(burst, x.tokens+elapsed/refill.Seconds())
	x.pings = min(presenceBurst, x.pings+elapsed/presenceRefill().Seconds())
	x.last = now

	// The charge is capped at the burst it is charged against. A bucket
	// fills to its burst and no further, so a message that costs more
	// than the burst is not rate limited, it is undeliverable: refused
	// now, refused after a refill, refused forever. The largest envelope
	// the protocol carries costs nine tokens, which is well inside a
	// settled sender's burst and nowhere near a newcomer's two, so
	// without this a newcomer could never say a long line at all - and a
	// limit that silently turns into a size limit is neither. Capping
	// costs a newcomer its whole allowance for one long line, which is
	// the price of saying it, and leaves the settled case untouched:
	// sendBurst is above what any envelope can cost.
	spent, cost, r := &x.tokens, min(float64(1+size/bytesPerToken), burst), &x.speech
	if k == kindJoin || k == kindPing {
		// Presence carries no text worth weighing, and its allowance is
		// counted in announcements rather than bytes.
		spent, cost, r = &x.pings, 1, &x.presence
	}
	if *spent < cost {
		return false, r.refuse(now)
	}
	*spent -= cost
	return true, 0
}

// prune forgets senders not heard from for [budgetIdle]. The table is
// itself per-sender state an attacker would otherwise grow, so it has to
// be bounded by something, and silence is the only thing available.
//
// Forgetting can only cost the sender: an entry missing from the table
// is treated as a newcomer, which is the strictest thing this node
// offers. A member that goes quiet for [budgetIdle] and comes back
// therefore serves its warm-up again. That is the right way round -
// erring towards forgetting standing rather than towards inventing it -
// and it is why standing is never written down anywhere.
func (b budgets) prune(now time.Time) {
	for id, x := range b {
		if now.Sub(x.last) > budgetIdle {
			delete(b, id)
		}
	}
}
