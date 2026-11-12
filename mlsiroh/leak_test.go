package mlsiroh

import (
	"context"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/mls"
)

// TestDirectoryLeavesNothingRunning fetches a key package and a
// GroupInfo, delivers a Welcome, closes each directory twice at once,
// and checks that every goroutine the directories started has gone and
// that the Welcomes stream ended.
func TestDirectoryLeavesNothingRunning(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	base := runtime.NumGoroutine()
	t.Run("session", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		alice, bob := newNode(t, ctx), newNode(t, ctx)
		bob.publish(t, 1)
		bobClient, err := NewClient(bob.sk, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if err := bob.dir.Add(bobClient.KeyPackage); err != nil {
			t.Fatal(err)
		}
		bob.dir.LimitKeyPackages(-1, -1, 0)
		if err := bob.dir.PublishGroupInfo(newGroupInfo(t, bob.sk, "g", 0), func(key.EndpointID) bool { return true }); err != nil {
			t.Fatal(err)
		}
		ended := make(chan int)
		go func() {
			n := 0
			for range bob.dir.Welcomes() {
				n++
			}
			ended <- n
		}()

		if _, err := FetchGroupInfo(ctx, alice.ep, bob.addr(), []byte("g")); err != nil {
			t.Fatal(err)
		}
		aliceClient, err := NewClient(alice.sk, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		g, err := aliceClient.NewGroup([]byte("h"), nil)
		if err != nil {
			t.Fatal(err)
		}
		var welcomes []*mls.Welcome
		for range 2 {
			kp, err := FetchKeyPackage(ctx, alice.ep, bob.addr(), Suite)
			if err != nil {
				t.Fatal(err)
			}
			_, _, w, err := g.Commit([]*mls.Proposal{{Type: mls.ProposalTypeAdd, Add: &mls.Add{KeyPackage: *kp}}})
			if err != nil {
				t.Fatal(err)
			}
			welcomes = append(welcomes, w.Welcome)
		}
		for _, w := range welcomes {
			if err := DeliverWelcome(ctx, alice.ep, bob.addr(), w); err != nil {
				t.Fatal(err)
			}
		}

		var wg sync.WaitGroup
		for _, d := range []*Directory{alice.dir, bob.dir, alice.dir, bob.dir} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := d.Close(); err != nil {
					t.Errorf("Close = %v", err)
				}
			}()
		}
		wg.Wait()
		select {
		case n := <-ended:
			if n != len(welcomes) {
				t.Errorf("Welcomes yielded %d, want %d", n, len(welcomes))
			}
		case <-ctx.Done():
			t.Fatal("Welcomes did not end after Close")
		}
	})
	deadline := time.Now().Add(15 * time.Second)
	for runtime.NumGoroutine() > base {
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<20)
			buf = buf[:runtime.Stack(buf, true)]
			var ours []string
			for _, g := range strings.Split(string(buf), "\n\n") {
				if strings.Contains(g, "mlsiroh") && !strings.Contains(g, "testing.tRunner") {
					ours = append(ours, g)
				}
			}
			t.Fatalf("%d goroutines, started with %d:\n\n%s", runtime.NumGoroutine(), base, strings.Join(ours, "\n\n"))
		}
		time.Sleep(20 * time.Millisecond)
	}
}
