package dtrain

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"
)

func TestBroadcastAndBarrier(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	nodes, groups := newAllReduceGroups(t, ctx, 3)
	defer closeGroups(groups)
	defer closeNodes(ctx, nodes)

	want := []byte("rank-zero-parameters")
	got := make([][]byte, len(groups))
	errs := make([]error, len(groups))
	var wg sync.WaitGroup
	for i, g := range groups {
		wg.Add(1)
		go func(i int, g *Group) {
			defer wg.Done()
			var in []byte
			if g.Rank() == 0 {
				in = want
			}
			got[i], errs[i] = g.Broadcast(ctx, in)
		}(i, g)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("peer %d Broadcast: %v", i, err)
		}
		if !bytes.Equal(got[i], want) {
			t.Fatalf("peer %d Broadcast = %q, want %q", i, got[i], want)
		}
	}

	errs = make([]error, len(groups))
	for i, g := range groups {
		wg.Add(1)
		go func(i int, g *Group) {
			defer wg.Done()
			errs[i] = g.Barrier(ctx)
		}(i, g)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("peer %d Barrier: %v", i, err)
		}
	}
}
