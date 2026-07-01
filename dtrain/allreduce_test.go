package dtrain

import (
	"context"
	"math"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
)

func TestAllReduce(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	nodes, groups := newAllReduceGroups(t, ctx, 4)
	defer closeGroups(groups)
	defer closeNodes(ctx, nodes)

	tests := []struct {
		name   string
		op     Op
		inputs [][]float32
		want   []float32
	}{
		{
			name: "sum",
			op:   Sum,
			inputs: [][]float32{
				{1, 2, 3, 4, 5},
				{10, 20, 30, 40, 50},
				{100, 200, 300, 400, 500},
				{7, 8, 9, 10, 11},
			},
			want: []float32{118, 230, 342, 454, 566},
		},
		{
			name: "mean",
			op:   Mean,
			inputs: [][]float32{
				{1, 5, 9},
				{3, 7, 11},
				{5, 9, 13},
				{7, 11, 15},
			},
			want: []float32{4, 8, 12},
		},
		{
			name: "max",
			op:   Max,
			inputs: [][]float32{
				{1, 9, 2, -1},
				{3, 4, 8, -2},
				{0, 7, 6, -3},
				{2, 6, 5, -4},
			},
			want: []float32{3, 9, 8, -1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := runAllReduce(t, ctx, groups, tt.inputs, tt.op)
			for i, values := range got {
				if !closeFloat32s(values, tt.want) {
					t.Fatalf("peer %d result = %v, want %v", i, values, tt.want)
				}
			}
		})
	}
}

func BenchmarkAllReduce1M(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping mesh benchmark in short mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	nodes, groups := newAllReduceGroups(b, ctx, 3)
	defer closeGroups(groups)
	defer closeNodes(ctx, nodes)

	inputs := make([][]float32, len(groups))
	for i := range inputs {
		inputs[i] = make([]float32, 1_000_000)
		for j := range inputs[i] {
			inputs[i][j] = float32(i + 1)
		}
	}
	b.SetBytes(int64(len(inputs[0]) * 4 * len(groups)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		runAllReduce(b, ctx, groups, inputs, Sum)
	}
}

type testingTB interface {
	Helper()
	Fatal(args ...any)
	Fatalf(string, ...any)
}

func newAllReduceGroups(tb testingTB, ctx context.Context, n int) ([]testNode, []*Group) {
	tb.Helper()
	nodes := make([]testNode, n)
	for i := range nodes {
		nodes[i] = newDtrainNode(tb, ctx)
	}
	groups := make([]*Group, n)
	for i := range groups {
		var bootstrap []netaddr.EndpointAddr
		for j := 0; j < i; j++ {
			bootstrap = append(bootstrap, nodes[j].addr())
		}
		var err error
		groups[i], err = JoinGroupWithHandler(ctx, nodes[i].ep, nodes[i].gossip, nodes[i].dtrain, "allreduce", bootstrap)
		if err != nil {
			closeNodes(ctx, nodes)
			tb.Fatal(err)
		}
	}
	if err := waitFor(ctx, func() bool {
		want := rankedIDs(groups[0].Members())
		if len(want) != n {
			return false
		}
		for _, g := range groups[1:] {
			if !sameStrings(rankedIDs(g.Members()), want) {
				return false
			}
		}
		for _, g := range groups {
			for _, m := range g.Members() {
				if m.Addr.IsEmpty() {
					return false
				}
			}
		}
		return true
	}); err != nil {
		closeGroups(groups)
		closeNodes(ctx, nodes)
		tb.Fatal(err)
	}
	return nodes, groups
}

func newDtrainNode(tb testingTB, ctx context.Context) testNode {
	tb.Helper()
	ep, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		tb.Fatal(err)
	}
	gg := gossip.NewGossip(ep)
	dh := NewHandler()
	router, err := iroh.NewRouter(ep, map[string]iroh.ProtocolHandler{
		gossip.ALPN: gg.Handler(),
		ALPN:        dh,
	}, nil)
	if err != nil {
		_ = ep.Shutdown(ctx)
		tb.Fatal(err)
	}
	return testNode{ep: ep, gossip: gg, dtrain: dh, router: router}
}

func runAllReduce(tb testingTB, ctx context.Context, groups []*Group, inputs [][]float32, op Op) [][]float32 {
	tb.Helper()
	out := make([][]float32, len(groups))
	errs := make([]error, len(groups))
	var wg sync.WaitGroup
	for i := range groups {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			out[i], errs[i] = groups[i].AllReduce(ctx, inputs[i], op)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			tb.Fatalf("peer %d AllReduce: %v", i, err)
		}
	}
	return out
}

func closeGroups(groups []*Group) {
	for i := len(groups) - 1; i >= 0; i-- {
		_ = groups[i].Close()
	}
}

func closeNodes(ctx context.Context, nodes []testNode) {
	for i := len(nodes) - 1; i >= 0; i-- {
		nodes[i].close(ctx)
	}
}

func closeFloat32s(got, want []float32) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if math.Abs(float64(got[i]-want[i])) > 1e-5 {
			return false
		}
	}
	return true
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
