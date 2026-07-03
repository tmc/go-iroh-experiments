package dtrain

import (
	"context"
	"fmt"
	"time"
)

func Example_diloco() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tb := exampleTB{}
	nodes, groups := newAllReduceGroups(tb, ctx, 3)
	defer closeGroups(groups)
	defer closeNodes(ctx, nodes)

	models := make([][]float32, len(groups))
	for i := range models {
		models[i] = []float32{1, 2, 3, 4}
	}

	for outer := 0; outer < 3; outer++ {
		errs := make(chan error, len(groups))
		for i, g := range groups {
			go func(i int, g *Group) {
				for step := 0; step < 2; step++ {
					for j := range models[i] {
						models[i][j] += float32(i+1) * 0.01
					}
				}
				avg, err := g.AllReduce(ctx, models[i], Mean)
				if err == nil {
					models[i] = avg
				}
				errs <- err
			}(i, g)
		}
		for range groups {
			if err := <-errs; err != nil {
				panic(err)
			}
		}
	}

	converged := true
	for _, model := range models[1:] {
		converged = converged && closeFloat32s(model, models[0])
	}
	fmt.Println("converged:", converged)
	fmt.Printf("parameters: %.2f %.2f %.2f %.2f\n", models[0][0], models[0][1], models[0][2], models[0][3])

	// Output:
	// converged: true
	// parameters: 1.12 2.12 3.12 4.12
}

func ExampleGroup_AllGather() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tb := exampleTB{}
	nodes, groups := newAllReduceGroups(tb, ctx, 3)
	defer closeGroups(groups)
	defer closeNodes(ctx, nodes)

	inputs := make([][]float32, len(groups))
	for i, g := range groups {
		rank := g.Rank()
		inputs[i] = []float32{float32(rank), float32(rank + 10)}
	}
	got := runAllGather(tb, ctx, groups, inputs)
	fmt.Println(got[0])

	// Output:
	// [0 10 1 11 2 12]
}

type exampleTB struct{}

func (exampleTB) Helper() {}

func (exampleTB) Fatal(args ...any) {
	panic(fmt.Sprint(args...))
}

func (exampleTB) Fatalf(format string, args ...any) {
	panic(fmt.Sprintf(format, args...))
}
