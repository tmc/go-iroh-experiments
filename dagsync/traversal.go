package dagsync

import (
	"fmt"

	"github.com/ipfs/go-cid"
)

func traversalCIDs(opts TraversalOpts, tables *Tables) ([]cid.Cid, error) {
	switch {
	case opts.Sequence != nil:
		out := make([]cid.Cid, len(opts.Sequence.Cids))
		for i, c := range opts.Sequence.Cids {
			out[i] = c.Cid
		}
		return out, nil
	case opts.Full != nil:
		return fullTraversal(opts.Full, tables)
	default:
		return nil, fmt.Errorf("dagsync: empty traversal")
	}
}

func fullTraversal(opts *FullTraversalOpts, tables *Tables) ([]cid.Cid, error) {
	if opts == nil {
		return nil, fmt.Errorf("dagsync: nil full traversal")
	}
	filter := TraversalFilter{All: true}
	if opts.Filter != nil {
		filter = *opts.Filter
	}
	visited := make(map[string]bool)
	for _, c := range opts.Visited {
		visited[c.Cid.KeyString()] = true
	}
	var out []cid.Cid
	stack := []cid.Cid{opts.Root.Cid}
	for len(stack) > 0 {
		c := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if visited[c.KeyString()] {
			continue
		}
		visited[c.KeyString()] = true
		if includeCID(filter, c) {
			out = append(out, c)
		}
		if c.Type() == cid.Raw {
			continue
		}
		links, ok := tables.Links(c)
		if !ok {
			continue
		}
		for i := len(links) - 1; i >= 0; i-- {
			stack = append(stack, links[i])
		}
	}
	return out, nil
}

func includeCID(filter TraversalFilter, c cid.Cid) bool {
	switch {
	case filter.All:
		return true
	case filter.NoRaw:
		return c.Type() != cid.Raw
	case filter.JustRaw:
		return c.Type() == cid.Raw
	case filter.Exclude != nil:
		for _, codec := range filter.Exclude {
			if c.Type() == codec {
				return false
			}
		}
		return true
	default:
		return true
	}
}
