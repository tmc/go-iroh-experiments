package pkarrnaming

import (
	"context"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/key"
)

// Client publishes and resolves pkarr content names.
type Client interface {
	Publish(ctx context.Context, sk key.SecretKey, r blobs.HashAndFormat) error
	Resolve(ctx context.Context, pk key.PublicKey) (blobs.HashAndFormat, error)
}

// Publisher publishes content names.
type Publisher struct {
	c Client
}

// NewPublisher returns a publisher using c.
func NewPublisher(c Client) *Publisher { return &Publisher{c: c} }

// Publish publishes r under sk.
func (p *Publisher) Publish(ctx context.Context, sk key.SecretKey, r blobs.HashAndFormat) error {
	return p.c.Publish(ctx, sk, r)
}

// Resolver resolves content names.
type Resolver struct {
	c Client
}

// NewResolver returns a resolver using c.
func NewResolver(c Client) *Resolver { return &Resolver{c: c} }

// Resolve resolves the content record published by pk.
func (r *Resolver) Resolve(ctx context.Context, pk key.PublicKey) (blobs.HashAndFormat, error) {
	return r.c.Resolve(ctx, pk)
}
