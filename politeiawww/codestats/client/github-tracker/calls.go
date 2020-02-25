// Copyright (c) 2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// TODO: consistent error wrapping

package github-tracker

import (
	"context"

	"github.com/decred/dcrwallet/errors/v2"
)

// Caller provides a client interface to perform JSON-RPC remote procedure calls.
type Caller interface {
	// Call performs the remote procedure call defined by method and
	// waits for a response or a broken client connection.
	// Args provides positional parameters for the call.
	// Res must be a pointer to a struct, slice, or map type to unmarshal
	// a result (if any), or nil if no result is needed.
	Call(ctx context.Context, method string, res interface{}, args ...interface{}) error
}

// RPC provides methods for calling dcrd JSON-RPCs without exposing the details
// of JSON encoding.
type RPC struct {
	Caller
}

// New creates a new RPC client instance from a caller.
func New(caller Caller) *RPC {
	return &RPC{caller}
}

// Update returns whether a ticket identified by its hash is currently
// live and not immature.
func (r *RPC) Update(ctx context.Context) error {
	const op errors.Op = "github-tracker.Update"
	err := r.Call(ctx, "update", nil)
	if err != nil {
		return errors.E(op, err)
	}
	return err
}

/*
// PublishTransaction submits the transaction to dcrd mempool for acceptance.
// If accepted, the transaction is published to other peers.
// The transaction may not be an orphan.
func (r *RPC) PublishTransaction(ctx context.Context, tx *wire.MsgTx) error {
	const op errors.Op = "dcrd.PublishTransaction"
	var b strings.Builder
	b.Grow(tx.SerializeSize() * 2)
	err := tx.Serialize(hex.NewEncoder(&b))
	if err != nil {
		return errors.E(op, errors.Encoding, err)
	}
	err = r.Call(ctx, "sendrawtransaction", nil, b.String())
	if err != nil {
		// Duplicate txs are not considered an error
		var e *wsrpc.Error
		if errors.As(err, &e) && e.Code == codeDuplicateTx {
			return nil
		}
		return errors.E(op, err)
	}
	return nil
}

// Blocks returns the blocks for each block hash.
func (r *RPC) Blocks(ctx context.Context, blockHashes []*chainhash.Hash) ([]*wire.MsgBlock, error) {
	const op errors.Op = "dcrd.Blocks"

	blocks := make([]*wire.MsgBlock, len(blockHashes))
	var g errgroup.Group
	for i := range blockHashes {
		i := i
		g.Go(func() error {
			blocks[i] = new(wire.MsgBlock)
			return r.Call(ctx, "getblock", unhex(blocks[i]), blockHashes[i].String(), false)
		})
	}
	err := g.Wait()
	if err != nil {
		return nil, errors.E(op, err)
	}
	return blocks, nil
}

// Headers returns the block headers starting at the fork point between the
// client and the dcrd server identified by the client's block locators.
func (r *RPC) Headers(ctx context.Context, blockLocators []*chainhash.Hash, hashStop *chainhash.Hash) ([]*wire.BlockHeader, error) {
	const op errors.Op = "dcrd.Headers"

	res := &struct {
		Headers *headers `json:"headers"`
	}{
		Headers: new(headers),
	}
	err := r.Call(ctx, "getheaders", res, &hashes{blockLocators}, hashStop.String())
	if err != nil {
		return nil, errors.E(op, err)
	}
	return res.Headers.Headers, nil
}
*/
