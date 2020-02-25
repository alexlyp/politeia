// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package codestats

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"sync/atomic"

	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrwallet/errors/v2"
	"github.com/decred/dcrwallet/rpc/client/dcrd"
	"github.com/jrick/wsrpc/v2"
)

var requiredAPIVersion = semver{Major: 1, Minor: 0, Patch: 0}

// Syncer implements wallet synchronization services by processing
// notifications from a dcrd JSON-RPC server.
type Syncer struct {
	opts     *RPCOptions
	rpc      *dcrd.RPC
	notifier *notifier
}

// RPCOptions specifies the network and security settings for establishing a
// websocket connection to a dcrd JSON-RPC server.
type RPCOptions struct {
	Address     string
	DefaultPort string
	User        string
	Pass        string
	Dial        func(ctx context.Context, network, address string) (net.Conn, error)
	CA          []byte
	Insecure    bool
}

// NewSyncer creates a Syncer that will sync the wallet using dcrd JSON-RPC.
func NewSyncer(r *RPCOptions) *Syncer {
	return &Syncer{
		opts: r,
	}
}

func normalizeAddress(addr string, defaultPort string) (hostport string, err error) {
	host, port, origErr := net.SplitHostPort(addr)
	if origErr == nil {
		return net.JoinHostPort(host, port), nil
	}
	addr = net.JoinHostPort(addr, defaultPort)
	_, _, err = net.SplitHostPort(addr)
	if err != nil {
		return "", origErr
	}
	return addr, nil
}

// Connect attempts to connect to the github-tracker server and then proceeds to
// request an update to it's data set.  Upon completion, it will notify that
// the data is up to date and ready to be queried for various codestats.
func (s *Syncer) Connect(ctx context.Context) (err error) {
	s.notifier = &notifier{
		syncer: s,
		ctx:    ctx,
		closed: make(chan struct{}),
	}
	addr, err := normalizeAddress(s.opts.Address, s.opts.DefaultPort)
	if err != nil {
		return errors.E(errors.Invalid, err)
	}
	if s.opts.Insecure {
		addr = "ws://" + addr + "/ws"
	} else {
		addr = "wss://" + addr + "/ws"
	}
	opts := make([]wsrpc.Option, 0, 5)
	opts = append(opts, wsrpc.WithBasicAuth(s.opts.User, s.opts.Pass))
	opts = append(opts, wsrpc.WithNotifier(s.notifier))
	opts = append(opts, wsrpc.WithoutPongDeadline())
	if s.opts.Dial != nil {
		opts = append(opts, wsrpc.WithDial(s.opts.Dial))
	}
	if len(s.opts.CA) != 0 && !s.opts.Insecure {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(s.opts.CA)
		tc := &tls.Config{
			RootCAs: pool,
		}
		opts = append(opts, wsrpc.WithTLSConfig(tc))
	}
	client, err := wsrpc.Dial(ctx, addr, opts...)
	if err != nil {
		return err
	}
	defer client.Close()
	s.rpc = dcrd.New(client)

	// Verify that the server is running on the expected network.
	var netID wire.CurrencyNet
	err = s.rpc.Call(ctx, "getcurrentnet", &netID)
	if err != nil {
		return err
	}
	if netID != params.Net {
		return errors.E("mismatched networks")
	}

	// Ensure the RPC server has a compatible API version.
	var api struct {
		Version semver `json:"dcrdjsonrpcapi"`
	}
	err = s.rpc.Call(ctx, "version", &api)
	if err != nil {
		return err
	}
	if !semverCompatible(requiredAPIVersion, api.Version) {
		return errors.Errorf("advertised API version %v incompatible "+
			"with required version %v", api.Version, requiredAPIVersion)
	}

	// Wait for notifications to finish before returning
	defer func() {
		<-s.notifier.closed
	}()

	select {
	case <-ctx.Done():
		client.Close()
		return ctx.Err()
	case <-client.Done():
		return client.Err()
	}
}

type notifier struct {
	atomicClosed     uint32
	syncer           *Syncer
	ctx              context.Context
	closed           chan struct{}
	connectingBlocks bool
}

func (n *notifier) Notify(method string, params json.RawMessage) error {
	/*
		s := n.syncer
		op := errors.Op(method)
		ctx, task := trace.NewTask(n.ctx, method)
		defer task.End()
		switch method {
		case "winningtickets":
			return nil
		}
	*/
	return nil
}

func (n *notifier) Close() error {
	if atomic.CompareAndSwapUint32(&n.atomicClosed, 0, 1) {
		close(n.closed)
	}
	return nil
}
