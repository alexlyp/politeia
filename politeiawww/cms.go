// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"net/http"

	cmsplugin "github.com/decred/politeia/politeiad/plugins/cms"
	cmplugin "github.com/decred/politeia/politeiad/plugins/comments"
	umplugin "github.com/decred/politeia/politeiad/plugins/usermd"
	cmsv2 "github.com/decred/politeia/politeiawww/api/cms/v2"
	cmv1 "github.com/decred/politeia/politeiawww/api/comments/v1"
	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/cms"
	"github.com/decred/politeia/politeiawww/comments"
	"github.com/decred/politeia/politeiawww/records"
	"github.com/google/uuid"
)

// setupCmsRoutes sets up the API routes for cmswww mode.
func (p *politeiawww) setupCmsRoutes(r *records.Records, c *comments.Comments, cis *cms.Cms) {
	// Return a 404 when a route is not found
	p.router.NotFoundHandler = http.HandlerFunc(p.handleNotFound)

	// The version routes set the CSRF token and thus need to be part
	// of the CSRF protected auth router.
	p.auth.HandleFunc("/", p.handleVersion).Methods(http.MethodGet)
	p.auth.StrictSlash(true).
		HandleFunc(www.PoliteiaWWWAPIRoute+www.RouteVersion, p.handleVersion).
		Methods(http.MethodGet)

	// Legacy www routes. These routes have been DEPRECATED. Support
	// will be removed in a future release.
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RoutePolicy, p.handlePolicy,
		permissionPublic)
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteTokenInventory, p.handleTokenInventory,
		permissionPublic)
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteAllVetted, p.handleAllVetted,
		permissionPublic)
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteProposalDetails, p.handleProposalDetails,
		permissionPublic)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteBatchProposals, p.handleBatchProposals,
		permissionPublic)
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteVoteStatus, p.handleVoteStatus,
		permissionPublic)
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteAllVoteStatus, p.handleAllVoteStatus,
		permissionPublic)
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteActiveVote, p.handleActiveVote,
		permissionPublic)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteCastVotes, p.handleCastVotes,
		permissionPublic)
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteVoteResults, p.handleVoteResults,
		permissionPublic)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteBatchVoteSummary, p.handleBatchVoteSummary,
		permissionPublic)

	// Record routes
	p.addRoute(http.MethodPost, rcv1.APIRoute,
		rcv1.RouteNew, r.HandleNew,
		permissionLogin)
	p.addRoute(http.MethodPost, rcv1.APIRoute,
		rcv1.RouteEdit, r.HandleEdit,
		permissionLogin)
	p.addRoute(http.MethodPost, rcv1.APIRoute,
		rcv1.RouteSetStatus, r.HandleSetStatus,
		permissionAdmin)
	p.addRoute(http.MethodPost, rcv1.APIRoute,
		rcv1.RouteDetails, r.HandleDetails,
		permissionPublic)
	p.addRoute(http.MethodPost, rcv1.APIRoute,
		rcv1.RouteTimestamps, r.HandleTimestamps,
		permissionPublic)
	p.addRoute(http.MethodPost, rcv1.APIRoute,
		rcv1.RouteRecords, r.HandleRecords,
		permissionPublic)
	p.addRoute(http.MethodPost, rcv1.APIRoute,
		rcv1.RouteInventory, r.HandleInventory,
		permissionPublic)
	p.addRoute(http.MethodPost, rcv1.APIRoute,
		rcv1.RouteInventoryOrdered, r.HandleInventoryOrdered,
		permissionPublic)
	p.addRoute(http.MethodPost, rcv1.APIRoute,
		rcv1.RouteUserRecords, r.HandleUserRecords,
		permissionPublic)

	// Comment routes
	p.addRoute(http.MethodPost, cmv1.APIRoute,
		cmv1.RoutePolicy, c.HandlePolicy,
		permissionPublic)
	p.addRoute(http.MethodPost, cmv1.APIRoute,
		cmv1.RouteNew, c.HandleNew,
		permissionLogin)
	p.addRoute(http.MethodPost, cmv1.APIRoute,
		cmv1.RouteVote, c.HandleVote,
		permissionLogin)
	p.addRoute(http.MethodPost, cmv1.APIRoute,
		cmv1.RouteDel, c.HandleDel,
		permissionAdmin)
	p.addRoute(http.MethodPost, cmv1.APIRoute,
		cmv1.RouteCount, c.HandleCount,
		permissionPublic)
	p.addRoute(http.MethodPost, cmv1.APIRoute,
		cmv1.RouteComments, c.HandleComments,
		permissionPublic)
	p.addRoute(http.MethodPost, cmv1.APIRoute,
		cmv1.RouteVotes, c.HandleVotes,
		permissionPublic)
	p.addRoute(http.MethodPost, cmv1.APIRoute,
		cmv1.RouteTimestamps, c.HandleTimestamps,
		permissionPublic)

	// Cms routes
	p.addRoute(http.MethodPost, cmsv2.APIRoute,
		cmsv2.RoutePolicy, cis.HandlePolicy,
		permissionPublic)
}

func (p *politeiawww) setupCms() error {
	// Get politeiad plugins
	plugins, err := p.getPluginInventory()
	if err != nil {
		return fmt.Errorf("getPluginInventory: %v", err)
	}

	// Verify all required politeiad plugins have been registered
	required := map[string]bool{
		cmsplugin.PluginID: false,
		cmplugin.PluginID:  false,
		umplugin.PluginID:  false,
	}
	for _, v := range plugins {
		_, ok := required[v.ID]
		if !ok {
			// Not a required plugin. Skip.
			continue
		}
		required[v.ID] = true
	}
	notFound := make([]string, 0, len(required))
	for pluginID, wasFound := range required {
		if !wasFound {
			notFound = append(notFound, pluginID)
		}
	}
	if len(notFound) > 0 {
		return fmt.Errorf("required politeiad plugins not found: %v", notFound)
	}

	// Setup api contexts
	recordsCtx := records.New(p.cfg, p.politeiad, p.db, p.sessions, p.events)
	commentsCtx, err := comments.New(p.cfg, p.politeiad, p.db,
		p.sessions, p.events, plugins)
	if err != nil {
		return fmt.Errorf("new comments api: %v", err)
	}
	cmsCtx, err := cms.New(p.cfg, p.politeiad, p.db,
		p.sessions, p.events, p.mail, plugins)
	if err != nil {
		return fmt.Errorf("new cms api: %v", err)
	}

	// Setup routes
	p.setUserWWWRoutes()
	p.setupCmsRoutes(recordsCtx, commentsCtx, cmsCtx)

	// Verify paywall settings
	switch {
	case p.cfg.PaywallAmount != 0 && p.cfg.PaywallXpub != "":
		// Paywall is enabled
		paywallAmountInDcr := float64(p.cfg.PaywallAmount) / 1e8
		log.Infof("Paywall : %v DCR", paywallAmountInDcr)

	case p.cfg.PaywallAmount == 0 && p.cfg.PaywallXpub == "":
		// Paywall is disabled
		log.Infof("Paywall: DISABLED")

	default:
		// Invalid paywall setting
		return fmt.Errorf("paywall settings invalid, both an amount " +
			"and public key MUST be set")
	}

	// Setup paywall pool
	p.userPaywallPool = make(map[uuid.UUID]paywallPoolMember)
	err = p.initPaywallChecker()
	if err != nil {
		return err
	}

	return nil
}
