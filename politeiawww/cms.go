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
	cmsv1 "github.com/decred/politeia/politeiawww/api/cms/v1"
	cmv1 "github.com/decred/politeia/politeiawww/api/comments/v1"
	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/cms"
	"github.com/decred/politeia/politeiawww/comments"
	"github.com/decred/politeia/politeiawww/records"
	"github.com/robfig/cron"
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
	p.addRoute(http.MethodGet, cmsv1.APIRoute,
		www.RoutePolicy, p.handleCMSPolicy,
		permissionPublic)
	p.addRoute(http.MethodPost, cmsv1.APIRoute,
		www.RouteNewComment, p.handleNewCommentInvoice,
		permissionLogin)
	p.addRoute(http.MethodPost, cmsv1.APIRoute,
		cmsv1.RouteNewInvoice, p.handleNewInvoice,
		permissionLogin)
	p.addRoute(http.MethodPost, cmsv1.APIRoute,
		cmsv1.RouteEditInvoice, p.handleEditInvoice,
		permissionLogin)
	p.addRoute(http.MethodGet, cmsv1.APIRoute,
		cmsv1.RouteInvoiceDetails, p.handleInvoiceDetails,
		permissionLogin)
	p.addRoute(http.MethodGet, cmsv1.APIRoute,
		cmsv1.RouteUserInvoices, p.handleUserInvoices,
		permissionLogin)
	p.addRoute(http.MethodPost, cmsv1.APIRoute,
		cmsv1.RouteInvoices, p.handleInvoices,
		permissionLogin)
	p.addRoute(http.MethodGet, cmsv1.APIRoute,
		cmsv1.RouteInvoiceComments, p.handleInvoiceComments,
		permissionLogin)
	p.addRoute(http.MethodPost, cmsv1.APIRoute,
		cmsv1.RouteInvoiceExchangeRate, p.handleInvoiceExchangeRate,
		permissionLogin)
	p.addRoute(http.MethodPost, cmsv1.APIRoute,
		cmsv1.RouteNewDCC, p.handleNewDCC,
		permissionLogin)
	p.addRoute(http.MethodGet, cmsv1.APIRoute,
		cmsv1.RouteDCCDetails, p.handleDCCDetails,
		permissionLogin)
	p.addRoute(http.MethodPost, cmsv1.APIRoute,
		cmsv1.RouteGetDCCs, p.handleGetDCCs,
		permissionLogin)
	p.addRoute(http.MethodPost, cmsv1.APIRoute,
		cmsv1.RouteSupportOpposeDCC, p.handleSupportOpposeDCC,
		permissionLogin)
	p.addRoute(http.MethodPost, cmsv1.APIRoute,
		cmsv1.RouteNewCommentDCC, p.handleNewCommentDCC,
		permissionLogin)
	p.addRoute(http.MethodGet, cmsv1.APIRoute,
		cmsv1.RouteDCCComments, p.handleDCCComments,
		permissionLogin)
	p.addRoute(http.MethodGet, cmsv1.APIRoute,
		cmsv1.RouteUserSubContractors, p.handleUserSubContractors,
		permissionLogin)
	p.addRoute(http.MethodGet, cmsv1.APIRoute,
		cmsv1.RouteProposalOwner, p.handleProposalOwner,
		permissionLogin)
	p.addRoute(http.MethodPost, cmsv1.APIRoute,
		cmsv1.RouteProposalBilling, p.handleProposalBilling,
		permissionLogin)
	p.addRoute(http.MethodPost, cmsv1.APIRoute,
		cmsv1.RouteCastVoteDCC, p.handleCastVoteDCC,
		permissionLogin)
	p.addRoute(http.MethodPost, cmsv1.APIRoute,
		cmsv1.RouteVoteDetailsDCC, p.handleVoteDetailsDCC,
		permissionLogin)
	p.addRoute(http.MethodGet, cmsv1.APIRoute,
		cmsv1.RouteActiveVotesDCC, p.handleActiveVoteDCC,
		permissionLogin)
	p.addRoute(http.MethodGet, cmsv1.APIRoute,
		www.RouteTokenInventory, p.handlePassThroughTokenInventory,
		permissionLogin)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteBatchProposals, p.handlePassThroughBatchProposals,
		permissionLogin)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteSetTOTP, p.handleSetTOTP,
		permissionLogin)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteVerifyTOTP, p.handleVerifyTOTP,
		permissionLogin)
	p.addRoute(http.MethodPost, cmsv1.APIRoute,
		cmsv1.RouteUserCodeStats, p.handleUserCodeStats,
		permissionLogin)

	// Unauthenticated websocket
	p.addRoute("", www.PoliteiaWWWAPIRoute,
		www.RouteUnauthenticatedWebSocket, p.handleUnauthenticatedWebsocket,
		permissionPublic)
	// Authenticated websocket
	p.addRoute("", www.PoliteiaWWWAPIRoute,
		www.RouteAuthenticatedWebSocket, p.handleAuthenticatedWebsocket,
		permissionLogin)

	// Routes that require being logged in as an admin user.
	p.addRoute(http.MethodPost, cmsv1.APIRoute,
		cmsv1.RouteInviteNewUser, p.handleInviteNewUser,
		permissionAdmin)
	p.addRoute(http.MethodPost, cmsv1.APIRoute,
		cmsv1.RouteSetInvoiceStatus, p.handleSetInvoiceStatus,
		permissionAdmin)
	p.addRoute(http.MethodPost, cmsv1.APIRoute,
		cmsv1.RouteGeneratePayouts, p.handleGeneratePayouts,
		permissionAdmin)
	p.addRoute(http.MethodGet, cmsv1.APIRoute,
		cmsv1.RoutePayInvoices, p.handlePayInvoices,
		permissionAdmin)
	p.addRoute(http.MethodPost, cmsv1.APIRoute,
		cmsv1.RouteInvoicePayouts, p.handleInvoicePayouts,
		permissionAdmin)
	p.addRoute(http.MethodGet, cmsv1.APIRoute,
		cmsv1.RouteAdminUserInvoices, p.handleAdminUserInvoices,
		permissionAdmin)
	p.addRoute(http.MethodPost, cmsv1.APIRoute,
		cmsv1.RouteSetDCCStatus, p.handleSetDCCStatus,
		permissionAdmin)
	p.addRoute(http.MethodPost, cmsv1.APIRoute,
		cmsv1.RouteStartVoteDCC, p.handleStartVoteDCC,
		permissionAdmin)
	p.addRoute(http.MethodGet, cmsv1.APIRoute,
		cmsv1.RouteProposalBillingSummary, p.handleProposalBillingSummary,
		permissionAdmin)
	p.addRoute(http.MethodPost, cmsv1.APIRoute,
		cmsv1.RouteProposalBillingDetails, p.handleProposalBillingDetails,
		permissionAdmin)

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
	/*
	    LEGACY CMSWWW SETUP
	   		// Setup dcrdata websocket connection
	   		ws, err := wsdcrdata.New(p.dcrdataHostWS())
	   		if err != nil {
	   			// Continue even if a websocket connection was not able to be
	   			// made. The application specific websocket setup (pi, cms, etc)
	   			// can decide whether to attempt reconnection or to exit.
	   			log.Errorf("wsdcrdata New: %v", err)
	   		}
	   		p.wsDcrdata = ws

	   		// Setup cmsdb
	   		net := filepath.Base(p.cfg.DataDir)
	   		p.cmsDB, err = cmsdb.New(p.cfg.DBHost, net, p.cfg.DBRootCert,
	   			p.cfg.DBCert, p.cfg.DBKey)
	   		if errors.Is(err, database.ErrNoVersionRecord) || errors.Is(err, database.ErrWrongVersion) {
	   			// The cmsdb version record was either not found or
	   			// is the wrong version which means that the cmsdb
	   			// needs to be built/rebuilt.
	   			p.cfg.BuildCMSDB = true
	   		} else if err != nil {
	   			return err
	   		}
	   		err = p.cmsDB.Setup()
	   		if err != nil {
	   			return fmt.Errorf("cmsdb setup: %v", err)
	   		}

	   		// Build the cms database
	   		if p.cfg.BuildCMSDB {
	   			index := 0
	   			// Do pagination since we can't handle the full payload
	   			count := 50
	   			dbInvs := make([]database.Invoice, 0, 2048)
	   			dbDCCs := make([]database.DCC, 0, 2048)
	   			for {
	   				log.Infof("requesting record inventory index %v of count %v", index, count)
	   				// Request full record inventory from backend
	   				challenge, err := util.Random(pd.ChallengeSize)
	   				if err != nil {
	   					return err
	   				}

	   				pdCommand := pd.Inventory{
	   					Challenge:    hex.EncodeToString(challenge),
	   					IncludeFiles: true,
	   					AllVersions:  true,
	   					VettedCount:  uint(count),
	   					VettedStart:  uint(index),
	   				}

	   				ctx := context.Background()
	   				responseBody, err := p.makeRequest(ctx, http.MethodPost,
	   					pd.InventoryRoute, pdCommand)
	   				if err != nil {
	   					return err
	   				}

	   				var pdReply pd.InventoryReply
	   				err = json.Unmarshal(responseBody, &pdReply)
	   				if err != nil {
	   					return fmt.Errorf("Could not unmarshal InventoryReply: %v",
	   						err)
	   				}

	   				// Verify the UpdateVettedMetadata challenge.
	   				err = util.VerifyChallenge(p.cfg.Identity, challenge, pdReply.Response)
	   				if err != nil {
	   					return err
	   				}

	   				vetted := pdReply.Vetted
	   				for _, r := range vetted {
	   					for _, m := range r.Metadata {
	   						switch m.ID {
	   						case mdstream.IDInvoiceGeneral:
	   							i, err := convertRecordToDatabaseInvoice(r)
	   							if err != nil {
	   								log.Errorf("convertRecordToDatabaseInvoice: %v", err)
	   								break
	   							}
	   							u, err := p.db.UserGetByPubKey(i.PublicKey)
	   							if err != nil {
	   								log.Errorf("usergetbypubkey: %v %v", err, i.PublicKey)
	   								break
	   							}
	   							i.UserID = u.ID.String()
	   							i.Username = u.Username
	   							dbInvs = append(dbInvs, *i)
	   						case mdstream.IDDCCGeneral:
	   							d, err := convertRecordToDatabaseDCC(r)
	   							if err != nil {
	   								log.Errorf("convertRecordToDatabaseDCC: %v", err)
	   								break
	   							}
	   							dbDCCs = append(dbDCCs, *d)
	   						}
	   					}
	   				}
	   				if len(vetted) < count {
	   					break
	   				}
	   				index += count
	   			}

	   			// Build the cache
	   			err = p.cmsDB.Build(dbInvs, dbDCCs)
	   			if err != nil {
	   				return fmt.Errorf("build cache: %v", err)
	   			}
	   		}
	   		if p.cfg.GithubAPIToken != "" {
	   			p.tracker, err = ghtracker.New(p.cfg.GithubAPIToken,
	   				p.cfg.DBHost, p.cfg.DBRootCert, p.cfg.DBCert, p.cfg.DBKey)
	   			if err != nil {
	   				return fmt.Errorf("code tracker failed to load: %v", err)
	   			}
	   			go func() {
	   				err = p.updateCodeStats(p.cfg.CodeStatSkipSync,
	   					p.cfg.CodeStatRepos, p.cfg.CodeStatStart, p.cfg.CodeStatEnd)
	   				if err != nil {
	   					log.Errorf("erroring updating code stats %v", err)
	   				}
	   			}()
	   		}

	   		// Register cms userdb plugin
	   		plugin := user.Plugin{
	   			ID:      user.CMSPluginID,
	   			Version: user.CMSPluginVersion,
	   		}
	   		err = p.db.RegisterPlugin(plugin)
	   		if err != nil {
	   			return fmt.Errorf("register userdb plugin: %v", err)
	   		}
	*/
	// Setup invoice notifications
	p.cron = cron.New()
	p.checkInvoiceNotifications()

	// Setup dcrdata websocket subscriptions and monitoring. This is
	// done in a go routine so cmswww startup will continue in
	// the event that a dcrdata websocket connection was not able to
	// be made during client initialization and reconnection attempts
	// are required.
	go func() {
		p.setupCMSAddressWatcher()
	}()

	return nil
}
