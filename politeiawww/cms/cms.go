// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cms

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	pdv2 "github.com/decred/politeia/politeiad/api/v2"
	pdclient "github.com/decred/politeia/politeiad/client"
	"github.com/decred/politeia/politeiad/plugins/cms"
	v1 "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/config"
	"github.com/decred/politeia/politeiawww/events"
	"github.com/decred/politeia/politeiawww/mail"
	"github.com/decred/politeia/politeiawww/sessions"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/util"
)

// Cms is the context for the cms API.
type Cms struct {
	cfg       *config.Config
	politeiad *pdclient.Client
	userdb    user.Database
	sessions  *sessions.Sessions
	events    *events.Manager
	mail      *mail.Client
	policy    *v1.PolicyReply
}

// HandlePolicy is the request handler for the cms v1 Policy route.
func (c *Cms) HandlePolicy(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandlePolicy")

	util.RespondWithJSON(w, http.StatusOK, c.policy)
}

// New returns a new Cms context.
func New(cfg *config.Config, pdc *pdclient.Client, udb user.Database, s *sessions.Sessions, e *events.Manager, m *mail.Client, plugins []pdv2.Plugin) (*Cms, error) {
	// Parse plugin settings
	var (
		textFileSizeMax    uint32
		imageFileCountMax  uint32
		imageFileSizeMax   uint32
		nameLengthMin      uint32
		nameLengthMax      uint32
		nameSupportedChars []string
	)
	for _, p := range plugins {
		if p.ID != cms.PluginID {
			// Not the cms plugin; skip
			continue
		}
		for _, v := range p.Settings {
			switch v.Key {
			case cms.SettingKeyTextFileSizeMax:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				textFileSizeMax = uint32(u)
			case cms.SettingKeyImageFileCountMax:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				imageFileCountMax = uint32(u)
			case cms.SettingKeyImageFileSizeMax:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				imageFileSizeMax = uint32(u)
			case cms.SettingKeyInvoiceNameLengthMin:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				nameLengthMin = uint32(u)
			case cms.SettingKeyInvoiceNameLengthMax:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				nameLengthMax = uint32(u)
			case cms.SettingKeyInvoiceNameSupportedChars:
				var sc []string
				err := json.Unmarshal([]byte(v.Value), &sc)
				if err != nil {
					return nil, err
				}
				nameSupportedChars = sc
			default:
				// Skip unknown settings
				log.Warnf("Unknown plugin setting %v; Skipping...", v.Key)
			}
		}
	}

	// Verify all plugin settings have been provided
	switch {
	case textFileSizeMax == 0:
		return nil, fmt.Errorf("plugin setting not found: %v",
			cms.SettingKeyTextFileSizeMax)
	case imageFileCountMax == 0:
		return nil, fmt.Errorf("plugin setting not found: %v",
			cms.SettingKeyImageFileCountMax)
	case imageFileSizeMax == 0:
		return nil, fmt.Errorf("plugin setting not found: %v",
			cms.SettingKeyImageFileSizeMax)
	case nameLengthMin == 0:
		return nil, fmt.Errorf("plugin setting not found: %v",
			cms.SettingKeyInvoiceNameLengthMin)
	case nameLengthMax == 0:
		return nil, fmt.Errorf("plugin setting not found: %v",
			cms.SettingKeyInvoiceNameLengthMax)
	}

	// Setup cms context
	c := Cms{
		cfg:       cfg,
		politeiad: pdc,
		userdb:    udb,
		sessions:  s,
		events:    e,
		mail:      m,
		policy: &v1.PolicyReply{
			TextFileSizeMax:    textFileSizeMax,
			ImageFileCountMax:  imageFileCountMax,
			ImageFileSizeMax:   imageFileSizeMax,
			NameLengthMin:      nameLengthMin,
			NameLengthMax:      nameLengthMax,
			NameSupportedChars: nameSupportedChars,
		},
	}

	// Setup event listeners
	c.setupEventListeners()

	return &c, nil
}
