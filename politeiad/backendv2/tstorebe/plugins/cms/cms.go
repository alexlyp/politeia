// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cms

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/plugins/cms"
	"github.com/decred/politeia/util"
)

var (
	_ plugins.PluginClient = (*cmsPlugin)(nil)
)

// cmsPlugin is the tstore backend implementation of the cms plugin. The cms
// plugin extends a record with functionality specific to the decred invoice
// system.
//
// cmsPlugin satisfies the plugins PluginClient interface.
type cmsPlugin struct {
	backend backend.Backend

	// dataDir is the cms plugin data directory. The only data that is
	// stored here is cached data that can be re-created at any time
	// by walking the trillian trees.
	dataDir string

	// Plugin settings
	textFileCountMax          uint32
	textFileSizeMax           uint32 // In bytes
	imageFileCountMax         uint32
	imageFileSizeMax          uint32 // In bytes
	invoiceNameSupportedChars string // JSON encoded []string
	invoiceNameLengthMin      uint32 // In characters
	invoiceNameLengthMax      uint32 // In characters
	invoiceNameRegexp         *regexp.Regexp
}

// Setup performs any plugin setup that is required.
//
// This function satisfies the plugins PluginClient interface.
func (c *cmsPlugin) Setup() error {
	log.Tracef("cms Setup")

	return nil
}

// Cmd executes a plugin command.
//
// This function satisfies the plugins PluginClient interface.
func (c *cmsPlugin) Cmd(token []byte, cmd, payload string) (string, error) {
	log.Tracef("cms Cmd: %x %v %v", token, cmd, payload)

	return "", backend.ErrPluginCmdInvalid
}

// Hook executes a plugin hook.
//
// This function satisfies the plugins PluginClient interface.
func (c *cmsPlugin) Hook(h plugins.HookT, payload string) error {
	log.Tracef("cms Hook: %v", plugins.Hooks[h])

	switch h {
	case plugins.HookTypeNewRecordPre:
		return c.hookNewRecordPre(payload)
	case plugins.HookTypeEditRecordPre:
		return c.hookEditRecordPre(payload)
	case plugins.HookTypePluginPre:
		return c.hookPluginPre(payload)
	}

	return nil
}

// Fsck performs a plugin filesystem check.
//
// This function satisfies the plugins PluginClient interface.
func (c *cmsPlugin) Fsck() error {
	log.Tracef("cms Fsck")

	return nil
}

// Settings returns the plugin's settings.
//
// This function satisfies the plugins PluginClient interface.
func (c *cmsPlugin) Settings() []backend.PluginSetting {
	log.Tracef("cms Settings")

	return []backend.PluginSetting{
		{
			Key:   cms.SettingKeyTextFileSizeMax,
			Value: strconv.FormatUint(uint64(c.textFileSizeMax), 10),
		},
		{
			Key:   cms.SettingKeyImageFileCountMax,
			Value: strconv.FormatUint(uint64(c.imageFileCountMax), 10),
		},
		{
			Key:   cms.SettingKeyImageFileCountMax,
			Value: strconv.FormatUint(uint64(c.imageFileCountMax), 10),
		},
		{
			Key:   cms.SettingKeyImageFileSizeMax,
			Value: strconv.FormatUint(uint64(c.imageFileSizeMax), 10),
		},
		{
			Key:   cms.SettingKeyInvoiceNameLengthMin,
			Value: strconv.FormatUint(uint64(c.invoiceNameLengthMin), 10),
		},
		{
			Key:   cms.SettingKeyInvoiceNameLengthMax,
			Value: strconv.FormatUint(uint64(c.invoiceNameLengthMax), 10),
		},
		{
			Key:   cms.SettingKeyInvoiceNameSupportedChars,
			Value: c.invoiceNameSupportedChars,
		},
	}
}

// New returns a new cmsPlugin.
func New(backend backend.Backend, settings []backend.PluginSetting, dataDir string) (*cmsPlugin, error) {
	// Create plugin data directory
	dataDir = filepath.Join(dataDir, cms.PluginID)
	err := os.MkdirAll(dataDir, 0700)
	if err != nil {
		return nil, err
	}

	// Setup plugin setting default values
	var (
		textFileSizeMax    = cms.SettingTextFileSizeMax
		imageFileCountMax  = cms.SettingImageFileCountMax
		imageFileSizeMax   = cms.SettingImageFileSizeMax
		nameLengthMin      = cms.SettingInvoiceNameLengthMin
		nameLengthMax      = cms.SettingInvoiceNameLengthMax
		nameSupportedChars = cms.SettingInvoiceNameSupportedChars
	)

	// Override defaults with any passed in settings
	for _, v := range settings {
		switch v.Key {
		case cms.SettingKeyTextFileSizeMax:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			textFileSizeMax = uint32(u)
		case cms.SettingKeyImageFileCountMax:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			imageFileCountMax = uint32(u)
		case cms.SettingKeyImageFileSizeMax:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			imageFileSizeMax = uint32(u)
		case cms.SettingKeyInvoiceNameLengthMin:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			nameLengthMin = uint32(u)
		case cms.SettingKeyInvoiceNameLengthMax:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			nameLengthMax = uint32(u)
		case cms.SettingKeyInvoiceNameSupportedChars:
			var sc []string
			err := json.Unmarshal([]byte(v.Value), &sc)
			if err != nil {
				return nil, fmt.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			nameSupportedChars = sc
		default:
			return nil, fmt.Errorf("invalid plugin setting: %v", v.Key)
		}
	}

	// Setup invoice name regex
	rexp, err := util.Regexp(nameSupportedChars, uint64(nameLengthMin),
		uint64(nameLengthMax))
	if err != nil {
		return nil, fmt.Errorf("invoice name regexp: %v", err)
	}

	// Encode the supported chars so that they can be returned as a
	// plugin setting string.
	b, err := json.Marshal(nameSupportedChars)
	if err != nil {
		return nil, err
	}
	nameSupportedCharsString := string(b)

	return &cmsPlugin{
		dataDir:                   dataDir,
		backend:                   backend,
		textFileSizeMax:           textFileSizeMax,
		imageFileCountMax:         imageFileCountMax,
		imageFileSizeMax:          imageFileSizeMax,
		invoiceNameLengthMin:      nameLengthMin,
		invoiceNameLengthMax:      nameLengthMax,
		invoiceNameSupportedChars: nameSupportedCharsString,
		invoiceNameRegexp:         rexp,
	}, nil
}
