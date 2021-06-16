// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cms

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	"github.com/decred/politeia/politeiad/plugins/cms"
	"github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/util"
)

// newTestCmsPlugin returns a piPlugin that has been setup for testing.
func newTestCmsPlugin(t *testing.T) (*cmsPlugin, func()) {
	// Create plugin data directory
	dataDir, err := ioutil.TempDir("", cms.PluginID)
	if err != nil {
		t.Fatal(err)
	}

	// Setup proposal name regex
	var (
		nameSupportedChars = cms.SettingInvoiceNameSupportedChars
		nameLengthMin      = cms.SettingInvoiceNameLengthMin
		nameLengthMax      = cms.SettingInvoiceNameLengthMax
	)
	rexp, err := util.Regexp(nameSupportedChars, uint64(nameLengthMin),
		uint64(nameLengthMax))
	if err != nil {
		t.Fatal(err)
	}

	// Encode the supported chars. This is done so that they can be
	// returned as a plugin setting string.
	b, err := json.Marshal(nameSupportedChars)
	if err != nil {
		t.Fatal(err)
	}
	nameSupportedCharsString := string(b)

	// Setup plugin context
	c := cmsPlugin{
		dataDir:                   dataDir,
		textFileSizeMax:           pi.SettingTextFileSizeMax,
		imageFileCountMax:         pi.SettingImageFileCountMax,
		imageFileSizeMax:          pi.SettingImageFileSizeMax,
		invoiceNameLengthMin:      nameLengthMin,
		invoiceNameLengthMax:      nameLengthMax,
		invoiceNameSupportedChars: nameSupportedCharsString,
		invoiceNameRegexp:         rexp,
	}

	return &c, func() {
		err = os.RemoveAll(dataDir)
		if err != nil {
			t.Fatal(err)
		}
	}
}
