// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package records

import (
	v1 "github.com/decred/politeia/politeiawww/api/records/v1"
	"github.com/decred/politeia/politeiawww/user"
)

func userCanSubmitInvoice(u user.User) bool {

	// check contractor type and check against these:

	return u.NewUserPaywallTx != ""
}

// cmsHookNewRecordpre executes the new record pre hook for cms.
//
// This function is a temporary function that will be removed once user plugins
// have been implemented.
func (r *Records) cmsHookNewRecordPre(u user.User) error {
	// Verify user has paid registration paywall
	if !userCanSubmitInvoice(u) {
		return v1.PluginErrorReply{
			PluginID:  user.CmsUserPluginID,
			ErrorCode: user.ErrorCodeInvalidContractorType,
		}
	}
	return nil
}

// cmsHookNewRecordPost executes the new record post hook for cms.
//
// This function is a temporary function that will be removed once user plugins
// have been implemented.
func (r *Records) cmsHookNewRecordPost(u user.User, token string) error {
	// Anything we should do on this post hook?
	return nil
}
