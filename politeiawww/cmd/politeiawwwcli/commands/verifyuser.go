// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

import (
	"encoding/hex"
	"fmt"

	"github.com/decred/politeia/politeiawww/api/v1"
)

// Help message displayed for the command 'politeiawwwcli help verifyuser'
var VerifyUserCmdHelpMsg = `verifyuser "email" "token"

Verify user's email address.

Arguments:
1. email       (string, optional)   Email of user
2. token       (string, optional)   Verification token

Result:
{}`

type VerifyUserCmd struct {
	Args struct {
		Email string `positional-arg-name:"email" description:"User email address"`
		Token string `positional-arg-name:"token" description:"Email verification token"`
	} `positional-args:"true" required:"true"`
}

func (cmd *VerifyUserCmd) Execute(args []string) error {
	// Check for user identity
	if cfg.Identity == nil {
		return fmt.Errorf(ErrorNoUserIdentity)
	}

	// Verify new user
	sig := cfg.Identity.SignMessage([]byte(cmd.Args.Token))
	vnur, err := c.VerifyNewUser(&v1.VerifyNewUser{
		Email:             cmd.Args.Email,
		VerificationToken: cmd.Args.Token,
		Signature:         hex.EncodeToString(sig[:]),
	})
	if err != nil {
		return err
	}

	// Print response details
	return Print(vnur, cfg.Verbose, cfg.RawJSON)
}
