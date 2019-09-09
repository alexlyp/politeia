// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	v1 "github.com/decred/politeia/politeiawww/api/cms/v1"
)

// DebateDCCCmd allows an administrator to debate a DCC proposal.
type DebateDCCCmd struct {
	Args struct {
		Token string `positional-arg-name:"token"`
	} `positional-args:"true" required:"true"`
	Reason string `long:"reason" optional:"true" description:"Reason to debate DCC"`
}

// Execute executes the debate DCC command.
func (cmd *DebateDCCCmd) Execute(args []string) error {
	token := cmd.Args.Token
	if token == "" {
		return fmt.Errorf("invalid request: you must specify dcc " +
			"token")
	}

	// Check for user identity
	if cfg.Identity == nil {
		return errUserIdentityNotFound
	}

	if cmd.Reason == "" {
		reader := bufio.NewReader(os.Stdin)
		if cmd.Reason == "" {
			fmt.Print("Enter your reason to debate the DCC: ")
			reason, _ := reader.ReadString('\n')
			cmd.Reason = strings.TrimSpace(reason)
		}
		fmt.Print("\nPlease carefully review your information and ensure it's " +
			"correct. If not, press Ctrl + C to exit. Or, press Enter to continue " +
			"your request.")
		reader.ReadString('\n')
	}

	// Setup new comment request
	msg := fmt.Sprintf("%v%v%v", token, int(v1.DCCStatusDebate), cmd.Reason)
	sig := cfg.Identity.SignMessage([]byte(msg))

	ad := v1.DebateDCC{
		Token:     cmd.Args.Token,
		Reason:    cmd.Reason,
		Signature: hex.EncodeToString(sig[:]),
		PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
	}

	// Print request details
	err := printJSON(ad)
	if err != nil {
		return err
	}

	// Send request
	sdr, err := client.DebateDCC(ad)
	if err != nil {
		return fmt.Errorf("DebateDCC: %v", err)
	}

	// Print response details
	err = printJSON(sdr)
	if err != nil {
		return err
	}

	return nil
}
