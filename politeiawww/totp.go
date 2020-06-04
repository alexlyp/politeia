// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.
package main

import (
	"bytes"
	"image/png"
	"time"

	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/pquerna/otp/totp"
)

// processSetTOTP attempts to set a new TOTP key based on the given TOTP type.
func (p *politeiawww) processSetTOTP(st www.SetTOTP, u *user.User) (*www.SetTOTPReply, error) {
	log.Tracef("processSetTOTP: %v", u.ID.String())
	// if the user already has a TOTP secret set, check the code that was given
	// as well to see if it matches to update.
	if u.TOTPSecret != "" && u.TOTPVerified {
		valid := totp.Validate(st.CurrentTOTPCode, u.TOTPSecret)
		if !valid {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusTOTPFailedValidation,
			}
		}
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      p.cfg.Mode,
		AccountName: u.Email,
	})
	if err != nil {
		return nil, err
	}
	// Convert TOTP key into a PNG
	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	if err != nil {
		return nil, err
	}
	png.Encode(&buf, img)

	u.TOTPType = int(st.Type)
	u.TOTPSecret = key.Secret()
	u.TOTPVerified = false
	u.TOTPLastUpdated = time.Now().Unix()

	err = p.db.UserUpdate(*u)
	if err != nil {
		return nil, err
	}

	return &www.SetTOTPReply{
		Key:   key.Secret(),
		Image: buf.Bytes(),
	}, nil
}

// processVerifyTOTP attempts to confirm a newly set TOTP key based on the
// given TOTP type.
func (p *politeiawww) processVerifyTOTP(vt www.VerifyTOTP, u *user.User) (*www.VerifyTOTPReply, error) {
	valid := totp.Validate(vt.Code, u.TOTPSecret)
	if !valid {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusTOTPFailedValidation,
		}
	}

	u.TOTPVerified = true
	u.TOTPLastUpdated = time.Now().Unix()

	err := p.db.UserUpdate(*u)
	if err != nil {
		return nil, err
	}

	return nil, nil
}
