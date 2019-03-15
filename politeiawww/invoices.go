// Copyright (c) 2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/decred/dcrtime/merkle"
	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	www "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/util"
)

const (
	// invoiceFile contains the file name of the invoice file
	invoiceFile = "invoice.csv"

	BackendInvoiceMetadataVersion = 1
)

// handleNewInvoice handles the incoming new invoice command.
func (p *politeiawww) handleNewInvoice(w http.ResponseWriter, r *http.Request) {
	// Get the new proposal command.
	log.Tracef("handleNewInvoice")
	var ni www.NewInvoice
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&ni); err != nil {
		RespondWithError(w, r, 0, "handleNewInvoice: unmarshal", www.UserError{
			ErrorCode: www.ErrorStatusInvalidInput,
		})
		return
	}

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleNewInvoice: getSessionUser %v", err)
		return
	}

	reply, err := p.ProcessNewInvoice(ni, user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleNewInvoice: ProcessNewInvoice %v", err)
		return
	}

	// Reply with the challenge response and censorship token.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// ProcessNewInvoice tries to submit a new proposal to politeiad.
func (p *politeiawww) ProcessNewInvoice(ni www.NewInvoice, u *user.User) (*www.NewInvoiceReply, error) {
	log.Tracef("ProcessNewInvoice")

	err := validateInvoice(ni, u)
	if err != nil {
		return nil, err
	}

	name := strconv.Itoa(int(ni.Year)) + strconv.Itoa(int(ni.Month)) + u.Username

	md, err := encodeBackendInvoiceMetadata(BackendInvoiceMetadata{
		Version:   BackendInvoiceMetadataVersion,
		Timestamp: time.Now().Unix(),
		Name:      name,
		PublicKey: ni.PublicKey,
		Signature: ni.Signature,
	})
	if err != nil {
		return nil, err
	}

	// Setup politeiad request
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}
	n := pd.NewRecord{
		Challenge: hex.EncodeToString(challenge),
		Metadata: []pd.MetadataStream{{
			ID:      mdStreamGeneral,
			Payload: string(md),
		}},
		Files: convertPropFilesFromWWW(ni.Files),
	}

	// Handle test case
	if p.test {
		tokenBytes, err := util.Random(pd.TokenSize)
		if err != nil {
			return nil, err
		}

		testReply := pd.NewRecordReply{
			CensorshipRecord: pd.CensorshipRecord{
				Token: hex.EncodeToString(tokenBytes),
			},
		}

		return &www.NewInvoiceReply{
			CensorshipRecord: convertPropCensorFromPD(testReply.CensorshipRecord),
		}, nil
	}

	// Send politeiad request
	responseBody, err := p.makeRequest(http.MethodPost,
		pd.NewRecordRoute, n)
	if err != nil {
		return nil, err
	}

	log.Infof("Submitted invoice name: %v", name)
	for k, f := range n.Files {
		log.Infof("%02v: %v %v", k, f.Name, f.Digest)
	}

	// Handle response
	var pdReply pd.NewRecordReply
	err = json.Unmarshal(responseBody, &pdReply)
	if err != nil {
		return nil, fmt.Errorf("Unmarshal NewInvoiceReply: %v", err)
	}

	err = util.VerifyChallenge(p.cfg.Identity, challenge, pdReply.Response)
	if err != nil {
		return nil, err
	}
	r := pd.Record{}
	ir, err := convertRecordToDatabaseInvoice(r)
	if err != nil {
		return nil, err
	}
	err = p.cmsDb.NewInvoice(ir)
	if err != nil {
		return nil, err
	}
	cr := convertPropCensorFromPD(pdReply.CensorshipRecord)

	// Fire off new proposal event
	p.fireEvent(EventTypeProposalSubmitted,
		EventDataProposalSubmitted{
			CensorshipRecord: &cr,
			ProposalName:     name,
			User:             u,
		},
	)

	return &www.NewInvoiceReply{
		CensorshipRecord: cr,
	}, nil
}

func validateInvoice(ni www.NewInvoice, u *user.User) error {
	log.Tracef("validateInvoice")

	// Obtain signature
	sig, err := util.ConvertSignature(ni.Signature)
	if err != nil {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}

	// Verify public key
	id, err := checkPublicKey(u, ni.PublicKey)
	if err != nil {
		return err
	}

	pk, err := identity.PublicIdentityFromBytes(id[:])
	if err != nil {
		return err
	}

	// Check for at least 1 markdown file with a non-empty payload.
	if len(ni.Files) == 0 || ni.Files[0].Payload == "" {
		return www.UserError{
			ErrorCode: www.ErrorStatusProposalMissingFiles,
		}
	}

	// verify if there are duplicate names
	filenames := make(map[string]int, len(ni.Files))
	// Check that the file number policy is followed.
	var (
		numCSVs, numImages, numInvoiceFiles    int
		csvExceedsMaxSize, imageExceedsMaxSize bool
		hashes                                 []*[sha256.Size]byte
	)
	for _, v := range ni.Files {
		filenames[v.Name]++
		var (
			data []byte
			err  error
		)
		if strings.HasPrefix(v.MIME, "image/") {
			numImages++
			data, err = base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return err
			}
			if len(data) > www.PolicyMaxImageSize {
				imageExceedsMaxSize = true
			}
		} else {
			numCSVs++

			if v.Name == invoiceFile {
				numInvoiceFiles++
			}

			data, err = base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return err
			}
			if len(data) > www.PolicyMaxMDSize {
				csvExceedsMaxSize = true
			}

			// Validate that the invoice shows the month and date in a comment.
			t := time.Date(int(ni.Year), time.Month(int(ni.Month)), 1, 0, 0, 0, 0, time.UTC)
			str := fmt.Sprintf("%v %v", www.PolicyInvoiceCommentChar,
				t.Format("2006-01"))
			if strings.HasPrefix(string(data), str) ||
				strings.Contains(string(data), "\n"+str) {
				return www.UserError{
					ErrorCode: www.ErrorStatusMalformedInvoiceFile,
				}
			}

			// Validate that the invoice is CSV-formatted.
			csvReader := csv.NewReader(strings.NewReader(string(data)))
			csvReader.Comma = www.PolicyInvoiceFieldDelimiterChar
			csvReader.Comment = www.PolicyInvoiceCommentChar
			csvReader.TrimLeadingSpace = true

			_, err = csvReader.ReadAll()
			if err != nil {
				return www.UserError{
					ErrorCode: www.ErrorStatusMalformedInvoiceFile,
				}
			}
		}

		// Append digest to array for merkle root calculation
		digest := util.Digest(data)
		var d [sha256.Size]byte
		copy(d[:], digest)
		hashes = append(hashes, &d)
	}

	// verify duplicate file names
	if len(ni.Files) > 1 {
		var repeated []string
		for name, count := range filenames {
			if count > 1 {
				repeated = append(repeated, name)
			}
		}
		if len(repeated) > 0 {
			return www.UserError{
				ErrorCode:    www.ErrorStatusProposalDuplicateFilenames,
				ErrorContext: repeated,
			}
		}
	}

	// we expect one index file
	if numInvoiceFiles == 0 {
		return www.UserError{
			ErrorCode:    www.ErrorStatusProposalMissingFiles,
			ErrorContext: []string{indexFile},
		}
	}

	if numCSVs > www.PolicyMaxMDs {
		return www.UserError{
			ErrorCode: www.ErrorStatusMaxMDsExceededPolicy,
		}
	}

	if numImages > www.PolicyMaxImages {
		return www.UserError{
			ErrorCode: www.ErrorStatusMaxImagesExceededPolicy,
		}
	}

	if csvExceedsMaxSize {
		return www.UserError{
			ErrorCode: www.ErrorStatusMaxMDSizeExceededPolicy,
		}
	}

	if imageExceedsMaxSize {
		return www.UserError{
			ErrorCode: www.ErrorStatusMaxImageSizeExceededPolicy,
		}
	}

	// Note that we need validate the string representation of the merkle
	mr := merkle.Root(hashes)
	if !pk.VerifyMessage([]byte(hex.EncodeToString(mr[:])), sig) {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}

	return nil
}

type BackendInvoiceMetadata struct {
	Version   uint64 `json:"version"` // BackendInvoiceMetadata version
	Month     uint16 `json:"month"`
	Year      uint16 `json:"year"`
	Timestamp int64  `json:"timestamp"` // Last update of invoice
	PublicKey string `json:"publickey"` // Key used for signature.
	Signature string `json:"signature"` // Signature of merkle root
	Name      string `json:"name"`      // Generated invoice name
}

// encodeBackendInvoiceMetadata encodes BackendInvoiceMetadata into a JSON
// byte slice.
func encodeBackendInvoiceMetadata(md BackendInvoiceMetadata) ([]byte, error) {
	b, err := json.Marshal(md)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// decodeBackendInvoiceMetadata decodes a JSON byte slice into a
// BackendInvoiceMetadata.
func decodeBackendInvoiceMetadata(payload []byte) (*BackendInvoiceMetadata, error) {
	var md BackendInvoiceMetadata

	err := json.Unmarshal(payload, &md)
	if err != nil {
		return nil, err
	}

	return &md, nil
}
