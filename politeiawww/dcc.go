// Copyright (c) 2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/decred/dcrtime/merkle"
	"github.com/decred/politeia/decredplugin"
	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/cache"
	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/cmsdatabase"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/util"
)

const (
	// dccFile contains the file name of the dcc file
	dccFile = "dcc.json"

	// politeiad dcc record metadata streams
	mdStreamDCCGeneral       = 5 // General DCC metadata
	mdStreamDCCStatusChanges = 6 // DCC status changes

	// Metadata stream struct versions
	backendDCCMetadataVersion     = 1
	backendDCCStatusChangeVersion = 1

	sponsorString = "aye"
	opposeString  = "nay"
)

var (
	validSponsorStatement     = regexp.MustCompile(createSponsorStatementRegex())
	validDCCStatusTransitions = map[cms.DCCStatusT][]cms.DCCStatusT{
		cms.DCCStatusActive: {
			cms.DCCStatusApproved,
			cms.DCCStatusSupported,
			cms.DCCStatusRejected,
			cms.DCCStatusDebate,
		},
		cms.DCCStatusSupported: {
			cms.DCCStatusApproved,
			cms.DCCStatusRejected,
		},
	}
)

type DCCVoteDetails struct {
	StartVote      cms.StartVote      // Start vote
	StartVoteReply cms.StartVoteReply // Start vote reply
}

// createSponsorStatementRegex generates a regex based on the policy supplied for
// valid characters sponsor statement.
func createSponsorStatementRegex() string {
	var buf bytes.Buffer
	buf.WriteString("^[")

	for _, supportedChar := range cms.PolicySponsorStatementSupportedChars {
		if len(supportedChar) > 1 {
			buf.WriteString(supportedChar)
		} else {
			buf.WriteString(`\` + supportedChar)
		}
	}
	buf.WriteString("]{")
	buf.WriteString(strconv.Itoa(cms.PolicyMinSponsorStatementLength) + ",")
	buf.WriteString(strconv.Itoa(cms.PolicyMaxSponsorStatementLength) + "}$")

	return buf.String()
}

func (p *politeiawww) processNewDCC(nd cms.NewDCC, u *user.User) (*cms.NewDCCReply, error) {
	reply := &cms.NewDCCReply{}

	err := p.validateDCC(nd, u)
	if err != nil {
		return nil, err
	}

	m := backendDCCMetadata{
		Version:   backendDCCMetadataVersion,
		Timestamp: time.Now().Unix(),
		PublicKey: nd.PublicKey,
		Signature: nd.Signature,
	}
	md, err := encodeBackendDCCMetadata(m)
	if err != nil {
		return nil, err
	}

	sc := backendDCCStatusChange{
		Version:   backendDCCStatusChangeVersion,
		Timestamp: time.Now().Unix(),
		NewStatus: cms.DCCStatusActive,
	}
	scb, err := encodeBackendDCCStatusChange(sc)
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
		Metadata: []pd.MetadataStream{
			{
				ID:      mdStreamDCCGeneral,
				Payload: string(md),
			},
			{
				ID:      mdStreamDCCStatusChanges,
				Payload: string(scb),
			},
		},
		Files: convertPropFilesFromWWW(nd.Files),
	}

	// Send the newrecord politeiad request
	responseBody, err := p.makeRequest(http.MethodPost,
		pd.NewRecordRoute, n)
	if err != nil {
		return nil, err
	}

	log.Infof("Submitted issuance nomination: %v", u.Username)
	for k, f := range n.Files {
		log.Infof("%02v: %v %v", k, f.Name, f.Digest)
	}

	// Handle newRecord response
	var pdReply pd.NewRecordReply
	err = json.Unmarshal(responseBody, &pdReply)
	if err != nil {
		return nil, fmt.Errorf("Unmarshal NewDCCReply: %v", err)
	}

	// Verify NewRecord challenge
	err = util.VerifyChallenge(p.cfg.Identity, challenge, pdReply.Response)
	if err != nil {
		return nil, err
	}

	// Change politeiad record status to public. DCCs
	// do not need to be reviewed before becoming public.
	// An admin signature is not included for this reason.
	c := MDStreamChanges{
		Version:   VersionMDStreamChanges,
		Timestamp: time.Now().Unix(),
		NewStatus: pd.RecordStatusPublic,
	}
	blob, err := encodeMDStreamChanges(c)
	if err != nil {
		return nil, err
	}

	challenge, err = util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	sus := pd.SetUnvettedStatus{
		Token:     pdReply.CensorshipRecord.Token,
		Status:    pd.RecordStatusPublic,
		Challenge: hex.EncodeToString(challenge),
		MDAppend: []pd.MetadataStream{
			{
				ID:      mdStreamChanges,
				Payload: string(blob),
			},
		},
	}

	// Send SetUnvettedStatus request to politeiad
	responseBody, err = p.makeRequest(http.MethodPost,
		pd.SetUnvettedStatusRoute, sus)
	if err != nil {
		return nil, err
	}

	var pdSetUnvettedStatusReply pd.SetUnvettedStatusReply
	err = json.Unmarshal(responseBody, &pdSetUnvettedStatusReply)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal SetUnvettedStatusReply: %v",
			err)
	}

	// Verify the SetUnvettedStatus challenge.
	err = util.VerifyChallenge(p.cfg.Identity, challenge,
		pdSetUnvettedStatusReply.Response)
	if err != nil {
		return nil, err
	}

	r := pd.Record{
		Metadata:         n.Metadata,
		Files:            n.Files,
		CensorshipRecord: pdReply.CensorshipRecord,
	}
	// Submit issuance to cmsdb

	dccRec, err := convertRecordToDatabaseDCC(r)
	if err != nil {
		return nil, err
	}

	err = p.cmsDB.NewDCC(dccRec)
	if err != nil {
		return nil, err
	}

	cr := convertPropCensorFromPD(pdReply.CensorshipRecord)

	reply.CensorshipRecord = cr
	return reply, nil
}

func (p *politeiawww) validateDCC(nd cms.NewDCC, u *user.User) error {

	// Obtain signature
	sig, err := util.ConvertSignature(nd.Signature)
	if err != nil {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}

	// Verify public key
	if u.PublicKey() != nd.PublicKey {
		fmt.Println(u.PublicKey(), nd.PublicKey)
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSigningKey,
		}
	}

	pk, err := identity.PublicIdentityFromBytes(u.ActiveIdentity().Key[:])
	if err != nil {
		return err
	}

	// Check for at least 1 markdown file with a non-empty payload.
	if len(nd.Files) == 0 || nd.Files[0].Payload == "" {
		return www.UserError{
			ErrorCode: www.ErrorStatusProposalMissingFiles,
		}
	}

	// verify if there are duplicate names
	filenames := make(map[string]int, len(nd.Files))
	// Check that the file number policy is followed.
	var (
		numFiles, numImages, numDCCFiles        int
		jsonExceedsMaxSize, imageExceedsMaxSize bool
		hashes                                  []*[sha256.Size]byte
	)
	for _, v := range nd.Files {
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
			if len(data) > cms.PolicyMaxImageSize {
				imageExceedsMaxSize = true
			}
		} else {
			numFiles++

			if v.Name == dccFile {
				numDCCFiles++
			}

			data, err = base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return err
			}
			if len(data) > cms.PolicyMaxMDSize {
				jsonExceedsMaxSize = true
			}

			// Check to see if the data can be parsed properly into DCCInput
			// struct.
			var issuance cms.DCCInput
			if err := json.Unmarshal(data, &issuance); err != nil {
				return www.UserError{
					ErrorCode: cms.ErrorStatusMalformedDCCFile,
				}
			}
			// Check UserID of Nominee
			_, err := p.getCMSUserByID(issuance.NomineeUserID)
			if err != nil {
				return err
			}

			sponsorUser, err := p.getCMSUserByID(u.ID.String())
			if err != nil {
				return err
			}

			// Check that domains match
			if sponsorUser.Domain != issuance.Domain {
				fmt.Println(sponsorUser.Domain, issuance.Domain)
				return www.UserError{
					ErrorCode: cms.ErrorStatusInvalidNominatingDomain,
				}
			}

			// Validate sponsor statement input
			statement := formatSponsorStatement(issuance.SponsorStatement)
			if !validateSponsorStatement(statement) {
				return www.UserError{
					ErrorCode: cms.ErrorStatusMalformedSponsorStatement,
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
	if len(nd.Files) > 1 {
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
	if numDCCFiles == 0 {
		return www.UserError{
			ErrorCode:    www.ErrorStatusProposalMissingFiles,
			ErrorContext: []string{indexFile},
		}
	}

	if numFiles > www.PolicyMaxMDs {
		return www.UserError{
			ErrorCode: www.ErrorStatusMaxMDsExceededPolicy,
		}
	}

	if numImages > www.PolicyMaxImages {
		return www.UserError{
			ErrorCode: www.ErrorStatusMaxImagesExceededPolicy,
		}
	}

	if jsonExceedsMaxSize {
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

// formatSponsorStatement normalizes a sponsor statement without leading and
// trailing spaces.
func formatSponsorStatement(statement string) string {
	return strings.TrimSpace(statement)
}

// validateSponsorStatement verifies that a field filled out in invoice.json is
// valid
func validateSponsorStatement(statement string) bool {
	if statement != formatSponsorStatement(statement) {
		log.Tracef("validateSponsorStatement: not normalized: %s %s",
			statement, formatSponsorStatement(statement))
		return false
	}
	if len(statement) > cms.PolicyMaxSponsorStatementLength ||
		len(statement) < cms.PolicyMinSponsorStatementLength {
		log.Tracef("validateSponsorStatement: not within bounds: have %v expected > %v < %v",
			len(statement), cms.PolicyMaxSponsorStatementLength,
			cms.PolicyMinSponsorStatementLength)
		return false
	}
	if !validSponsorStatement.MatchString(statement) {
		log.Tracef("validateSponsorStatement: not valid: %s %s",
			statement, validSponsorStatement.String())
		return false
	}
	return true
}

// backendDCCMetadata represents the general metadata for a DCC and is
// stored in the metadata stream mdStreamDCCGeneral in politeiad.
type backendDCCMetadata struct {
	Version   uint64 `json:"version"`   // Version of the struct
	Timestamp int64  `json:"timestamp"` // Last update of invoice
	PublicKey string `json:"publickey"` // Key used for signature
	Signature string `json:"signature"` // Signature of merkle root
}

// backendDCCStatusChange represents the metadata for any status change that
// occurs to a patricular DCC issuance or revocation.
type backendDCCStatusChange struct {
	Version        uint           `json:"version"`        // Version of the struct
	AdminPublicKey string         `json:"adminpublickey"` // Identity of the administrator
	NewStatus      cms.DCCStatusT `json:"newstatus"`      // Status
	Reason         string         `json:"reason"`         // Reason
	Timestamp      int64          `json:"timestamp"`      // Timestamp of the change
}

// encodeBackendDCCMetadata encodes a backendDCCMetadata into a JSON
// byte slice.
func encodeBackendDCCMetadata(md backendDCCMetadata) ([]byte, error) {
	b, err := json.Marshal(md)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// decodeBackendDCCMetadata decodes a JSON byte slice into a
// backendDCCMetadata.
func decodeBackendDCCMetadata(payload []byte) (*backendDCCMetadata, error) {
	var md backendDCCMetadata

	err := json.Unmarshal(payload, &md)
	if err != nil {
		return nil, err
	}

	return &md, nil
}

// encodeBackendDCCStatusChange encodes a backendDCCStatusChange into a
// JSON byte slice.
func encodeBackendDCCStatusChange(md backendDCCStatusChange) ([]byte, error) {
	b, err := json.Marshal(md)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// decodeBackendDCCStatusChanges decodes a JSON byte slice into a slice of
// backendDCCStatusChanges.
func decodeBackendDCCStatusChanges(payload []byte) ([]backendDCCStatusChange, error) {
	var md []backendDCCStatusChange

	d := json.NewDecoder(strings.NewReader(string(payload)))
	for {
		var m backendDCCStatusChange
		err := d.Decode(&m)
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		md = append(md, m)
	}

	return md, nil
}

// getDCC gets the most recent verions of the given DCC from the cache
// then fills in any missing user fields before returning the DCC record.
func (p *politeiawww) getDCC(token string) (*cms.DCCRecord, error) {
	// Get invoice from cache
	r, err := p.cache.Record(token)
	if err != nil {
		return nil, err
	}
	i := convertDCCFromCache(*r)

	// Fill in userID and username fields
	u, err := p.db.UserGetByPubKey(i.PublicKey)
	if err != nil {
		log.Errorf("getDCC: getUserByPubKey: token:%v "+
			"pubKey:%v err:%v", token, i.PublicKey, err)
	} else {
		i.SponsorUserID = u.ID.String()
		i.SponsorUsername = u.Username
	}
	support, oppose, err := p.getDCCSupportOppositionComments(token)
	if err != nil {
		log.Errorf("getDCC: %v", err)
	}
	i.SupportUserIDs = support
	i.OppositionUserIDs = oppose
	return &i, nil
}

func (p *politeiawww) getDCCSupportOppositionComments(token string) ([]string, []string, error) {
	log.Tracef("getDCCSupportOpposition: %v", token)

	dc, err := p.decredGetComments(token)
	if err != nil {
		return nil, nil, fmt.Errorf("decredGetComments: %v", err)
	}

	support := make([]string, 0, len(dc))
	oppose := make([]string, 0, len(dc))
	for _, v := range dc {
		c := convertCommentFromDecred(v)
		u, err := p.db.UserGetByPubKey(c.PublicKey)
		if err != nil {
			log.Errorf("getDCCSupportOpposition: UserGetByPubKey: "+
				"token:%v commentID:%v pubKey:%v err:%v",
				token, c.CommentID, c.PublicKey, err)
		}
		if c.Comment == sponsorString {
			support = append(support, u.ID.String())
		} else if c.Comment == opposeString {
			oppose = append(support, u.ID.String())
		}
	}

	return support, oppose, nil
}

/*
func (p *politeiawww) processIssuances(cr cms.Issuances) (*cms.IssuancesReply, error) {
	reply := &cms.ContractorRevocationReply{}
	return reply, nil
}

func (p *politeiawww) processRevocations(cr cms.Revocations) (*cms.RevocationsReply, error) {
	reply := &cms.ContractorRevocationReply{}
	return reply, nil
}
*/

func (p *politeiawww) processSupportDCC(sd cms.SupportDCC, u *user.User) (*cms.SupportDCCReply, error) {
	log.Tracef("processSupportDCC: %v %v", sd.Token, u.ID)

	dcc, err := p.getDCC(sd.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: cms.ErrorStatusInvoiceNotFound,
			}
		}
		return nil, err
	}

	// Check to make sure the user has not Supported or Opposed this DCC yet
	if stringInSlice(dcc.SupportUserIDs, u.ID.String()) ||
		stringInSlice(dcc.OppositionUserIDs, u.ID.String()) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusUserActionNotAllowed,
		}
	}

	// Check to make sure the user is not the author of the DCC.
	if dcc.SponsorUserID == u.ID.String() {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusUserActionNotAllowed,
		}
	}

	// Ensure the public key is the user's active key
	if sd.PublicKey != u.PublicKey() {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSigningKey,
		}
	}

	// Validate signature
	msg := sd.Token + sd.Comment
	err = validateSignature(sd.PublicKey, sd.Signature, msg)
	if err != nil {
		return nil, err
	}

	// Validate sponsor comment
	if strings.TrimSpace(sd.Comment) != sponsorString {
		return nil, www.UserError{
			ErrorCode: cms.ErrorStatusInvalidDCCComment,
		}
	}

	// Check to make sure that the DCC is still active
	if dcc.Status != cms.DCCStatusActive {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusCannotCommentOnProp,
		}
	}

	// Setup plugin command
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	// Create new comment
	nc := www.NewComment{
		Token:     sd.Token,
		ParentID:  "0",
		Comment:   strings.TrimSpace(sd.Comment),
		Signature: sd.Signature,
		PublicKey: sd.PublicKey,
	}

	dnc := convertNewCommentToDecredPlugin(nc)
	payload, err := decredplugin.EncodeNewComment(dnc)
	if err != nil {
		return nil, err
	}

	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        decredplugin.ID,
		Command:   decredplugin.CmdNewComment,
		CommandID: decredplugin.CmdNewComment,
		Payload:   string(payload),
	}

	// Send polieiad request
	responseBody, err := p.makeRequest(http.MethodPost,
		pd.PluginCommandRoute, pc)
	if err != nil {
		return nil, err
	}

	// Handle response
	var reply pd.PluginCommandReply
	err = json.Unmarshal(responseBody, &reply)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal "+
			"PluginCommandReply: %v", err)
	}

	err = util.VerifyChallenge(p.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return nil, err
	}

	return &cms.SupportDCCReply{}, nil
}

func (p *politeiawww) processOpposeDCC(od cms.OpposeDCC, u *user.User) (*cms.OpposeDCCReply, error) {
	log.Tracef("processOpposeDCC: %v %v", od.Token, u.ID)

	dcc, err := p.getDCC(od.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: cms.ErrorStatusInvoiceNotFound,
			}
		}
		return nil, err
	}

	// Check to make sure the user has not Supported or Opposed this DCC yet
	if stringInSlice(dcc.SupportUserIDs, u.ID.String()) ||
		stringInSlice(dcc.OppositionUserIDs, u.ID.String()) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusUserActionNotAllowed,
		}
	}

	// Check to make sure the user is not the author of the DCC.
	if dcc.SponsorUserID == u.ID.String() {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusUserActionNotAllowed,
		}
	}

	// Ensure the public key is the user's active key
	if od.PublicKey != u.PublicKey() {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSigningKey,
		}
	}

	// Validate signature
	msg := od.Token + od.Comment
	err = validateSignature(od.PublicKey, od.Signature, msg)
	if err != nil {
		return nil, err
	}

	// Validate oppose comment
	if strings.TrimSpace(od.Comment) != opposeString {
		return nil, www.UserError{
			ErrorCode: cms.ErrorStatusInvalidDCCComment,
		}
	}

	// Check to make sure that the DCC is still active
	if dcc.Status != cms.DCCStatusActive {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusCannotCommentOnProp,
		}
	}

	// Setup plugin command
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	// Create new comment
	nc := www.NewComment{
		Token:     od.Token,
		ParentID:  "0",
		Comment:   strings.TrimSpace(od.Comment),
		Signature: od.Signature,
		PublicKey: od.PublicKey,
	}

	dnc := convertNewCommentToDecredPlugin(nc)
	payload, err := decredplugin.EncodeNewComment(dnc)
	if err != nil {
		return nil, err
	}

	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        decredplugin.ID,
		Command:   decredplugin.CmdNewComment,
		CommandID: decredplugin.CmdNewComment,
		Payload:   string(payload),
	}

	// Send polieiad request
	responseBody, err := p.makeRequest(http.MethodPost,
		pd.PluginCommandRoute, pc)
	if err != nil {
		return nil, err
	}

	// Handle response
	var reply pd.PluginCommandReply
	err = json.Unmarshal(responseBody, &reply)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal "+
			"PluginCommandReply: %v", err)
	}

	err = util.VerifyChallenge(p.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return nil, err
	}

	return &cms.OpposeDCCReply{}, nil
}

func (p *politeiawww) processDCCDetails(gd cms.DCCDetails) (*cms.DCCDetailsReply, error) {
	log.Tracef("processDCCDetails: %v", gd.Token)

	dcc, err := p.getDCC(gd.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: cms.ErrorStatusInvoiceNotFound,
			}
		}
		return nil, err
	}
	reply := &cms.DCCDetailsReply{
		DCC: *dcc,
	}
	return reply, nil
}

func (p *politeiawww) processGetDCCs(gds cms.GetDCCs) (*cms.GetDCCsReply, error) {
	log.Tracef("processGetDCCs: %v", gds.Status)

	var dbDCCs []*cmsdatabase.DCC
	var err error
	switch {
	case gds.Status != 0:
		dbDCCs, err = p.cmsDB.DCCsByStatus(int(gds.Status))
		if err != nil {
			return nil, err
		}

	default:
		dbDCCs, err = p.cmsDB.DCCsAll()
		if err != nil {
			return nil, err
		}
	}
	dccs := make([]cms.DCCRecord, 0, len(dbDCCs))

	for _, v := range dbDCCs {
		dcc := convertDCCDatabaseToRecord(v)
		dccs = append(dccs, dcc)
	}

	return &cms.GetDCCsReply{
		DCCs: dccs,
	}, nil
}

func (p *politeiawww) processApproveDCC(ad cms.ApproveDCC, u *user.User) (*cms.ApproveDCCReply, error) {
	log.Tracef("processApproveDCC: %v", u.PublicKey())

	dcc, err := p.getDCC(ad.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: cms.ErrorStatusInvoiceNotFound,
			}
		}
		return nil, err
	}

	// Validate signature
	msg := fmt.Sprintf("%v%v", ad.Token, ad.Reason)
	err = validateSignature(ad.PublicKey, ad.Signature, msg)
	if err != nil {
		return nil, err
	}

	err = validateDCCStatusTransition(dcc.Status, cms.DCCStatusApproved)
	if err != nil {
		return nil, err
	}

	// Create the change record.
	c := backendDCCStatusChange{
		Version:        backendInvoiceStatusChangeVersion,
		AdminPublicKey: u.PublicKey(),
		Timestamp:      time.Now().Unix(),
		NewStatus:      cms.DCCStatusApproved,
		Reason:         ad.Reason,
	}
	blob, err := encodeBackendDCCStatusChange(c)
	if err != nil {
		return nil, err
	}

	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	pdCommand := pd.UpdateVettedMetadata{
		Challenge: hex.EncodeToString(challenge),
		Token:     ad.Token,
		MDAppend: []pd.MetadataStream{
			{
				ID:      mdStreamDCCStatusChanges,
				Payload: string(blob),
			},
		},
	}

	responseBody, err := p.makeRequest(http.MethodPost, pd.UpdateVettedMetadataRoute, pdCommand)
	if err != nil {
		return nil, err
	}

	var pdReply pd.UpdateVettedMetadataReply
	err = json.Unmarshal(responseBody, &pdReply)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal UpdateVettedMetadataReply: %v",
			err)
	}

	// Verify the UpdateVettedMetadata challenge.
	err = util.VerifyChallenge(p.cfg.Identity, challenge, pdReply.Response)
	if err != nil {
		return nil, err
	}

	dbDCC, err := p.cmsDB.DCCByToken(ad.Token)
	if err != nil {
		return nil, err
	}
	dbDCC.Status = cms.DCCStatusApproved
	dbDCC.StatusChangeReason = ad.Reason

	// Update cmsdb
	err = p.cmsDB.UpdateDCC(dbDCC)
	if err != nil {
		return nil, err
	}

	if dcc.DCC.Type == cms.DCCTypeIssuance {
		// Do DCC user Issuance processing
		verifyToken, err := p.issuanceDCCUser(dcc.DCC.NomineeUserID)
		if err != nil {
			return nil, err
		}
		return &cms.ApproveDCCReply{
			VerificationToken: hex.EncodeToString(verifyToken),
		}, nil

	} else if dcc.DCC.Type == cms.DCCTypeRevocation {
		// Do DCC user Revocation processing
		err = p.revokeDCCUser(dcc.DCC.NomineeUserID)
		if err != nil {
			return nil, err
		}
	}
	return &cms.ApproveDCCReply{}, nil
}

func validateDCCStatusTransition(oldStatus cms.DCCStatusT, newStatus cms.DCCStatusT) error {
	validStatuses, ok := validDCCStatusTransitions[oldStatus]
	if !ok {
		log.Errorf("status not supported: %v", oldStatus)
		return www.UserError{
			ErrorCode: cms.ErrorStatusInvalidDCCStatusTransition,
		}
	}

	if !dccStatusInSlice(validStatuses, newStatus) {
		return www.UserError{
			ErrorCode: cms.ErrorStatusInvalidDCCStatusTransition,
		}
	}

	return nil
}

func dccStatusInSlice(arr []cms.DCCStatusT, status cms.DCCStatusT) bool {
	for _, s := range arr {
		if status == s {
			return true
		}
	}

	return false
}
func (p *politeiawww) processRejectDCC(rd cms.RejectDCC, u *user.User) (*cms.RejectDCCReply, error) {
	log.Tracef("processRejectDCC: %v", u.PublicKey())

	dcc, err := p.getDCC(rd.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: cms.ErrorStatusInvoiceNotFound,
			}
		}
		return nil, err
	}

	// Validate signature
	msg := fmt.Sprintf("%v%v", rd.Token, rd.Reason)
	err = validateSignature(rd.PublicKey, rd.Signature, msg)
	if err != nil {
		return nil, err
	}

	err = validateDCCStatusTransition(dcc.Status, cms.DCCStatusApproved)
	if err != nil {
		return nil, err
	}

	// Create the change record.
	c := backendDCCStatusChange{
		Version:        backendDCCStatusChangeVersion,
		AdminPublicKey: u.PublicKey(),
		Timestamp:      time.Now().Unix(),
		NewStatus:      cms.DCCStatusRejected,
		Reason:         rd.Reason,
	}
	blob, err := encodeBackendDCCStatusChange(c)
	if err != nil {
		return nil, err
	}

	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	pdCommand := pd.UpdateVettedMetadata{
		Challenge: hex.EncodeToString(challenge),
		Token:     rd.Token,
		MDAppend: []pd.MetadataStream{
			{
				ID:      mdStreamDCCStatusChanges,
				Payload: string(blob),
			},
		},
	}

	responseBody, err := p.makeRequest(http.MethodPost, pd.UpdateVettedMetadataRoute, pdCommand)
	if err != nil {
		return nil, err
	}

	var pdReply pd.UpdateVettedMetadataReply
	err = json.Unmarshal(responseBody, &pdReply)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal UpdateVettedMetadataReply: %v",
			err)
	}

	// Verify the UpdateVettedMetadata challenge.
	err = util.VerifyChallenge(p.cfg.Identity, challenge, pdReply.Response)
	if err != nil {
		return nil, err
	}

	dbDCC, err := p.cmsDB.DCCByToken(rd.Token)
	if err != nil {
		return nil, err
	}
	dbDCC.Status = cms.DCCStatusRejected
	dbDCC.StatusChangeReason = rd.Reason

	// Update cmsdb
	err = p.cmsDB.UpdateDCC(dbDCC)
	if err != nil {
		return nil, err
	}

	return &cms.RejectDCCReply{}, nil
}

func stringInSlice(arr []string, str string) bool {
	for _, s := range arr {
		if str == s {
			return true
		}
	}

	return false
}

// processNewCommentDCC sends a new comment decred plugin command to politeaid
// then fetches the new comment from the cache and returns it.
func (p *politeiawww) processNewCommentDCC(nc www.NewComment, u *user.User) (*www.NewCommentReply, error) {
	log.Tracef("processNewCommentDCC: %v %v", nc.Token, u.ID)

	dcc, err := p.getDCC(nc.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: cms.ErrorStatusInvoiceNotFound,
			}
		}
		return nil, err
	}

	// Check to make sure the user is either an admin or the
	// author of the invoice.
	if !u.Admin && (dcc.SponsorUsername != u.Username) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusUserActionNotAllowed,
		}
	}

	// Ensure the public key is the user's active key
	if nc.PublicKey != u.PublicKey() {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSigningKey,
		}
	}

	// Validate signature
	msg := nc.Token + nc.ParentID + nc.Comment
	err = validateSignature(nc.PublicKey, nc.Signature, msg)
	if err != nil {
		return nil, err
	}

	// Don't allow comments of just "aye" or "nay" that would be confused
	// with support or opposition.
	if nc.Comment == sponsorString || nc.Comment == opposeString {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusUserActionNotAllowed,
		}
	}

	// Validate comment
	err = validateComment(nc)
	if err != nil {
		return nil, err
	}

	// Check to make sure that dcc isn't already approved.
	if dcc.Status != cms.DCCStatusActive {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusCannotCommentOnProp,
		}
	}

	// Setup plugin command
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	dnc := convertNewCommentToDecredPlugin(nc)
	payload, err := decredplugin.EncodeNewComment(dnc)
	if err != nil {
		return nil, err
	}

	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        decredplugin.ID,
		Command:   decredplugin.CmdNewComment,
		CommandID: decredplugin.CmdNewComment,
		Payload:   string(payload),
	}

	// Send polieiad request
	responseBody, err := p.makeRequest(http.MethodPost,
		pd.PluginCommandRoute, pc)
	if err != nil {
		return nil, err
	}

	// Handle response
	var reply pd.PluginCommandReply
	err = json.Unmarshal(responseBody, &reply)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal "+
			"PluginCommandReply: %v", err)
	}

	err = util.VerifyChallenge(p.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return nil, err
	}

	ncr, err := decredplugin.DecodeNewCommentReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}

	// Add comment to commentScores in-memory cache
	p.Lock()
	p.commentScores[nc.Token+ncr.CommentID] = 0
	p.Unlock()

	// Get comment from cache
	c, err := p.getComment(nc.Token, ncr.CommentID)
	if err != nil {
		return nil, fmt.Errorf("getComment: %v", err)
	}

	return &www.NewCommentReply{
		Comment: *c,
	}, nil
}

func dccVoteResults(sv cms.StartVote, cv []cms.CastVote) []cms.VoteOptionResult {
	log.Tracef("dccVoteResults: %v", sv.Vote.Token)

	// Tally votes
	votes := make(map[string]uint64)
	for _, v := range cv {
		votes[v.VoteBit]++
	}

	// Prepare vote option results
	results := make([]cms.VoteOptionResult, 0, len(sv.Vote.Options))
	for _, v := range sv.Vote.Options {
		results = append(results, cms.VoteOptionResult{
			Option:        v,
			VotesReceived: votes[strconv.FormatUint(v.Bits, 10)],
		})
	}

	return results
}

// setVoteStatusReply stores the given VoteStatusReply in memory.  This is to
// only be used for dccs whose voting period has ended so that we don't
// have to worry about cache invalidation issues.
//
// This function must be called without the lock held.
func (p *politeiawww) setDCCVoteStatusReply(v cms.VoteStatusReply) {
	p.Lock()
	defer p.Unlock()

	p.dccVoteStatuses[v.Token] = v
}

func (p *politeiawww) dccVoteStatusReply(token string, bestBlock uint64) (*cms.VoteStatusReply, error) {
	p.RLock()
	vsr, ok := p.dccVoteStatuses[token]
	p.RUnlock()
	if ok {
		vsr.BestBlock = strconv.Itoa(int(bestBlock))
		return &vsr, nil
	}

	// Vote status wasn't in the memory cache
	// so fetch it from the cache database.
	r, err := p.decredVoteSummary(token)
	if err != nil {
		return nil, err
	}

	results := convertDCCVoteOptionResultsFromDecred(r.Results)
	var total uint64
	for _, v := range results {
		total += v.VotesReceived
	}

	vsr = cms.VoteStatusReply{
		Token:              token,
		Status:             dccVoteStatusFromVoteSummary(*r, bestBlock),
		TotalVotes:         total,
		OptionsResult:      results,
		EndHeight:          r.EndHeight,
		BestBlock:          strconv.Itoa(int(bestBlock)),
		NumOfEligibleVotes: r.EligibleTicketCount,
		QuorumPercentage:   r.QuorumPercentage,
		PassPercentage:     r.PassPercentage,
	}

	// If the voting period has ended the vote status
	// is not going to change so add it to the memory
	// cache.
	if vsr.Status == cms.DCCVoteStatusFinished {
		p.setDCCVoteStatusReply(vsr)
	}

	return &vsr, nil
}

// processVoteStatus returns the vote status for a given proposal
func (p *politeiawww) processDCCVoteStatus(token string) (*cms.VoteStatusReply, error) {
	log.Tracef("processDCCVotingStatus: %v", token)

	// Ensure proposal is vetted
	pr, err := p.getProp(token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			}
		}
		return nil, err
	}

	if pr.State != www.PropStateVetted {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongStatus,
		}
	}

	// Get best block
	bestBlock, err := p.getBestBlock()
	if err != nil {
		return nil, fmt.Errorf("bestBlock: %v", err)
	}

	// Get vote status
	vsr, err := p.dccVoteStatusReply(token, bestBlock)
	if err != nil {
		return nil, fmt.Errorf("voteStatusReply: %v", err)
	}

	return vsr, nil
}

// processGetAllVoteStatus returns the vote status of all public proposals.
func (p *politeiawww) processDCCGetAllVoteStatus() (*cms.GetAllVoteStatusReply, error) {
	log.Tracef("processDCCGetAllVoteStatus")

	// We need to determine best block height here in order
	// to set the voting status
	bestBlock, err := p.getBestBlock()
	if err != nil {
		return nil, fmt.Errorf("bestBlock: %v", err)
	}

	// Get all proposals from cache
	all, err := p.getAllProps()
	if err != nil {
		return nil, fmt.Errorf("getAllProps: %v", err)
	}

	// Compile votes statuses
	vrr := make([]cms.VoteStatusReply, 0, len(all))
	for _, v := range all {
		// Get vote status for proposal
		vs, err := p.dccVoteStatusReply(v.CensorshipRecord.Token, bestBlock)
		if err != nil {
			return nil, fmt.Errorf("dccVoteStatusReply: %v", err)
		}

		vrr = append(vrr, *vs)
	}

	return &cms.GetAllVoteStatusReply{
		VotesStatus: vrr,
	}, nil
}

func (p *politeiawww) processDCCActiveVote() (*cms.ActiveVoteReply, error) {
	log.Tracef("processDCCActiveVote")

	// We need to determine best block height here and only
	// return active votes.
	bestBlock, err := p.getBestBlock()
	if err != nil {
		return nil, err
	}

	// Get all proposals from cache
	all, err := p.getAllProps()
	if err != nil {
		return nil, fmt.Errorf("getAllProps: %v", err)
	}

	// Compile dcc vote tuples
	pvt := make([]cms.DCCVoteTuple, 0, len(all))
	for _, v := range all {
		// Get vote details from cache
		vdr, err := p.decredVoteDetails(v.CensorshipRecord.Token)
		if err != nil {
			log.Errorf("processDCCActiveVote: decredVoteDetails failed %v: %v",
				v.CensorshipRecord.Token, err)
			continue
		}
		vd := convertDCCVoteDetailsReplyFromDecred(*vdr)

		// We only want proposals that are currently being voted on
		s := getDCCVoteStatus(vd.StartVoteReply, bestBlock)
		if s != cms.DCCVoteStatusStarted {
			continue
		}

		pvt = append(pvt, cms.DCCVoteTuple{
			StartVote:      vd.StartVote,
			StartVoteReply: vd.StartVoteReply,
		})
	}

	return &cms.ActiveVoteReply{
		Votes: pvt,
	}, nil
}

// processDCCVoteResults returns the vote details for a specific dcc and all
// of the votes that have been cast.
func (p *politeiawww) processDCCVoteResults(token string) (*cms.VoteResultsReply, error) {
	log.Tracef("processDCCVoteResults: %v", token)

	// Get vote details from cache
	vdr, err := p.decredVoteDetails(token)
	if err != nil {
		return nil, fmt.Errorf("decredDCCVoteDetails: %v", err)
	}

	// Get cast votes from cache
	vrr, err := p.decredProposalVotes(token)
	if err != nil {
		return nil, fmt.Errorf("decredDCCVoteDetails: %v", err)
	}

	return &cms.VoteResultsReply{
		StartVote:      convertDCCStartVoteFromDecred(vdr.StartVote),
		StartVoteReply: convertDCCStartVoteReplyFromDecred(vdr.StartVoteReply),
		CastVotes:      convertDCCCastVotesFromDecred(vrr.CastVotes),
	}, nil
}

// processCastVotes handles the www.Ballot call
func (p *politeiawww) processDCCCastVotes(ballot *cms.Ballot) (*cms.BallotReply, error) {
	log.Tracef("processDCCCastVotes")

	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	payload, err := decredplugin.EncodeBallot(convertBallotFromCMS(*ballot))
	if err != nil {
		return nil, err
	}
	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        decredplugin.ID,
		Command:   decredplugin.CmdBallot,
		CommandID: decredplugin.CmdBallot,
		Payload:   string(payload),
	}

	responseBody, err := p.makeRequest(http.MethodPost,
		pd.PluginCommandRoute, pc)
	if err != nil {
		return nil, err
	}

	var reply pd.PluginCommandReply
	err = json.Unmarshal(responseBody, &reply)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal "+
			"PluginCommandReply: %v", err)
	}

	// Verify the challenge.
	err = util.VerifyChallenge(p.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return nil, err
	}

	// Decode plugin reply
	br, err := decredplugin.DecodeBallotReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}
	brr := convertDCCBallotReplyFromDecredPlugin(*br)
	return &brr, nil
}

// getDCCVoteStatus returns the status for the provided vote.
func getDCCVoteStatus(svr cms.StartVoteReply, bestBlock uint64) cms.DCCVoteStatusT {
	/*
		if svr.StartBlockHeight == "" {
			// Vote has not started. Check if it's been authorized yet.
			if voteIsAuthorized(avr) {
				return cms.DCCVoteStatusAuthorized
			} else {
				return cms.DCCVoteStatusNotAuthorized
			}
		}
	*/

	// Vote has at least been started. Check if it has finished.
	ee, err := strconv.ParseUint(svr.EndHeight, 10, 64)
	if err != nil {
		// This should not happen
		log.Errorf("getDCCVoteStatus: ParseUint failed on '%v': %v",
			svr.EndHeight, err)
		return cms.DCCVoteStatusInvalid
	}

	if bestBlock >= ee {
		return cms.DCCVoteStatusFinished
	}
	return cms.DCCVoteStatusStarted
}

func dccVoteStatusFromVoteSummary(r decredplugin.VoteSummaryReply, bestBlock uint64) cms.DCCVoteStatusT {
	switch {
	case !r.Authorized:
		return cms.DCCVoteStatusNotAuthorized
	case r.EndHeight == "":
		return cms.DCCVoteStatusAuthorized
	default:
		endHeight, err := strconv.ParseUint(r.EndHeight, 10, 64)
		if err != nil {
			// This should not happen
			log.Errorf("voteStatusFromVoteSummary: ParseUint "+
				"failed on '%v': %v", r.EndHeight, err)
		}

		if bestBlock < endHeight {
			return cms.DCCVoteStatusStarted
		}

		return cms.DCCVoteStatusFinished
	}
}

// processDCCStartVote handles the cms.StartVote call.
func (p *politeiawww) processDCCStartVote(sv cms.StartVote, u *user.User) (*cms.StartVoteReply, error) {

	// AuthorizeVoteBits looks like nothing useful on this side, d is handling most of the lifting there
	/*
		// Setup plugin command
		challenge, err := util.Random(pd.ChallengeSize)
		if err != nil {
			return nil, fmt.Errorf("Random: %v", err)
		}

		dav := convertAuthorizeVoteFromWWW(av)
		payload, err := decredplugin.EncodeAuthorizeVote(dav)
		if err != nil {
			return nil, fmt.Errorf("EncodeAuthorizeVote: %v", err)
		}

		pc := pd.PluginCommand{
			Challenge: hex.EncodeToString(challenge),
			ID:        decredplugin.ID,
			Command:   decredplugin.CmdAuthorizeVote,
			CommandID: decredplugin.CmdAuthorizeVote + " " + sv.Vote.Token,
			Payload:   string(payload),
		}

		// Send authorizevote plugin request
		responseBody, err := p.makeRequest(http.MethodPost,
			pd.PluginCommandRoute, pc)
		if err != nil {
			return nil, err
		}

		var reply pd.PluginCommandReply
		err = json.Unmarshal(responseBody, &reply)
		if err != nil {
			return nil, fmt.Errorf("Unmarshal PluginCommandReply: %v", err)
		}

		// Verify challenge
		err = util.VerifyChallenge(p.cfg.Identity, challenge, reply.Response)
		if err != nil {
			return nil, fmt.Errorf("VerifyChallenge: %v", err)
		}
	*/
	log.Tracef("processDCCStartVote %v", sv.Vote.Token)

	// Ensure the public key is the user's active key
	if sv.PublicKey != u.PublicKey() {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSigningKey,
		}
	}

	// Validate signature
	err := validateSignature(sv.PublicKey, sv.Signature, sv.Vote.Token)
	if err != nil {
		return nil, err
	}

	// Validate vote bits
	for _, v := range sv.Vote.Options {
		err = validateDCCVoteBit(sv.Vote, v.Bits)
		if err != nil {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusInvalidPropVoteBits,
			}
		}
	}

	// Validate vote parameters
	if sv.Vote.Duration < p.cfg.VoteDurationMin ||
		sv.Vote.Duration > p.cfg.VoteDurationMax ||
		sv.Vote.QuorumPercentage > 100 || sv.Vote.PassPercentage > 100 {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidPropVoteParams,
		}
	}

	// Create vote bits as plugin payload
	dsv := convertStartVoteFromCMS(sv)
	payload, err := decredplugin.EncodeStartVote(dsv)
	if err != nil {
		return nil, err
	}

	// Get vote details from cache
	vdr, err := p.decredVoteDetails(sv.Vote.Token)
	if err != nil {
		return nil, fmt.Errorf("decredVoteDetails: %v", err)
	}
	vd := convertDCCVoteDetailsReplyFromDecred(*vdr)

	if vd.StartVoteReply.StartBlockHeight != "" {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongVoteStatus,
		}
	}

	// Tell decred plugin to start voting
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        decredplugin.ID,
		Command:   decredplugin.CmdStartVote,
		CommandID: decredplugin.CmdStartVote + " " + sv.Vote.Token,
		Payload:   string(payload),
	}

	responseBody, err := p.makeRequest(http.MethodPost,
		pd.PluginCommandRoute, pc)
	if err != nil {
		return nil, err
	}

	var reply pd.PluginCommandReply
	err = json.Unmarshal(responseBody, &reply)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal "+
			"PluginCommandReply: %v", err)
	}

	// Verify the challenge.
	err = util.VerifyChallenge(p.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return nil, err
	}

	vr, err := decredplugin.DecodeStartVoteReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}
	/*
		Notification to alert users of new all-contractor vote?
		p.fireEvent(EventTypeProposalVoteStarted,
			EventDataProposalVoteStarted{
				AdminUser: u,
				StartVote: &sv,
			},
		)
	*/
	// return a copy
	rv := convertDCCStartVoteReplyFromDecred(*vr)
	return &rv, nil
}

// validateDCCVoteBit ensures that bit is a valid vote bit.
func validateDCCVoteBit(vote cms.Vote, bit uint64) error {
	if len(vote.Options) == 0 {
		return fmt.Errorf("vote corrupt")
	}
	if bit == 0 {
		return fmt.Errorf("invalid bit 0x%x", bit)
	}
	if vote.Mask&bit != bit {
		return fmt.Errorf("invalid mask 0x%x bit 0x%x",
			vote.Mask, bit)
	}

	for _, v := range vote.Options {
		if v.Bits == bit {
			return nil
		}
	}

	return fmt.Errorf("bit not found 0x%x", bit)
}
