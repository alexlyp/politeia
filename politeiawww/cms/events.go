// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cms

import (
	"context"
	"fmt"

	pdv2 "github.com/decred/politeia/politeiad/api/v2"
	cmsplugin "github.com/decred/politeia/politeiad/plugins/cms"
	cmplugin "github.com/decred/politeia/politeiad/plugins/comments"
	cmv1 "github.com/decred/politeia/politeiawww/api/comments/v1"
	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	v1 "github.com/decred/politeia/politeiawww/api/records/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/client"
	"github.com/decred/politeia/politeiawww/comments"
	"github.com/decred/politeia/politeiawww/records"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/google/uuid"
)

func (c *Cms) setupEventListeners() {
	// Setup process for each event:
	// 1. Create a channel for the event.
	// 2. Register the channel with the event manager.
	// 3. Launch an event handler to listen for events emitted into the
	//    channel by the event manager.

	log.Debugf("Setting up cms event listeners")

	// Record new
	ch := make(chan interface{})
	c.events.Register(records.EventTypeNew, ch)
	go c.handleEventRecordNew(ch)

	// Record edit
	ch = make(chan interface{})
	c.events.Register(records.EventTypeEdit, ch)
	go c.handleEventRecordEdit(ch)

	// Record set status
	ch = make(chan interface{})
	c.events.Register(records.EventTypeSetStatus, ch)
	go c.handleEventRecordSetStatus(ch)
}

func (p *Cms) handleEventRecordNew(ch chan interface{}) {
	for msg := range ch {
		e, ok := msg.(records.EventNew)
		if !ok {
			log.Errorf("handleEventRecordNew invalid msg: %v", msg)
			continue
		}

		// Compile notification email list
		var (
			emails  = make([]string, 0, 1024)
			ntfnBit = uint64(www.NotificationEmailAdminProposalNew)
		)
		err := p.userdb.AllUsers(func(u *user.User) {
			switch {
			case !u.Admin:
				// Only admins get this notification
				return
			case !u.NotificationIsEnabled(ntfnBit):
				// Admin doesn't have notification bit set
				return
			default:
				// User is an admin and has the notification bit set. Add
				// them to the email list.
				emails = append(emails, u.Email)
			}
		})
		if err != nil {
			log.Errorf("handleEventRecordNew: AllUsers: %v", err)
			return
		}

		// Send notfication email
		var (
			token = e.Record.CensorshipRecord.Token
			name  = proposalNameFromFiles(e.Record.Files)
		)
		err = p.mailNtfnProposalNew(token, name, e.User.Username, emails)
		if err != nil {
			log.Errorf("mailNtfnProposalNew: %v", err)
		}

		log.Debugf("Proposal new ntfn sent %v", token)
	}
}

func (p *Cms) handleEventRecordEdit(ch chan interface{}) {
	for msg := range ch {
		e, ok := msg.(records.EventEdit)
		if !ok {
			log.Errorf("handleEventRecordEdit invalid msg: %v", msg)
			continue
		}

		// Only send edit notifications for public proposals
		if e.Record.State == rcv1.RecordStateUnvetted {
			log.Debugf("Proposal is unvetted no edit ntfn %v",
				e.Record.CensorshipRecord.Token)
			continue
		}

		// Compile notification email list
		var (
			emails   = make([]string, 0, 1024)
			authorID = e.User.ID.String()
			ntfnBit  = uint64(www.NotificationEmailRegularProposalEdited)
		)
		err := p.userdb.AllUsers(func(u *user.User) {
			switch {
			case u.ID.String() == authorID:
				// User is the author. No need to send the notification to
				// the author.
				return
			case u.NotificationIsEnabled(ntfnBit):
				// User doesn't have notification bit set
				return
			default:
				// User has the notification bit set. Add them to the email
				// list.
				emails = append(emails, u.Email)
			}
		})
		if err != nil {
			log.Errorf("handleEventRecordEdit: AllUsers: %v", err)
			continue
		}

		// Send notification email
		var (
			token    = e.Record.CensorshipRecord.Token
			version  = e.Record.Version
			name     = proposalNameFromFiles(e.Record.Files)
			username = e.User.Username
		)
		err = p.mailNtfnProposalEdit(token, version, name, username, emails)
		if err != nil {
			log.Errorf("mailNtfnProposaledit: %v", err)
			continue
		}

		log.Debugf("Proposal edit ntfn sent %v", token)
	}
}

func (p *Cms) ntfnRecordSetStatusToAuthor(r rcv1.Record) error {
	// Unpack args
	var (
		token    = r.CensorshipRecord.Token
		status   = r.Status
		name     = proposalNameFromFiles(r.Files)
		authorID = userIDFromMetadata(r.Metadata)
	)

	// Parse the status change reason
	sc, err := client.StatusChangesDecode(r.Metadata)
	if err != nil {
		return fmt.Errorf("decode status changes: %v", err)
	}
	if len(sc) == 0 {
		return fmt.Errorf("not status changes found %v", token)
	}
	reason := sc[len(sc)-1].Reason

	// Get author
	uid, err := uuid.Parse(authorID)
	if err != nil {
		return err
	}
	author, err := p.userdb.UserGetById(uid)
	if err != nil {
		return fmt.Errorf("UserGetById %v: %v", uid, err)
	}

	// Send notification to author
	ntfnBit := uint64(www.NotificationEmailRegularProposalVetted)
	if !author.NotificationIsEnabled(ntfnBit) {
		// Author does not have notification enabled
		log.Debugf("Record set status ntfn to author not enabled %v", token)
		return nil
	}

	// Author has notification enabled
	err = p.mailNtfnProposalSetStatusToAuthor(token, name,
		status, reason, author.Email)
	if err != nil {
		return fmt.Errorf("mailNtfnProposalSetStatusToAuthor: %v", err)
	}

	log.Debugf("Record set status ntfn to author sent %v", token)

	return nil
}

func (p *Cms) ntfnRecordSetStatus(r rcv1.Record) error {
	// Unpack args
	var (
		token    = r.CensorshipRecord.Token
		status   = r.Status
		name     = proposalNameFromFiles(r.Files)
		authorID = userIDFromMetadata(r.Metadata)
	)

	// Compile user notification email list
	var (
		emails  = make([]string, 0, 1024)
		ntfnBit = uint64(www.NotificationEmailRegularProposalVetted)
	)
	err := p.userdb.AllUsers(func(u *user.User) {
		switch {
		case u.ID.String() == authorID:
			// User is the author. The author is sent a different
			// notification. Don't include them in the users list.
			return
		case !u.NotificationIsEnabled(ntfnBit):
			// User does not have notification bit set
			return
		default:
			// Add user to notification list
			emails = append(emails, u.Email)
		}
	})
	if err != nil {
		return fmt.Errorf("AllUsers: %v", err)
	}

	// Send user notifications
	err = p.mailNtfnProposalSetStatus(token, name, status, emails)
	if err != nil {
		return fmt.Errorf("mailNtfnProposalSetStatus: %v", err)
	}

	log.Debugf("Record set status ntfn to users sent %v", token)

	return nil
}

func (p *Cms) handleEventRecordSetStatus(ch chan interface{}) {
	for msg := range ch {
		e, ok := msg.(records.EventSetStatus)
		if !ok {
			log.Errorf("handleRecordSetStatus invalid msg: %v", msg)
			continue
		}

		// Unpack args
		var (
			token  = e.Record.CensorshipRecord.Token
			status = e.Record.Status
		)

		// Verify a notification should be sent
		switch status {
		case rcv1.RecordStatusPublic, rcv1.RecordStatusCensored:
			// Status requires a notification be sent
		default:
			// Status does not require a notification be sent
			log.Debugf("Record set status ntfn not needed for %v status %v",
				rcv1.RecordStatuses[status], token)
			continue
		}

		// Send notification to the author
		err := p.ntfnRecordSetStatusToAuthor(e.Record)
		if err != nil {
			// Log the error and continue. This error should not prevent
			// the other notifications from attempting to be sent.
			log.Errorf("ntfnRecordSetStatusToAuthor: %v", err)
		}

		// Only send a notification to non-author users if the proposal
		// is being made public.
		if status != rcv1.RecordStatusPublic {
			log.Debugf("Record set status ntfn to users not needed for %v status %v",
				rcv1.RecordStatuses[status], token)
			continue
		}

		// Send notification to the users
		err = p.ntfnRecordSetStatus(e.Record)
		if err != nil {
			log.Errorf("ntfnRecordSetStatus: %v", err)
			continue
		}

		// Notifications sent!
		continue
	}
}

func (p *Cms) ntfnCommentNewProposalAuthor(c cmv1.Comment, proposalAuthorID, proposalName string) error {
	// Get the proposal author
	uid, err := uuid.Parse(proposalAuthorID)
	if err != nil {
		return err
	}
	pauthor, err := p.userdb.UserGetById(uid)
	if err != nil {
		return fmt.Errorf("UserGetByID %v: %v", uid.String(), err)
	}

	// Check if notification should be sent
	ntfnBit := uint64(www.NotificationEmailCommentOnMyProposal)
	switch {
	case c.Username == pauthor.Username:
		// Author commented on their own proposal
		log.Debugf("Comment ntfn to proposal author not needed %v", c.Token)
		return nil
	case !pauthor.NotificationIsEnabled(ntfnBit):
		// Author does not have notification bit set on
		log.Debugf("Comment ntfn to proposal author not enabled %v", c.Token)
		return nil
	}

	// Send notification email
	err = p.mailNtfnCommentNewToProposalAuthor(c.Token, c.CommentID,
		c.Username, proposalName, pauthor.Email)
	if err != nil {
		return err
	}

	log.Debugf("Comment new ntfn to proposal author sent %v", c.Token)

	return nil
}

func (p *Cms) ntfnCommentReply(c cmv1.Comment, proposalName string) error {
	// Verify there is work to do. This notification only applies to
	// reply comments.
	if c.ParentID == 0 {
		log.Debugf("Comment reply ntfn not needed %v", c.Token)
		return nil
	}

	// Get the parent comment author
	g := cmplugin.Get{
		CommentIDs: []uint32{c.ParentID},
	}
	cs, err := p.politeiad.CommentsGet(context.Background(), c.Token, g)
	if err != nil {
		return err
	}
	parent, ok := cs[c.ParentID]
	if !ok {
		return fmt.Errorf("parent comment %v not found", c.ParentID)
	}
	userID, err := uuid.Parse(parent.UserID)
	if err != nil {
		return err
	}
	pauthor, err := p.userdb.UserGetById(userID)
	if err != nil {
		return err
	}

	// Check if notification should be sent
	ntfnBit := uint64(www.NotificationEmailCommentOnMyComment)
	switch {
	case c.UserID == pauthor.ID.String():
		// Author replied to their own comment
		log.Debugf("Comment reply ntfn to parent author not needed %v", c.Token)
		return nil
	case !pauthor.NotificationIsEnabled(ntfnBit):
		// Author does not have notification bit set
		log.Debugf("Comment reply ntfn to parent author not enabled %v", c.Token)
		return nil
	}

	// Send notification email
	err = p.mailNtfnCommentReply(c.Token, c.CommentID,
		c.Username, proposalName, pauthor.Email)
	if err != nil {
		return err
	}

	log.Debugf("Comment reply ntfn to parent author sent %v", c.Token)

	return nil
}

func (p *Cms) handleEventCommentNew(ch chan interface{}) {
	for msg := range ch {
		e, ok := msg.(comments.EventNew)
		if !ok {
			log.Errorf("handleEventCommentNew invalid msg: %v", msg)
			continue
		}

		// Get the record author and record name
		var (
			pdr              *pdv2.Record
			r                rcv1.Record
			proposalAuthorID string
			proposalName     string
			err              error
		)
		pdr, err = p.recordAbridged(e.Comment.Token)
		if err != nil {
			goto failed
		}
		r = convertRecordToV1(*pdr)
		proposalAuthorID = userIDFromMetadata(r.Metadata)
		proposalName = proposalNameFromFiles(r.Files)

		// Notify the proposal author
		err = p.ntfnCommentNewProposalAuthor(e.Comment,
			proposalAuthorID, proposalName)
		if err != nil {
			// Log error and continue. This error should not prevent the
			// other notifications from attempting to be sent.
			log.Errorf("ntfnCommentNewProposalAuthor: %v", err)
		}

		// Notify the parent comment author
		err = p.ntfnCommentReply(e.Comment, proposalName)
		if err != nil {
			err = fmt.Errorf("ntfnCommentReply: %v", err)
			goto failed
		}

		// Notifications sent!
		continue

	failed:
		log.Errorf("handleEventCommentNew: %v", err)
		continue
	}
}

// recordAbridged returns a proposal record without its index file or any
// attachment files. This allows the request to be light weight.
func (p *Cms) recordAbridged(token string) (*pdv2.Record, error) {
	reqs := []pdv2.RecordRequest{
		{
			Token: token,
			Filenames: []string{
				cmsplugin.FileNameInvoiceMetadata,
			},
		},
	}
	rs, err := p.politeiad.Records(context.Background(), reqs)
	if err != nil {
		return nil, fmt.Errorf("politeiad records: %v", err)
	}
	r, ok := rs[token]
	if !ok {
		return nil, fmt.Errorf("record not found %v", token)
	}
	return &r, nil
}

// proposalNameFromFiles parses the proposal name from the ProposalMetadata file and
// returns it. An empty string is returned if a proposal name is not found.
func proposalNameFromFiles(files []rcv1.File) string {
	pm, err := client.ProposalMetadataDecode(files)
	if err != nil {
		return ""
	}
	return pm.Name
}

// userIDFromMetadata searches for a UserMetadata and parses the user ID from
// it if found. An empty string is returned if no UserMetadata is found.
func userIDFromMetadata(ms []v1.MetadataStream) string {
	um, err := client.UserMetadataDecode(ms)
	if err != nil {
		return ""
	}
	if um == nil {
		return ""
	}
	return um.UserID
}

func convertStateToV1(s pdv2.RecordStateT) rcv1.RecordStateT {
	switch s {
	case pdv2.RecordStateUnvetted:
		return rcv1.RecordStateUnvetted
	case pdv2.RecordStateVetted:
		return rcv1.RecordStateVetted
	}
	return rcv1.RecordStateInvalid
}

func convertStatusToV1(s pdv2.RecordStatusT) rcv1.RecordStatusT {
	switch s {
	case pdv2.RecordStatusUnreviewed:
		return rcv1.RecordStatusUnreviewed
	case pdv2.RecordStatusPublic:
		return rcv1.RecordStatusPublic
	case pdv2.RecordStatusCensored:
		return rcv1.RecordStatusCensored
	case pdv2.RecordStatusArchived:
		return rcv1.RecordStatusArchived
	}
	return rcv1.RecordStatusInvalid
}

func convertFilesToV1(f []pdv2.File) []rcv1.File {
	files := make([]rcv1.File, 0, len(f))
	for _, v := range f {
		files = append(files, rcv1.File{
			Name:    v.Name,
			MIME:    v.MIME,
			Digest:  v.Digest,
			Payload: v.Payload,
		})
	}
	return files
}

func convertMetadataStreamsToV1(ms []pdv2.MetadataStream) []rcv1.MetadataStream {
	metadata := make([]rcv1.MetadataStream, 0, len(ms))
	for _, v := range ms {
		metadata = append(metadata, rcv1.MetadataStream{
			PluginID: v.PluginID,
			StreamID: v.StreamID,
			Payload:  v.Payload,
		})
	}
	return metadata
}

func convertRecordToV1(r pdv2.Record) rcv1.Record {
	// User fields that are not part of the politeiad record have
	// been intentionally left blank. These fields must be pulled
	// from the user database.
	return rcv1.Record{
		State:     convertStateToV1(r.State),
		Status:    convertStatusToV1(r.Status),
		Version:   r.Version,
		Timestamp: r.Timestamp,
		Username:  "", // Intentionally left blank
		Metadata:  convertMetadataStreamsToV1(r.Metadata),
		Files:     convertFilesToV1(r.Files),
		CensorshipRecord: rcv1.CensorshipRecord{
			Token:     r.CensorshipRecord.Token,
			Merkle:    r.CensorshipRecord.Merkle,
			Signature: r.CensorshipRecord.Signature,
		},
	}
}
