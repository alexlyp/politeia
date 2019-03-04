// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cockroachdb

import "time"

// Version describes the version of a record or plugin that the database is
// currently using.
type Version struct {
	ID        string `gorm:"primary_key"` // Primary key
	Version   string `gorm:"not null"`    // Version
	Timestamp int64  `gorm:"not null"`    // UNIX timestamp of record creation
}

// TableName returns the name of the Version database table.
func (Version) TableName() string {
	return tableVersions
}

// File describes an individual file that is part of the record.
type File struct {
	Key       uint   `gorm:"primary_key"`      // Primary key
	RecordKey string `gorm:"not null"`         // Record foreign key
	Name      string `gorm:"not null"`         // Basename of the file
	MIME      string `gorm:"not null"`         // MIME type
	Digest    string `gorm:"not null;size:64"` // SHA256 of decoded Payload
	Payload   string `gorm:"not null"`         // base64 encoded file
}

// TableName returns the name of the File database table.
func (File) TableName() string {
	return tableFiles
}

// MetadataStream identifies a metadata stream by its identity.
type MetadataStream struct {
	Key       uint   `gorm:"primary_key"` // Primary key
	RecordKey string `gorm:"not null"`    // Record foreign key
	ID        uint64 `gorm:"not null"`    // Stream identity
	Payload   string `gorm:"not null"`    // String encoded metadata
}

// TableName returns the name of the MetadataStream database table.
func (MetadataStream) TableName() string {
	return tableMetadataStreams
}

// Record is an entire record and it's content.
type Record struct {
	Key       string `gorm:"primary_key"`       // Primary key (token+version)
	Token     string `gorm:"not null;size:64"`  // Censorship token
	Version   string `gorm:"not null"`          // Version of files
	Status    int    `gorm:"not null"`          // Current status
	Timestamp int64  `gorm:"not null"`          // UNIX timestamp of last updated
	Merkle    string `gorm:"not null;size:64"`  // Merkle root of all files in record
	Signature string `gorm:"not null;size:128"` // Server signature of merkle+token

	Metadata []MetadataStream `gorm:"foreignkey:RecordKey"` // User provided metadata
	Files    []File           `gorm:"foreignkey:RecordKey"` // User provided files
}

// TableName returns the name of the Record database table.
func (Record) TableName() string {
	return tableRecords
}

// Comment is a decred plugin comment, including all of the server side
// metadata.
type Comment struct {
	Key       string `gorm:"primary_key"`       // Primary key (token+commentID)
	Token     string `gorm:"not null;size:64"`  // Censorship token
	ParentID  string `gorm:"not null"`          // Parent comment ID
	Comment   string `gorm:"not null"`          // Comment
	Signature string `gorm:"not null;size:128"` // Client Signature of Token+ParentID+Comment
	PublicKey string `gorm:"not null;size:64"`  // Pubkey used for Signature
	CommentID string `gorm:"not null"`          // Comment ID
	Receipt   string `gorm:"not null"`          // Server signature of the client Signature
	Timestamp int64  `gorm:"not null"`          // Received UNIX timestamp
	Censored  bool   `gorm:"not null"`          // Has this comment been censored
}

// TableName returns the name of the Comment database table.
func (Comment) TableName() string {
	return tableComments
}

// LikeComment is a decred plugin comment upvote/downvote.  The server side
// metadata is not included.
type LikeComment struct {
	Key       uint   `gorm:"primary_key"`       // Primary key
	Token     string `gorm:"not null;size:64"`  // Censorship token
	CommentID string `gorm:"not null"`          // Comment ID
	Action    string `gorm:"not null;size:2"`   // Up or downvote (1, -1)
	Signature string `gorm:"not null;size:128"` // Client Signature of Token+CommentID+Action
	PublicKey string `gorm:"not null;size:64"`  // Public key used for Signature
}

// TableName returns the name of the LikeComment database table.
func (LikeComment) TableName() string {
	return tableCommentLikes
}

// AuthorizeVote is a decred plugin metadata stream that is created by a
// proposal author and is used to indicate that the proposal has been finalized
// and is ready to be voted on.
type AuthorizeVote struct {
	Key       string `gorm:"primary_key"`       // Primary key (token+version)
	Token     string `gorm:"not null;size:64"`  // Censorship token
	Version   string `gorm:"not null"`          // Version of files
	Action    string `gorm:"not null"`          // Authorize or revoke
	Signature string `gorm:"not null;size:128"` // Signature of token+version+action
	PublicKey string `gorm:"not null;size:64"`  // Pubkey used for signature
	Receipt   string `gorm:"not null;size:128"` // Server signature of client signature
	Timestamp int64  `gorm:"not null"`          // Received UNIX timestamp
}

// TableName returns the name of the AuthorizeVote database table.
func (AuthorizeVote) TableName() string {
	return tableAuthorizeVotes
}

// VoteOption is a decred plugin struct that describes a single vote option.
type VoteOption struct {
	Key         uint   `gorm:"primary_key"`      // Primary key
	Token       string `gorm:"not null;size:64"` // StartVote foreign key
	ID          string `gorm:"not null"`         // Single unique word identifying vote (e.g. yes)
	Description string `gorm:"not null"`         // Longer description of the vote
	Bits        uint64 `gorm:"not null"`         // Bits used for this option
}

// TableName returns the name of the VoteOption database table.
func (VoteOption) TableName() string {
	return tableVoteOptions
}

// StartVote is a decred plugin struct that is used to record the details of
// a proposal vote.
type StartVote struct {
	Token            string       `gorm:"primary_key;size:64"` // Censorship token
	Version          string       `gorm:"not null"`            // Version of files
	Mask             uint64       `gorm:"not null"`            // Valid votebits
	Duration         uint32       `gorm:"not null"`            // Duration in blocks
	QuorumPercentage uint32       `gorm:"not null"`            // Percent of eligible votes required for quorum
	PassPercentage   uint32       `gorm:"not null"`            // Percent of total votes required to pass
	Options          []VoteOption `gorm:"foreignkey:Token"`    // Vote option
	PublicKey        string       `gorm:"not null;size:64"`    // Key used for signature
	Signature        string       `gorm:"not null;size:128"`   // Signature of Votehash
	StartBlockHeight string       `gorm:"not null"`            // Block height
	StartBlockHash   string       `gorm:"not null"`            // Block hash
	EndHeight        string       `gorm:"not null"`            // Height of vote end
	EligibleTickets  string       `gorm:"not null"`            // Valid voting tickets
}

// TableName returns the name of the StartVote database table.
func (StartVote) TableName() string {
	return tableStartVotes
}

// CastVote is a decred plugin struct that is used to record a signed vote.
type CastVote struct {
	Key       uint   `gorm:"primary_key"`       // Primary key
	Token     string `gorm:"not null;size:64"`  // Censorship token
	Ticket    string `gorm:"not null"`          // Ticket ID
	VoteBit   string `gorm:"not null"`          // Vote bit that was selected, this is encode in hex
	Signature string `gorm:"not null;size:130"` // Signature of Token+Ticket+VoteBit
}

// TableName returns the name of the CastVote database table.
func (CastVote) TableName() string {
	return tableCastVotes
}

type Invoice struct {
	Token              string           `gorm:"primary_key;size:64"`
	UserID             uint             `gorm:"not_null"`
	Month              uint             `gorm:"not_null"`
	Year               uint             `gorm:"not_null"`
	Timestamp          time.Time        `gorm:"not_null"`
	Status             uint             `gorm:"not_null"`
	StatusChangeReason string           `gorm:"not_null"`
	Files              []File           `gorm:"foreignkey:RecordKey"` // User provided files
	PublicKey          string           `gorm:"not_null"`
	UserSignature      string           `gorm:"not_null"`
	ServerSignature    string           `gorm:"not_null"`
	Proposal           string           `gorm:"not_null"`
	Version            string           `gorm:"not_null"`
	LineItems          []LineItem       `gorm:"not_null"`
	Changes            []InvoiceChange  `gorm:"not_null"`
	Payments           []InvoicePayment `gorm:"not_null"`
}

func (Invoice) TableName() string {
	return tableInvoices
}

type InvoiceChange struct {
	Key            uint      `gorm:"primary_key"`      // Primary key
	Token          string    `gorm:"not null;size:64"` // Censorship token
	AdminPublicKey string    `gorm:"not null;size:64"` // Key used for signature
	NewStatus      uint      `gorm:"not null"`         // Updated status
	Timestamp      time.Time `gorm:"not null"`         // Received UNIX timestamp
}

func (InvoiceChange) TableName() string {
	return tableInvoiceChange
}

type InvoicePayment struct {
	Key         uint   `gorm:"primary_key"`      // Primary key
	Token       string `gorm:"not null;size:64"` // Censorship token
	IsTotalCost bool   `gorm:"not_null"`         // Is this the entire payment for an invoice
	Address     string `gorm:"not_null"`         // Address paid to by the payment
	Amount      uint   `gorm:"not_null"`         // Amount paid by the payment
	TxNotBefore int64  `gorm:"not_null"`         // ???
	PollExpiry  int64  `gorm:"not_null"`         // ???
	TxID        string `gorm:"not_null"`         // Transaction Hash of the payment
}

func (InvoicePayment) TableName() string {
	return tableInvoicePayments
}

// LineItem is contains all the information about line items contained in Invoices
// that are currently records and entries in the database
type LineItem struct {
	Key         string `gorm:"primary_key;size:64"` // Identifying line item token
	Token       string `gorm:"not null"`            // Invoice's Censorship token
	LineNumber  uint   `gorm:"not null"`            // Invoice line number
	Type        string `gorm:"not null"`            // Type of work being submitted
	SubType     string `gorm:"not null"`            // Subtype of work (if necessary)
	Description string `gorm:"not null"`            // Description of work being completed
	Hours       uint   `gorm:"not null"`            // Number of hours worked (if necessary)
	Rate        int64  `gorm:"not null"`            // Hourly Rate of work (if necessary)
	TotalCost   int64  `gorm:"not null"`            // Total Cost of the Line Item
	Proposal    string `gorm:"not null"`            // Token of related proposal (if necessary)
}

// TableName returns the name of the LineItem database table.
func (LineItem) TableName() string {
	return tableLineItems
}
