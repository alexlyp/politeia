// Copyright (c) 2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package database

import (
	"errors"

	www "github.com/decred/politeia/politeiawww/api/v1"
)

var (
	// ErrUserNotFound indicates that a user name was not found in the
	// database.
	ErrUserNotFound = errors.New("user not found")

	// ErrInvoiceNotFound indicates that the invoice was not found in the
	// database.
	ErrInvoiceNotFound = errors.New("invoice not found")
)

// Database interface that is required by the web server.
type Database interface {
	// Invoice functions
	NewInvoice(*Invoice) error // Create new invoice

	UpdateInvoice(*Invoice) error // Update existing invoice

	InvoiceByToken(string) (*Invoice, error) // Return invoice given its token

	Invoices(InvoicesRequest) ([]Invoice, int, error) // Return a list of invoices

	NewInvoicePayment(*InvoicePayment) error

	UpdateInvoicePayment(*InvoicePayment) error // Update an existing invoice's payment

	// Get the latest version of all invoices
	Inventory() ([]Invoice, error)

	// Setup the invoice tables
	Setup() error

	// Build the invoice tables from scratch (from inventory of d)
	Build([]Invoice) error

	// Close performs cleanup of the backend.
	Close() error
}

type Invoice struct {
	Token              string
	UserID             uint64
	Username           string // Only populated when reading from the database
	Month              uint16
	Year               uint16
	Timestamp          int64
	Status             www.InvoiceStatusT
	StatusChangeReason string
	Files              []www.File
	PublicKey          string
	UserSignature      string
	ServerSignature    string
	Proposal           string // Optional link to a Politeia proposal
	Version            string // Version number of this invoice

	Changes  []InvoiceChange
	Payments []InvoicePayment
}

// InvoicesRequest is used for passing parameters into the
// GetInvoices() function.
type InvoicesRequest struct {
	UserID    string
	Month     uint16
	Year      uint16
	StatusMap map[www.InvoiceStatusT]bool
	Page      int
}

type InvoiceChange struct {
	AdminPublicKey string
	NewStatus      www.InvoiceStatusT
	Reason         string
	Timestamp      int64
}

type InvoicePayment struct {
	ID           uint64
	InvoiceToken string
	IsTotalCost  bool // Whether this payment represents the total cost of the invoice
	Address      string
	Amount       uint64
	TxNotBefore  int64
	PollExpiry   int64
	TxID         string
}
