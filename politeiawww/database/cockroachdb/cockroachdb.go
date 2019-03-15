// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cockroachdb

import (
	"fmt"
	"sync"

	"github.com/decred/politeia/decredplugin"
	"github.com/decred/politeia/politeiawww/database"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

const (
	cacheID      = "records"
	cacheVersion = "1"

	// Database table names
	tableNameInvoice        = "invoices"
	tableNameInvoiceChange  = "invoice_changes"
	tableNameInvoicePayment = "invoice_payments"

	// Database users
	UserPoliteiad   = "records_politeiad"   // politeiad user (read/write access)
	UserPoliteiawww = "records_politeiawww" // politeiawww user (read access)
)

// cockroachdb implements the cache interface.
type cockroachdb struct {
	sync.RWMutex
	shutdown  bool     // Backend is shutdown
	recordsdb *gorm.DB // Database context
}

// Create new invoice.
//
// CreateInvoice satisfies the backend interface.
func (c *cockroachdb) NewInvoice(dbInvoice *database.Invoice) error {
	invoice := EncodeInvoice(dbInvoice)

	log.Debugf("CreateInvoice: %v", invoice.Token)
	return c.recordsdb.Create(invoice).Error
}

// Update existing invoice.
//
// CreateInvoice satisfies the backend interface.
func (c *cockroachdb) UpdateInvoice(dbInvoice *database.Invoice) error {
	invoice := EncodeInvoice(dbInvoice)

	log.Debugf("UpdateInvoice: %v", invoice.Token)

	return c.recordsdb.Save(invoice).Error
}

// Return invoice by its token.
func (c *cockroachdb) InvoiceByToken(token string) (*database.Invoice, error) {
	log.Debugf("InvoiceByToken: %v", token)

	invoice := Invoice{
		Token: token,
	}
	err := c.recordsdb.Find(&invoice).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			err = database.ErrInvoiceNotFound
		}
		return nil, err
	}

	return DecodeInvoice(&invoice)
}

// Close satisfies the backend interface.
func (c *cockroachdb) Close() error {
	return c.recordsdb.Close()
}

// This function must be called within a transaction.
func createCmsTables(tx *gorm.DB) error {
	log.Tracef("createCmsTables")

	// Create cms tables
	if !tx.HasTable(tableNameInvoice) {
		err := tx.CreateTable(&Invoice{}).Error
		if err != nil {
			return err
		}
	}
	if !tx.HasTable(tableNameInvoiceChange) {
		err := tx.CreateTable(&InvoiceChange{}).Error
		if err != nil {
			return err
		}
	}
	if !tx.HasTable(tableNameInvoicePayment) {
		err := tx.CreateTable(&InvoicePayment{}).Error
		if err != nil {
			return err
		}
	}
	return nil
}

//
// This function must be called within a transaction.
func (c *cockroachdb) build(tx *gorm.DB, ir *decredplugin.InventoryReply) error {
	log.Tracef("cms build")

	// Create the database tables
	err := createCmsTables(tx)
	if err != nil {
		return fmt.Errorf("createCmsTables: %v", err)
	}

	// pull Inventory from d then rebuild invoice database
	return nil
}

// Build drops all existing decred plugin tables from the database, recreates
// them, then uses the passed in inventory payload to build the decred plugin
// cache.
func (c *cockroachdb) Build(payload string) error {
	log.Tracef("invoice Build")

	// Decode the payload
	ir, err := decredplugin.DecodeInventoryReply([]byte(payload))
	if err != nil {
		return fmt.Errorf("DecodeInventoryReply: %v", err)
	}

	// Drop all decred plugin tables
	err = c.recordsdb.DropTableIfExists(tableNameInvoice, tableNameInvoiceChange, tableNameInvoicePayment).Error
	if err != nil {
		return fmt.Errorf("drop invoice tables failed: %v", err)
	}

	// Build the decred plugin cache from scratch
	tx := c.recordsdb.Begin()
	err = c.build(tx, ir)
	if err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit().Error
}

func (c *cockroachdb) Setup() error {
	tx := c.recordsdb.Begin()
	err := createCmsTables(tx)
	if err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit().Error
}
