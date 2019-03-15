// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cockroachdb

import (
	"fmt"
	"strconv"
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
func (c *cockroachdb) CreateInvoice(dbInvoice *database.Invoice) error {
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
func (c *cockroachdb) GetInvoiceByToken(token string) (*database.Invoice, error) {
	log.Debugf("GetInvoiceByToken: %v", token)

	var invoice Invoice
	result := c.recordsdb.Table(fmt.Sprintf("%v i", tableNameInvoice)).Select("i.*, u.username").Joins(
		"inner join users u on i.user_id = u.id").Where(
		"i.token = ?", token).Scan(&invoice)
	if result.Error != nil {
		if gorm.IsRecordNotFoundError(result.Error) {
			return nil, database.ErrInvoiceNotFound
		}
		return nil, result.Error
	}

	result = c.recordsdb.Where("invoice_token = ?", invoice.Token).Find(
		&invoice.Payments)
	if result.Error != nil {
		return nil, result.Error
	}

	return DecodeInvoice(&invoice)
}

// Return a list of invoices.
func (c *cockroachdb) GetInvoices(invoicesRequest database.InvoicesRequest) ([]database.Invoice, int, error) {
	log.Debugf("GetInvoices")

	paramsMap := make(map[string]interface{})
	var err error
	if invoicesRequest.UserID != "" {
		paramsMap["i.user_id"], err = strconv.ParseUint(invoicesRequest.UserID, 10, 64)
		if err != nil {
			return nil, 0, err
		}
	}

	if invoicesRequest.StatusMap != nil && len(invoicesRequest.StatusMap) > 0 {
		statuses := make([]uint, 0, len(invoicesRequest.StatusMap))
		for k := range invoicesRequest.StatusMap {
			statuses = append(statuses, uint(k))
		}
		paramsMap["i.status"] = statuses
	}

	if invoicesRequest.Month != 0 {
		paramsMap["i.month"] = invoicesRequest.Month
	}

	if invoicesRequest.Year != 0 {
		paramsMap["i.year"] = invoicesRequest.Year
	}

	//tbl := fmt.Sprintf("%v i", tableNameInvoice)
	//sel := "i.*, u.username"
	//join := fmt.Sprintf("inner join %v u on i.user_id = u.id", tableNameUser)
	/*
		order := "i.timestamp asc"

		db := c.recordsdb.Table(tbl)
		if invoicesRequest.Page > -1 {
			offset := invoicesRequest.Page * v1.ListPageSize
			db = db.Offset(offset).Limit(v1.ListPageSize)
		}
		db = db.Select(sel).Joins(join)
		db = c.addWhereClause(db, paramsMap)
		db = db.Order(order)

		var invoices []Invoice
		result := db.Scan(&invoices)
		if result.Error != nil {
			if gorm.IsRecordNotFoundError(result.Error) {
				return nil, 0, database.ErrInvoiceNotFound
			}
			return nil, 0, result.Error
		}

		// If the number of users returned equals the apage size,
		// find the count of all users that match the query.
		numMatches := len(invoices)
		if len(invoices) == v1.ListPageSize {
			db = c.recordsdb.Table(tbl).Select(sel).Joins(join)
			db = c.addWhereClause(db, paramsMap)
			result = db.Count(&numMatches)
			if result.Error != nil {
				return nil, 0, result.Error
			}
		}
	*/
	var invoices []Invoice
	dbInvoices, err := DecodeInvoices(invoices)
	if err != nil {
		return nil, 0, err
	}
	return dbInvoices, 0, nil
}

func (c *cockroachdb) UpdateInvoicePayment(dbInvoicePayment *database.InvoicePayment) error {
	invoicePayment := EncodeInvoicePayment(dbInvoicePayment)

	log.Debugf("UpdateInvoicePayment: %v", invoicePayment.InvoiceToken)

	return c.recordsdb.Save(invoicePayment).Error
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
