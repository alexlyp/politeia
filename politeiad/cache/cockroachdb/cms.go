package cockroachdb

import (
	"fmt"
	"time"

	"github.com/decred/politeia/cmsplugin"
	"github.com/decred/politeia/politeiad/cache"
	"github.com/jinzhu/gorm"
)

const (
	// cmsVersion is the version of the cache implementation of
	// cms plugin. This may differ from the cmsplugin package
	// version.
	cmsVersion = "1"

	// Cms plugin table names
	tableInvoices        = "invoices"
	tableInvoiceChange   = "invoice_changes"
	tableInvoicePayments = "invoice_payments"
	tableLineItems       = "line_items"
)

// cms implements the PluginDriver interface.
type cms struct {
	recordsdb *gorm.DB              // Database context
	version   string                // Version of decred cache plugin
	settings  []cache.PluginSetting // Plugin settings
}

// newComment inserts a Comment record into the database.  This function has a
// database parameter so that it can be called inside of a transaction when
// required.
func (c *cms) newInvoice(db *gorm.DB, i Invoice) error {
	return db.Create(&i).Error
}

// cmdNewComment creates a Comment record using the passed in payloads and
// inserts it into the database.
func (c *cms) cmdNewInvoice(cmdPayload, replyPayload string) (string, error) {
	log.Tracef("cms cmdNewInvoice")
	/*
		nc, err := cmsplugin.DecodeNewInvoice([]byte(cmdPayload))
		if err != nil {
			return "", err
		}
		ncr, err := cmsplugin.DecodeInvoiceReply([]byte(replyPayload))
		if err != nil {
			return "", err
		}

		i := convertNewInvoiceFromCms(*nc, *ncr)
		err = c.newInvoice(c.recordsdb, i)
	*/
	return replyPayload, nil
}

// cmdInventory returns the decred plugin inventory.
func (c *cms) cmdInventory() (string, error) {
	log.Tracef("cms cmdInventory")

	// Get all invoices
	/*
			var i []Invoice
			err := c.recordsdb.Find(&i).Error
			if err != nil {
				return "", err
			}

			dc := make([]decredplugin.Comment, 0, len(i))
			for _, v := range i {
				dc = append(dc, convertCommentToDecred(v))
			}

			// Prepare inventory reply
			ir := decredplugin.InventoryReply{
				Comments: dc,
			}
			irb, err := decredplugin.EncodeInventoryReply(ir)
			if err != nil {
				return "", err
			}
		return string(irb), err
	*/
	return "", nil
}

// Exec executes a decred plugin command.  Plugin commands that write data to
// the cache require both the command payload and the reply payload.  Plugin
// commands that fetch data from the cache require only the command payload.
// All commands return the appropriate reply payload.
func (c *cms) Exec(cmd, cmdPayload, replyPayload string) (string, error) {
	log.Tracef("decred Exec: %v", cmd)

	switch cmd {
	case cmsplugin.CmdInventory:
		return c.cmdInventory()
	}

	return "", cache.ErrInvalidPluginCmd
}

// createCmsTables creates the cache tables needed by the cms plugin if
// they do not already exist. A cms plugin version record is inserted into
// the database during table creation.
//
// This function must be called within a transaction.
func createCmsTables(tx *gorm.DB) error {
	log.Tracef("createCmsTables")

	// Create decred plugin tables
	if !tx.HasTable(tableComments) {
		err := tx.CreateTable(&Comment{}).Error
		if err != nil {
			return err
		}
	}

	// Check if a decred version record exists. Insert one
	// if no version record is found.
	if !tx.HasTable(tableVersions) {
		// This should never happen
		return fmt.Errorf("versions table not found")
	}

	var v Version
	err := tx.Where("id = ?", cmsplugin.ID).
		Find(&v).
		Error
	if err == gorm.ErrRecordNotFound {
		err = tx.Create(
			&Version{
				ID:        cmsplugin.ID,
				Version:   cmsVersion,
				Timestamp: time.Now().Unix(),
			}).Error
	}

	return err
}

// build the cms plugin cache using the passed in inventory.
//
// This function must be called within a transaction.
func (c *cms) build(tx *gorm.DB, ir *cmsplugin.InventoryReply) error {
	log.Tracef("cms build")

	// Create the database tables
	err := createCmsTables(tx)
	if err != nil {
		return fmt.Errorf("createCmsTables: %v", err)
	}

	return nil
}

// Build drops all existing cms plugin tables from the database, recreates
// them, then uses the passed in inventory payload to build the cms plugin
// cache.
func (c *cms) Build(payload string) error {
	log.Tracef("cms Build")

	// Decode the payload
	ir, err := cmsplugin.DecodeInventoryReply([]byte(payload))
	if err != nil {
		return fmt.Errorf("DecodeInventoryReply: %v", err)
	}

	// Drop all decred plugin tables
	err = c.recordsdb.DropTableIfExists(tableInvoices, tableInvoiceChange, tableInvoicePayments, tableLineItems).Error
	if err != nil {
		return fmt.Errorf("drop decred tables failed: %v", err)
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

// Setup creates the decred plugin tables if they do not already exist.  A
// decred plugin version record is inserted into the database during table
// creation.
func (c *cms) Setup() error {
	tx := c.recordsdb.Begin()
	err := createCmsTables(tx)
	if err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit().Error
}

// CheckVersion retrieves the cms plugin version record from the database,
// if one exists, and checks that it matches the version of the current cms
// plugin cache implementation.
func (c *cms) CheckVersion() error {
	// Sanity check. Ensure version table exists.
	if !c.recordsdb.HasTable(tableVersions) {
		return fmt.Errorf("versions table not found")
	}

	// Lookup version record
	var v Version
	err := c.recordsdb.
		Where("id = ?", cmsplugin.ID).
		Find(&v).
		Error
	if err == gorm.ErrRecordNotFound {
		// A version record not being found indicates that the
		// decred plugin cache has not been built yet. Return a
		// ErrWrongPluginVersion error so that the cache will be
		// built.
		return cache.ErrWrongPluginVersion
	} else if err != nil {
		return err
	}

	// Ensure we're using the correct version
	if v.Version != cmsVersion {
		return cache.ErrWrongPluginVersion
	}

	return nil
}

// newCmsPlugin returns a cache decred plugin context.
func newCmsPlugin(db *gorm.DB, p cache.Plugin) *cms {
	log.Tracef("newCmsPlugin")
	return &cms{
		recordsdb: db,
		version:   cmsVersion,
		settings:  p.Settings,
	}
}
