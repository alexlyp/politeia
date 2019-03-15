package cockroachdb

import (
	"time"

	_ "github.com/jinzhu/gorm/dialects/postgres"
)

type Invoice struct {
	Token              string    `gorm:"primary_key"`
	UserID             uint      `gorm:"not_null"`
	Username           string    `gorm:"-"` // Only populated when reading from the database
	Month              uint      `gorm:"not_null"`
	Year               uint      `gorm:"not_null"`
	Timestamp          time.Time `gorm:"not_null"`
	Status             uint      `gorm:"not_null"`
	StatusChangeReason string
	Files              []File
	PublicKey          string `gorm:"not_null"`
	UserSignature      string `gorm:"not_null"`
	ServerSignature    string `gorm:"not_null"`
	Proposal           string
	Version            string

	Changes  []InvoiceChange
	Payments []InvoicePayment

	// gorm.Model fields, included manually
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

func (Invoice) TableName() string {
	return tableNameInvoice
}

type InvoiceChange struct {
	InvoiceToken   string
	AdminPublicKey string
	NewStatus      uint
	Timestamp      time.Time
}

func (InvoiceChange) TableName() string {
	return tableNameInvoiceChange
}

type InvoicePayment struct {
	ID           uint
	InvoiceToken string
	IsTotalCost  bool   `gorm:"not_null"`
	Address      string `gorm:"not_null"`
	Amount       uint   `gorm:"not_null"`
	TxNotBefore  int64  `gorm:"not_null"`
	PollExpiry   int64
	TxID         string
}

func (InvoicePayment) TableName() string {
	return tableNameInvoicePayment
}

type File struct {
	// Meta-data
	Name   string `json:"name"`   // Suggested filename
	MIME   string `json:"mime"`   // Mime type
	Digest string `json:"digest"` // Digest of unencoded payload

	// Data
	Payload string `json:"payload"` // File content, base64 encoded
}
