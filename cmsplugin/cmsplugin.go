package cmsplugin

import (
	"encoding/json"
	"time"
)

// Plugin settings, kinda doesn;t go here but for now it is fine
const (
	Version      = "1"
	ID           = "cms"
	CmdInventory = "inventory"
)

// Inventory is used to retreive the decred plugin inventory.
type Inventory struct{}

// EncodeInventory encodes Inventory into a JSON byte slice.
func EncodeInventory(i Inventory) ([]byte, error) {
	return json.Marshal(i)
}

// DecodeInventory decodes a JSON byte slice into a Inventory.
func DecodeInventory(payload []byte) (*Inventory, error) {
	var i Inventory

	err := json.Unmarshal(payload, &i)
	if err != nil {
		return nil, err
	}

	return &i, nil
}

// InventoryReply returns the decred plugin inventory.
type InventoryReply struct {
	Invoices []Invoice `json:"invoices"` //Invoices
}

// EncodeInventoryReply encodes a InventoryReply into a JSON byte slice.
func EncodeInventoryReply(ir InventoryReply) ([]byte, error) {
	return json.Marshal(ir)
}

// DecodeInventoryReply decodes a JSON byte slice into a inventory.
func DecodeInventoryReply(payload []byte) (*InventoryReply, error) {
	var ir InventoryReply

	err := json.Unmarshal(payload, &ir)
	if err != nil {
		return nil, err
	}

	return &ir, nil
}

type Invoice struct {
	Token              string    `gorm:"primary_key;size:64"`
	UserID             uint      `gorm:"not_null"`
	Month              uint      `gorm:"not_null"`
	Year               uint      `gorm:"not_null"`
	Timestamp          time.Time `gorm:"not_null"`
	Status             uint      `gorm:"not_null"`
	StatusChangeReason string    `gorm:"not_null"`
	PublicKey          string    `gorm:"not_null"`
	UserSignature      string    `gorm:"not_null"`
	ServerSignature    string    `gorm:"not_null"`
	Proposal           string    `gorm:"not_null"`
	Version            string    `gorm:"not_null"`
}
