package cockroachdb

import (
	"time"

	www "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/database"
)

// EncodeInvoice encodes a generic database.Invoice instance into a cockroachdb
// Invoice.
func EncodeInvoice(dbInvoice *database.Invoice) *Invoice {
	invoice := Invoice{}

	invoice.Token = dbInvoice.Token
	invoice.UserID = uint(dbInvoice.UserID)
	invoice.Month = uint(dbInvoice.Month)
	invoice.Year = uint(dbInvoice.Year)
	invoice.Status = uint(dbInvoice.Status)
	invoice.StatusChangeReason = dbInvoice.StatusChangeReason
	invoice.Timestamp = time.Unix(dbInvoice.Timestamp, 0)

	files := make([]www.File, len(dbInvoice.Files))
	for i := 0; i < len(dbInvoice.Files); i++ {
		file := www.File{
			Payload: dbInvoice.Files[i].Payload,
			MIME:    dbInvoice.Files[i].MIME,
			Digest:  dbInvoice.Files[i].Digest,
		}
		files[i] = file
	}
	invoice.PublicKey = dbInvoice.PublicKey
	invoice.UserSignature = dbInvoice.UserSignature
	invoice.ServerSignature = dbInvoice.ServerSignature
	invoice.Proposal = dbInvoice.Proposal
	invoice.Version = dbInvoice.Version

	for _, dbInvoiceChange := range dbInvoice.Changes {
		invoiceChange := EncodeInvoiceChange(&dbInvoiceChange)
		invoiceChange.InvoiceToken = invoice.Token
		invoice.Changes = append(invoice.Changes, *invoiceChange)
		invoice.Status = invoiceChange.NewStatus
	}

	for _, dbInvoicePayment := range dbInvoice.Payments {
		invoicePayment := EncodeInvoicePayment(&dbInvoicePayment)
		invoicePayment.InvoiceToken = invoice.Token
		invoice.Payments = append(invoice.Payments, *invoicePayment)
	}

	return &invoice
}

// EncodeInvoiceChange encodes a generic database.InvoiceChange instance into a cockroachdb
// InvoiceChange.
func EncodeInvoiceChange(dbInvoiceChange *database.InvoiceChange) *InvoiceChange {
	invoiceChange := InvoiceChange{}

	invoiceChange.AdminPublicKey = dbInvoiceChange.AdminPublicKey
	invoiceChange.NewStatus = uint(dbInvoiceChange.NewStatus)
	invoiceChange.Timestamp = time.Unix(dbInvoiceChange.Timestamp, 0)

	return &invoiceChange
}

// EncodeInvoicePayment encodes a generic database.InvoicePayment instance into a cockroachdb
// InvoicePayment.
func EncodeInvoicePayment(dbInvoicePayment *database.InvoicePayment) *InvoicePayment {
	invoicePayment := InvoicePayment{}

	invoicePayment.ID = uint(dbInvoicePayment.ID)
	invoicePayment.InvoiceToken = dbInvoicePayment.InvoiceToken
	invoicePayment.IsTotalCost = dbInvoicePayment.IsTotalCost
	invoicePayment.Address = dbInvoicePayment.Address
	invoicePayment.Amount = uint(dbInvoicePayment.Amount)
	invoicePayment.TxNotBefore = dbInvoicePayment.TxNotBefore
	invoicePayment.PollExpiry = dbInvoicePayment.PollExpiry
	invoicePayment.TxID = dbInvoicePayment.TxID

	return &invoicePayment
}

// DecodeInvoice decodes a cockroachdb Invoice instance into a generic database.Invoice.
func DecodeInvoice(invoice *Invoice) (*database.Invoice, error) {
	dbInvoice := database.Invoice{}

	dbInvoice.Token = invoice.Token
	dbInvoice.UserID = uint64(invoice.UserID)
	dbInvoice.Username = invoice.Username
	dbInvoice.Month = uint16(invoice.Month)
	dbInvoice.Year = uint16(invoice.Year)
	dbInvoice.Status = www.InvoiceStatusT(invoice.Status)
	dbInvoice.StatusChangeReason = invoice.StatusChangeReason
	dbInvoice.Timestamp = invoice.Timestamp.Unix()
	dbInvoice.PublicKey = invoice.PublicKey
	dbInvoice.UserSignature = invoice.UserSignature
	dbInvoice.ServerSignature = invoice.ServerSignature
	dbInvoice.Proposal = invoice.Proposal
	dbInvoice.Version = invoice.Version
	/*
		for _, invoiceChange := range invoice.Changes {
			dbInvoiceChange := DecodeInvoiceChange(&invoiceChange)
			dbInvoice.Changes = append(dbInvoice.Changes, *dbInvoiceChange)
		}
	*/
	for _, invoicePayment := range invoice.Payments {
		dbInvoicePayment := DecodeInvoicePayment(&invoicePayment)
		dbInvoice.Payments = append(dbInvoice.Payments, *dbInvoicePayment)
	}

	return &dbInvoice, nil
}

// DecodeInvoiceChange decodes a cockroachdb InvoiceChange instance into a generic
// database.InvoiceChange.
func DecodeInvoiceChange(invoiceChange *InvoiceChange) *database.InvoiceChange {
	dbInvoiceChange := database.InvoiceChange{}

	dbInvoiceChange.AdminPublicKey = invoiceChange.AdminPublicKey
	dbInvoiceChange.NewStatus = www.InvoiceStatusT(invoiceChange.NewStatus)
	dbInvoiceChange.Timestamp = invoiceChange.Timestamp.Unix()

	return &dbInvoiceChange
}

// DecodeInvoicePayment decodes a cockroachdb InvoicePayment instance into a
// generic database.InvoicePayment.
func DecodeInvoicePayment(invoicePayment *InvoicePayment) *database.InvoicePayment {
	dbInvoicePayment := database.InvoicePayment{}

	dbInvoicePayment.ID = uint64(invoicePayment.ID)
	dbInvoicePayment.InvoiceToken = invoicePayment.InvoiceToken
	dbInvoicePayment.IsTotalCost = invoicePayment.IsTotalCost
	dbInvoicePayment.Address = invoicePayment.Address
	dbInvoicePayment.Amount = uint64(invoicePayment.Amount)
	dbInvoicePayment.TxNotBefore = invoicePayment.TxNotBefore
	dbInvoicePayment.PollExpiry = invoicePayment.PollExpiry
	dbInvoicePayment.TxID = invoicePayment.TxID

	return &dbInvoicePayment
}

// DecodeInvoices decodes an array of cockroachdb Invoice instances into
// generic database.Invoices.
func DecodeInvoices(invoices []Invoice) ([]database.Invoice, error) {
	dbInvoices := make([]database.Invoice, 0, len(invoices))

	for _, invoice := range invoices {
		dbInvoice, err := DecodeInvoice(&invoice)
		if err != nil {
			return nil, err
		}

		dbInvoices = append(dbInvoices, *dbInvoice)
	}

	return dbInvoices, nil
}
