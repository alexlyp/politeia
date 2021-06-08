// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package cms provides a plugin that extends records with functionality for
// decred's contractor management system.
package cms

const (
	// PluginID is the unique identifier for this plugin.
	PluginID = "cms"
)

// Plugin setting keys can be used to specify custom plugin settings. Default
// plugin setting values can be overridden by providing a plugin setting key
// and value to the plugin on startup.
const (
	// SettingKeyTextFileSizeMax is the plugin setting key for the
	// SettingTextFileSizeMax plugin setting.
	SettingKeyTextFileSizeMax = "textfilesizemax"

	// SettingKeyImageFileCountMax is the plugin setting key for the
	// SettingImageFileCountMax plugin setting.
	SettingKeyImageFileCountMax = "imagefilecountmax"

	// SettingKeyImageFileSizeMax is the plugin setting key for the
	// SettingImageFileSizeMax plugin setting.
	SettingKeyImageFileSizeMax = "imagefilesizemax"

	// SettingKeyInvoiceNameLengthMin is the plugin setting key for
	// the SettingInvoiceNameLengthMin plugin setting.
	SettingKeyInvoiceNameLengthMin = "invoicenamelengthmin"

	// SettingKeyInvoiceNameLengthMax is the plugin setting key for
	// the SettingInvoiceNameLengthMax plugin setting.
	SettingKeyInvoiceNameLengthMax = "invoicenamelengthmax"

	// SettingKeyInvoiceNameSupportedChars is the plugin setting key
	// for the SettingInvoiceNameSupportedChars plugin setting.
	SettingKeyInvoiceNameSupportedChars = "invoicenamesupportedchars"
)

// Plugin setting default values. These can be overridden by providing a plugin
// setting key and value to the plugin on startup.
const (
	// SettingTextFileSizeMax is the default maximum allowed size of a
	// text file in bytes.
	SettingTextFileSizeMax uint32 = 512 * 1024

	// SettingImageFileCountMax is the default maximum number of image
	// files that can be included in a invoice.
	SettingImageFileCountMax uint32 = 5

	// SettingImageFileSizeMax is the default maximum allowed size of
	// an image file in bytes.
	SettingImageFileSizeMax uint32 = 512 * 1024

	// SettingInvoiceNameLengthMin is the default minimum number of
	// characters that a invoice name can be.
	SettingInvoiceNameLengthMin uint32 = 8

	// SettingInvoiceNameLengthMax is the default maximum number of
	// characters that a invoice name can be.
	SettingInvoiceNameLengthMax uint32 = 80
)

var (
	// SettingInvoiceNameSupportedChars contains the supported
	// characters in a invoice name.
	SettingInvoiceNameSupportedChars = []string{
		"A-z", "0-9", "&", ".", ",", ":", ";", "-", " ", "@", "+", "#",
		"/", "(", ")", "!", "?", "\"", "'",
	}
)

/*
	// PolicyValidMimeTypes is the accepted mime types of attachments
	// in invoices
	PolicyValidMimeTypes = []string{
		"image/png",
	}

	// PolicyInvoiceFieldSupportedChars is the regular expression of a valid
	// invoice fields.
	PolicyInvoiceFieldSupportedChars = []string{
		"A-z", "0-9", "&", ".", ",", ":", ";", "-", " ", "@", "+", "#", "/",
		"(", ")", "!", "?", "\"", "'"}

	// PolicyCMSNameLocationSupportedChars is the regular expression of a valid
	// name or location for registering users on cms.
	PolicyCMSNameLocationSupportedChars = []string{
		"A-z", "0-9", ".", "-", " ", ","}

	// PolicyCMSContactSupportedChars is the regular expression of a valid
	// contact for registering users on cms.
	PolicyCMSContactSupportedChars = []string{
		"A-z", "0-9", "&", ".", ":", "-", "_", "@", "+", ",", " "}

	// PolicySponsorStatementSupportedChars is the regular expression of a valid
	// sponsor statement for DCC in cms.
	PolicySponsorStatementSupportedChars = []string{
		"A-z", "0-9", "&", ".", ",", ":", ";", "-", " ", "@", "+", "#", "/",
		"(", ")", "!", "?", "\"", "'", "\n"}

	// PolicySupportedCMSDomains supplies the currently available domain types
	// and descriptions of them.
	PolicySupportedCMSDomains = []AvailableDomain{
		{
			Description: "development",
			Type:        DomainTypeDeveloper,
		},
		{
			Description: "marketing",
			Type:        DomainTypeMarketing,
		},
		{
			Description: "research",
			Type:        DomainTypeResearch,
		},
		{
			Description: "design",
			Type:        DomainTypeDesign,
		},
	}

	// PolicyCMSSupportedLineItemTypes supplies the currently available invoice types
	// and descriptions of them.
	PolicyCMSSupportedLineItemTypes = []AvailableLineItemType{
		{
			Description: "labor",
			Type:        LineItemTypeLabor,
		},
		{
			Description: "expense",
			Type:        LineItemTypeExpense,
		},
		{
			Description: "misc",
			Type:        LineItemTypeMisc,
		},
		{
			Description: "subhours",
			Type:        LineItemTypeSubHours,
		},
	}
*/

// ErrorCodeT represents a plugin error that was caused by the user.
type ErrorCodeT uint32

const (
	// ErrorCodeInvalid represents and invalid error code.
	ErrorCodeInvalid ErrorCodeT = 0

	// ErrorCodeTextFileNameInvalid is returned when a text file has
	// a file name that is not allowed.
	ErrorCodeTextFileNameInvalid ErrorCodeT = 1

	// ErrorCodeTextFileSizeInvalid is returned when a text file size
	// exceedes the TextFileSizeMax setting.
	ErrorCodeTextFileSizeInvalid ErrorCodeT = 2

	// ErrorCodeTextFileMissing is returned when the invoice does not
	// contain one or more of the required text files.
	ErrorCodeTextFileMissing ErrorCodeT = 3

	// ErrorCodeImageFileCountInvalid is returned when the number of
	// image attachments exceedes the ImageFileCountMax setting.
	ErrorCodeImageFileCountInvalid ErrorCodeT = 4

	// ErrorCodeImageFileSizeInvalid is returned when an image file
	// size exceedes the ImageFileSizeMax setting.
	ErrorCodeImageFileSizeInvalid ErrorCodeT = 5

	// ErrorCodeInvoiceNameInvalid is returned when a invoice name
	// does not adhere to the invoice name settings.
	ErrorCodeInvoiceNameInvalid ErrorCodeT = 6

	// ErrorCodeLocationMissing
	ErrorCodeLocationMissing = 7

	// ErrorCodeLocationInvalid
	ErrorCodeLocationInvalid = 8

	// ErrorCodeMonthYearMissing
	ErrorCodeMonthYearMissing = 9

	// ErrorCodeMonthYearInvalid
	ErrorCodeMonthYearInvalid = 10

	// ErrorCodeLineItemInvalid
	ErrorCodeLineItemInvalid = 11

	// ErrorCodePaymentAddressInvalid
	ErrorCodePaymentAddressInvalid = 12

	// ErrorCodeContractorNameMissing
	ErrorCodeContractorNameMissing = 13

	// ErrorCodeContractorContactMissing
	ErrorCodeContractorContactMissing = 14

	// ErrorCodeContractorContactInvalid
	ErrorCodeContractorContactInvalid = 15

	// ErrorCodeContractorRateMissing
	ErrorCodeContractorRateMissing = 16

	// ErrorCodeContractorRateInvalid
	ErrorCodeContractorRateInvalid = 17

	// ErrorCodeProposalTokenInvalid
	ErrorCodeProposalTokenInvalid = 18

	// ErrorCodeLineItemDomainInvalid
	ErrorCodeLineItemDomainInvalid = 19

	// ErrorCodeLineItemSubdomainInvalid
	ErrorCodeLineItemSubdomainInvalid = 20

	// ErrorCodeLineItemDescriptionInvalid
	ErrorCodeLineItemDescriptionInvalid = 21

	// ErrorCodeMinRequiredLineItems
	ErrorCodeMinRequiredLineItems = 22

	// ErrorCodeExchangeRateInvalid
	ErrorCodeExchangeRateInvalid = 23

	// ErrorCodeLineItemTypeInvalid
	ErrorCodeLineItemTypeInvalid = 24

	// ErrorCodeLaborExpenseInvalid
	ErrorCodeLaborExpenseInvalid = 25

	// ErrorCodeLast unit test only.
	ErrorCodeLast ErrorCodeT = 26
)

var (
	// ErrorCodes contains the human readable errors.
	ErrorCodes = map[ErrorCodeT]string{
		ErrorCodeInvalid:                  "error code invalid",
		ErrorCodeTextFileNameInvalid:      "text file name invalid",
		ErrorCodeTextFileSizeInvalid:      "text file size invalid",
		ErrorCodeTextFileMissing:          "text file is misisng",
		ErrorCodeImageFileCountInvalid:    "image file count invalid",
		ErrorCodeImageFileSizeInvalid:     "image file size invalid",
		ErrorCodeInvoiceNameInvalid:       "invoice name invalid",
		ErrorCodeLocationInvalid:          "malformed location",
		ErrorCodeMonthYearInvalid:         "an invalid month/year was submitted on an invoice",
		ErrorCodeMonthYearMissing:         "month or year was set, while the other was not",
		ErrorCodeLineItemInvalid:          "malformed line item submitted",
		ErrorCodeContractorNameMissing:    "invoice missing contractor name",
		ErrorCodeContractorContactMissing: "invoice missing contractor contact",

		ErrorCodeContractorContactInvalid:   "invoice has malformed contractor contact",
		ErrorCodeContractorRateMissing:      "invoice missing contractor rate",
		ErrorCodeContractorRateInvalid:      "invoice has invalid contractor rate",
		ErrorCodeProposalTokenInvalid:       "line item has malformed proposal token",
		ErrorCodeLineItemDomainInvalid:      "line item has malformed domain",
		ErrorCodeLineItemSubdomainInvalid:   "line item has malformed subdomain",
		ErrorCodeLineItemDescriptionInvalid: "line item has malformed description",
		ErrorCodeMinRequiredLineItems:       "invoices require at least 1 line item",
		ErrorCodeExchangeRateInvalid:        "exchange rate was invalid or didn't match expected result",
		ErrorCodeLineItemTypeInvalid:        "line item has an invalid type",
		ErrorCodeLaborExpenseInvalid:        "line item has an invalid labor or expense field",
		/*
			ErrorStatusInvalidInvoiceStatusTransition: "invalid invoice status transition",
			ErrorStatusReasonNotProvided:              "reason for action not provided",
			ErrorStatusInvoiceDuplicate:               "submitted invoice is a duplicate of an existing invoice",
			ErrorStatusWrongInvoiceStatus: "invoice is an wrong status to be editted (approved, rejected or paid)",
		*/
	}
)

const (
	// FileNameIndexFile is the file name of the invoice markdown
	// file. Every invoice is required to have an index file. The
	// index file should contain the invoice content.
	FileNameIndexFile = "index.md"

	// FileNameInvoiceMetadata is the filename of the InvoiceMetadata
	// file that is saved to politeiad. InvoiceMetadata is saved to
	// politeiad as a file, not as a metadata stream, since it contains
	// user provided metadata and needs to be included in the merkle
	// root that politeiad signs.
	FileNameInvoiceMetadata = "invoicemetadata.json"
)

// InvoiceMetadata contains metadata that is provided by the user as part of
// the invoice submission bundle. The invoice metadata is included in the
// invoice signature since it is user specified data. The InvoiceMetadata
// object is saved to politeiad as a file, not as a metadata stream, since it
// needs to be included in the merkle root that politeiad signs.
type InvoiceMetadata struct {
	Name string `json:"name"`
}
