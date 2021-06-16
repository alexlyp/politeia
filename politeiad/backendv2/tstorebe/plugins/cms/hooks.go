// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cms

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/plugins/cms"
	"github.com/decred/politeia/politeiad/plugins/comments"
	"github.com/decred/politeia/util"
)

const (
	// Accepted MIME types
	mimeTypeText     = "text/plain"
	mimeTypeTextUTF8 = "text/plain; charset=utf-8"
	mimeTypePNG      = "image/png"
)

var (
	// allowedTextFiles contains the filenames of the only text files
	// that are allowed to be submitted as part of a invoice.
	allowedTextFiles = map[string]struct{}{
		cms.FileNameIndexFile:       {},
		cms.FileNameInvoiceMetadata: {},
	}
)

// hookNewRecordPre adds plugin specific validation onto the tstore backend
// RecordNew method.
func (c *cmsPlugin) hookNewRecordPre(payload string) error {
	var nr plugins.HookNewRecordPre
	err := json.Unmarshal([]byte(payload), &nr)
	if err != nil {
		return err
	}

	return c.invoiceFilesVerify(nr.Files)
}

// hookEditRecordPre adds plugin specific validation onto the tstore backend
// RecordEdit method.
func (c *cmsPlugin) hookEditRecordPre(payload string) error {
	var er plugins.HookEditRecord
	err := json.Unmarshal([]byte(payload), &er)
	if err != nil {
		return err
	}

	// Verify invoice files
	err = c.invoiceFilesVerify(er.Files)
	if err != nil {
		return err
	}

	// Verify invoice status. Edits are not allowed to be made once a invoice
	// has been authorized. This only needs to be checked for vetted
	// records since you cannot authorize or start a ticket invoice on an
	// unvetted record.
	if er.RecordMetadata.State == backend.StateVetted {
		_, err := tokenDecode(er.RecordMetadata.Token)
		if err != nil {
			return err
		}
	}

	return nil
}

// hookCommentNew adds cms specific validation onto the comments plugin New
// command.
func (c *cmsPlugin) hookCommentNew(token []byte) error {
	return c.commentWritesAllowed(token)
}

// hookCommentDel adds cms specific validation onto the comments plugin Del
// command.
func (c *cmsPlugin) hookCommentDel(token []byte) error {
	return c.commentWritesAllowed(token)
}

// hookPluginPre extends plugin write commands from other plugins with cms
// specific validation.
func (c *cmsPlugin) hookPluginPre(payload string) error {
	// Decode payload
	var hpp plugins.HookPluginPre
	err := json.Unmarshal([]byte(payload), &hpp)
	if err != nil {
		return err
	}

	// Call plugin hook
	switch hpp.PluginID {
	case comments.PluginID:
		switch hpp.Cmd {
		case comments.CmdNew:
			return c.hookCommentNew(hpp.Token)
		case comments.CmdDel:
			return c.hookCommentDel(hpp.Token)
		}
	}

	return nil
}

// invoiceNameIsValid returns whether the provided name is a valid invoice
// name.
func (c *cmsPlugin) invoiceNameIsValid(name string) bool {
	return c.invoiceNameRegexp.MatchString(name)
}

// invoiceFilesVerify verifies the files adhere to all cms plugin setting
// requirements. If this hook is being executed then the files have already
// passed politeiad validation so we can assume that the file has a unique
// name, a valid base64 payload, and that the file digest and MIME type are
// correct.
func (c *cmsPlugin) invoiceFilesVerify(files []backend.File) error {
	var imagesCount uint32
	for _, v := range files {
		payload, err := base64.StdEncoding.DecodeString(v.Payload)
		if err != nil {
			return fmt.Errorf("invalid base64 %v", v.Name)
		}

		// MIME type specific validation
		switch v.MIME {
		case mimeTypeText, mimeTypeTextUTF8:
			// Verify text file is allowed
			_, ok := allowedTextFiles[v.Name]
			if !ok {
				return backend.PluginError{
					PluginID:     cms.PluginID,
					ErrorCode:    uint32(cms.ErrorCodeTextFileNameInvalid),
					ErrorContext: v.Name,
				}
			}

			// Verify text file size
			if len(payload) > int(c.textFileSizeMax) {
				return backend.PluginError{
					PluginID:  cms.PluginID,
					ErrorCode: uint32(cms.ErrorCodeTextFileSizeInvalid),
					ErrorContext: fmt.Sprintf("file %v "+
						"size %v exceeds max size %v",
						v.Name, len(payload),
						c.textFileSizeMax),
				}
			}

		case mimeTypePNG:
			imagesCount++

			// Verify image file size
			if len(payload) > int(c.imageFileSizeMax) {
				return backend.PluginError{
					PluginID:  cms.PluginID,
					ErrorCode: uint32(cms.ErrorCodeImageFileSizeInvalid),
					ErrorContext: fmt.Sprintf("image %v "+
						"size %v exceeds max size %v",
						v.Name, len(payload),
						c.imageFileSizeMax),
				}
			}

		default:
			return fmt.Errorf("invalid mime: %v", v.MIME)
		}
	}

	// Verify that an index file is present
	var found bool
	for _, v := range files {
		if v.Name == cms.FileNameIndexFile {
			found = true
			break
		}
	}
	if !found {
		return backend.PluginError{
			PluginID:     cms.PluginID,
			ErrorCode:    uint32(cms.ErrorCodeTextFileMissing),
			ErrorContext: cms.FileNameIndexFile,
		}
	}

	// Verify image file count is acceptable
	if imagesCount > c.imageFileCountMax {
		return backend.PluginError{
			PluginID:  cms.PluginID,
			ErrorCode: uint32(cms.ErrorCodeImageFileCountInvalid),
			ErrorContext: fmt.Sprintf("got %v image files, max "+
				"is %v", imagesCount, c.imageFileCountMax),
		}
	}

	// Verify a invoice metadata has been included
	pm, err := invoiceMetadataDecode(files)
	if err != nil {
		return err
	}
	if pm == nil {
		return backend.PluginError{
			PluginID:     cms.PluginID,
			ErrorCode:    uint32(cms.ErrorCodeTextFileMissing),
			ErrorContext: cms.FileNameInvoiceMetadata,
		}
	}

	// Verify invoice name
	if !c.invoiceNameIsValid(pm.Name) {
		return backend.PluginError{
			PluginID:     cms.PluginID,
			ErrorCode:    uint32(cms.ErrorCodeInvoiceNameInvalid),
			ErrorContext: c.invoiceNameRegexp.String(),
		}
	}

	return nil
}

// commentWritesAllowed verifies that a invoice has a vote status that allows
// comment writes to be made to the invoice. This includes both comments and
// comment votes. Comment writes are allowed up until the invoice has finished
// voting.
func (c *cmsPlugin) commentWritesAllowed(token []byte) error {
	// Get Invoice status and see if it's updated/new/disputed to see
	// if comment writes are allowed.
	/*
		// Invoice status does not allow writes
		return backend.PluginError{
			PluginID:     cms.PluginID,
			ErrorCode:    uint32(cms.ErrorCodeInvoiceStatusInvalid),
			ErrorContext: "invoice has ended; invoice is locked",
		}
	}*/
	return nil
}

// tokenDecode returns the decoded censorship token. An error will be returned
// if the token is not a full length token.
func tokenDecode(token string) ([]byte, error) {
	return util.TokenDecode(util.TokenTypeTstore, token)
}

// invoiceMetadataDecode decodes and returns the InvoiceMetadata from the
// provided backend files. If a InvoiceMetadata is not found, nil is returned.
func invoiceMetadataDecode(files []backend.File) (*cms.InvoiceMetadata, error) {
	var propMD *cms.InvoiceMetadata
	for _, v := range files {
		if v.Name != cms.FileNameInvoiceMetadata {
			continue
		}
		b, err := base64.StdEncoding.DecodeString(v.Payload)
		if err != nil {
			return nil, err
		}
		var m cms.InvoiceMetadata
		err = json.Unmarshal(b, &m)
		if err != nil {
			return nil, err
		}
		propMD = &m
		break
	}
	return propMD, nil
}
