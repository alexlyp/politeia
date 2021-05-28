// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package client

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	cmsv2 "github.com/decred/politeia/politeiawww/api/cms/v2"
	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
)

// PiPolicy sends a pi v1 Policy request to politeiawww.
func (c *Client) CmsPolicy() (*cmsv2.PolicyReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		cmsv2.APIRoute, cmsv2.RoutePolicy, nil)
	if err != nil {
		return nil, err
	}

	var pr cmsv2.PolicyReply
	err = json.Unmarshal(resBody, &pr)
	if err != nil {
		return nil, err
	}

	return &pr, nil
}

// InvoiceMetadataDecode decodes and returns the InvoiceMetadata from the
// Provided record files. An error returned if a InvoiceMetadata is not found.
func InvoiceMetadataDecode(files []rcv1.File) (*cmsv2.InvoiceMetadata, error) {
	var pmp *cmsv2.InvoiceMetadata
	for _, v := range files {
		if v.Name != cmsv2.FileNameInvoiceMetadata {
			continue
		}
		b, err := base64.StdEncoding.DecodeString(v.Payload)
		if err != nil {
			return nil, err
		}
		var pm cmsv2.InvoiceMetadata
		err = json.Unmarshal(b, &pm)
		if err != nil {
			return nil, err
		}
		pmp = &pm
		break
	}
	if pmp == nil {
		return nil, fmt.Errorf("invoice metadata not found")
	}
	return pmp, nil
}
