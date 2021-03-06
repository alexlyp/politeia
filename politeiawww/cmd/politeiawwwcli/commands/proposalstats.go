// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

const ProposalStatsHelpMsg = `proposalstats

Get proposal inventory statistics.

Arguments:
None

Result:
{
  "numofcensored": 1,
  "numofunvetted": 0,
  "numofunvettedchanges": 2,
  "numofpublic": 1,
  "numofabandoned": 1
}`

type ProposalStatsCmd struct{}

func (cmd *ProposalStatsCmd) Execute(args []string) error {
	psr, err := c.ProposalsStats()
	if err != nil {
		return err
	}
	return Print(psr, cfg.Verbose, cfg.RawJSON)
}
