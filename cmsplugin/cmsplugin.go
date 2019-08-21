package cmsplugin

import "encoding/json"

// Plugin settings, kinda doesn;t go here but for now it is fine
const (
	Version               = "1"
	ID                    = "cms"
	CmdAuthorizeVote      = "dccauthorizevote"
	CmdStartVote          = "dccstartvote"
	CmdVoteDetails        = "dccvotedetails"
	CmdVoteSummary        = "dccvotesummary"
	CmdLoadVoteResults    = "loaddccvoteresults"
	CmdBallot             = "dccballot"
	CmdVotes              = "dccvotes"
	CmdInventory          = "dccinventory"
	MDStreamAuthorizeVote = 1013 // Vote authorization by dcc author
	MDStreamVoteBits      = 1014 // Vote bits and mask
	MDStreamVoteSnapshot  = 1015 // Vote tickets and start/end parameters

	VoteDurationMin = 2016 // Minimum vote duration (in blocks)
	VoteDurationMax = 4032 // Maximum vote duration (in blocks)

	// Authorize vote actions
	AuthVoteActionAuthorize = "authorize" // Authorize a proposal vote
	AuthVoteActionRevoke    = "revoke"    // Revoke a proposal vote authorization
)

// CastVote is a signed vote.
type CastVote struct {
	Token     string `json:"token"`     // Proposal ID
	Ticket    string `json:"ticket"`    // Ticket ID
	VoteBit   string `json:"votebit"`   // Vote bit that was selected, this is encode in hex
	Signature string `json:"signature"` // Signature of Token+Ticket+VoteBit
}

// Ballot is a batch of votes that are sent to the server.
type Ballot struct {
	Votes []CastVote `json:"votes"`
}

// EncodeCastVotes encodes CastVotes into a JSON byte slice.
func EncodeBallot(b Ballot) ([]byte, error) {
	return json.Marshal(b)
}

// DecodeCastVotes decodes a JSON byte slice into a CastVotes.
func DecodeBallot(payload []byte) (*Ballot, error) {
	var b Ballot

	err := json.Unmarshal(payload, &b)
	if err != nil {
		return nil, err
	}

	return &b, nil
}

// CastVoteReply contains the signature or error to a cast vote command.
type CastVoteReply struct {
	ClientSignature string `json:"clientsignature"` // Signature that was sent in
	Signature       string `json:"signature"`       // Signature of the ClientSignature
	Error           string `json:"error"`           // Error if something wen't wrong during casting a vote
}

// EncodeCastVoteReply encodes CastVoteReply into a JSON byte slice.
func EncodeCastVoteReply(cvr CastVoteReply) ([]byte, error) {
	return json.Marshal(cvr)
}

// DecodeBallotReply decodes a JSON byte slice into a CastVotes.
func DecodeCastVoteReply(payload []byte) (*CastVoteReply, error) {
	var cvr CastVoteReply

	err := json.Unmarshal(payload, &cvr)
	if err != nil {
		return nil, err
	}

	return &cvr, nil
}

// BallotReply is a reply to a batched list of votes.
type BallotReply struct {
	Receipts []CastVoteReply `json:"receipts"`
}

// EncodeCastVoteReplies encodes CastVotes into a JSON byte slice.
func EncodeBallotReply(br BallotReply) ([]byte, error) {
	return json.Marshal(br)
}

// DecodeBallotReply decodes a JSON byte slice into a CastVotes.
func DecodeBallotReply(payload []byte) (*BallotReply, error) {
	var br BallotReply

	err := json.Unmarshal(payload, &br)
	if err != nil {
		return nil, err
	}

	return &br, nil
}

// VoteOption describes a single vote option.
type VoteOption struct {
	Id          string `json:"id"`          // Single unique word identifying vote (e.g. yes)
	Description string `json:"description"` // Longer description of the vote.
	Bits        uint64 `json:"bits"`        // Bits used for this option
}

// Vote represents the vote options for vote that is identified by its token.
type Vote struct {
	Token            string       `json:"token"`            // Token that identifies vote
	Mask             uint64       `json:"mask"`             // Valid votebits
	Duration         uint32       `json:"duration"`         // Duration in blocks
	QuorumPercentage uint32       `json:"quorumpercentage"` // Percent of eligible votes required for quorum
	PassPercentage   uint32       `json:"passpercentage"`   // Percent of total votes required to pass
	Options          []VoteOption `json:"options"`          // Vote option
}

// EncodeVote encodes Vote into a JSON byte slice.
func EncodeVote(v Vote) ([]byte, error) {
	return json.Marshal(v)
}

// DecodeVote decodes a JSON byte slice into a Vote.
func DecodeVote(payload []byte) (*Vote, error) {
	var v Vote

	err := json.Unmarshal(payload, &v)
	if err != nil {
		return nil, err
	}

	return &v, nil
}

// AuthorizeVote is an MDStream that is used to indicate that a proposal has
// been finalized and is ready to be voted on.  The signature and public
// key are from the proposal author.  The author can revoke a previously sent
// vote authorization by setting the Action field to revoke.
const VersionAuthorizeVote = 1

type AuthorizeVote struct {
	// Generated by decredplugin
	Version   uint   `json:"version"`   // Version of this structure
	Receipt   string `json:"receipt"`   // Server signature of client signature
	Timestamp int64  `json:"timestamp"` // Received UNIX timestamp

	// Generated by client
	Action    string `json:"action"`    // Authorize or revoke
	Token     string `json:"token"`     // Proposal censorship token
	Signature string `json:"signature"` // Signature of token+version+action
	PublicKey string `json:"publickey"` // Pubkey used for signature
}

// EncodeAuthorizeVote encodes AuthorizeVote into a JSON byte slice.
func EncodeAuthorizeVote(av AuthorizeVote) ([]byte, error) {
	return json.Marshal(av)
}

// DecodeAuthorizeVote decodes a JSON byte slice into an AuthorizeVote.
func DecodeAuthorizeVote(payload []byte) (*AuthorizeVote, error) {
	var av AuthorizeVote
	err := json.Unmarshal(payload, &av)
	if err != nil {
		return nil, err
	}
	return &av, nil
}

// AuthorizeVoteReply returns the authorize vote action that was executed and
// the receipt for the action.  The receipt is the server side signature of
// AuthorizeVote.Signature.
type AuthorizeVoteReply struct {
	Action        string `json:"action"`        // Authorize or revoke
	RecordVersion string `json:"recordversion"` // Version of record files
	Receipt       string `json:"receipt"`       // Server signature of client signature
	Timestamp     int64  `json:"timestamp"`     // Received UNIX timestamp
}

// EncodeAuthorizeVote encodes AuthorizeVoteReply into a JSON byte slice.
func EncodeAuthorizeVoteReply(avr AuthorizeVoteReply) ([]byte, error) {
	return json.Marshal(avr)
}

// DecodeAuthorizeVoteReply decodes a JSON byte slice into a AuthorizeVoteReply.
func DecodeAuthorizeVoteReply(payload []byte) (*AuthorizeVoteReply, error) {
	var avr AuthorizeVoteReply
	err := json.Unmarshal(payload, &avr)
	if err != nil {
		return nil, err
	}
	return &avr, nil
}

// StartVote instructs the plugin to commence voting on a proposal with the
// provided vote bits.
const VersionStartVote = 1

type StartVote struct {
	// decred plugin only data
	Version uint `json:"version"` // Version of this structure

	PublicKey string `json:"publickey"` // Key used for signature.
	Vote      Vote   `json:"vote"`      // Vote + options
	Signature string `json:"signature"` // Signature of Votehash
}

// EncodeStartVoteencodes StartVoteinto a JSON byte slice.
func EncodeStartVote(v StartVote) ([]byte, error) {
	return json.Marshal(v)
}

// DecodeVotedecodes a JSON byte slice into a StartVote.
func DecodeStartVote(payload []byte) (*StartVote, error) {
	var sv StartVote

	err := json.Unmarshal(payload, &sv)
	if err != nil {
		return nil, err
	}

	return &sv, nil
}

// StartVoteReply is the reply to StartVote.
const VersionStartVoteReply = 1

type StartVoteReply struct {
	// cms plugin only data
	Version uint `json:"version"` // Version of this structure

	// Shared data
	StartBlockHeight    string           `json:"startblockheight"`   // Block height
	StartBlockHash      string           `json:"startblockhash"`     // Block hash
	EndHeight           string           `json:"endheight"`          // Height of vote end
	EligibleUserWeights map[string]int64 `json:"eligbleuserweights"` // Valid user weights
}

// EncodeStartVoteReply encodes StartVoteReply into a JSON byte slice.
func EncodeStartVoteReply(v StartVoteReply) ([]byte, error) {
	return json.Marshal(v)
}

// DecodeVoteReply decodes a JSON byte slice into a StartVoteReply.
func DecodeStartVoteReply(payload []byte) (*StartVoteReply, error) {
	var v StartVoteReply

	err := json.Unmarshal(payload, &v)
	if err != nil {
		return nil, err
	}

	return &v, nil
}

// VoteDetails is used to retrieve the voting period details for a record.
type VoteDetails struct {
	Token string `json:"token"` // Censorship token
}

// EncodeVoteDetails encodes VoteDetails into a JSON byte slice.
func EncodeVoteDetails(vd VoteDetails) ([]byte, error) {
	return json.Marshal(vd)
}

// DecodeVoteDetails decodes a JSON byte slice into a VoteDetails.
func DecodeVoteDetails(payload []byte) (*VoteDetails, error) {
	var vd VoteDetails

	err := json.Unmarshal(payload, &vd)
	if err != nil {
		return nil, err
	}

	return &vd, nil
}

// VoteDetailsReply is the reply to VoteDetails.
type VoteDetailsReply struct {
	AuthorizeVote  AuthorizeVote  `json:"authorizevote"`  // Vote authorization
	StartVote      StartVote      `json:"startvote"`      // Vote ballot
	StartVoteReply StartVoteReply `json:"startvotereply"` // Start vote snapshot
}

// EncodeVoteDetailsReply encodes VoteDetailsReply into a JSON byte slice.
func EncodeVoteDetailsReply(vdr VoteDetailsReply) ([]byte, error) {
	return json.Marshal(vdr)
}

// DecodeVoteReply decodes a JSON byte slice into a VoteDetailsReply.
func DecodeVoteDetailsReply(payload []byte) (*VoteDetailsReply, error) {
	var vdr VoteDetailsReply

	err := json.Unmarshal(payload, &vdr)
	if err != nil {
		return nil, err
	}

	return &vdr, nil
}

type VoteResults struct {
	Token string `json:"token"` // Censorship token
}

type VoteResultsReply struct {
	StartVote StartVote  `json:"startvote"` // Original ballot
	CastVotes []CastVote `json:"castvotes"` // All votes
}

// EncodeVoteResults encodes VoteResults into a JSON byte slice.
func EncodeVoteResults(v VoteResults) ([]byte, error) {
	return json.Marshal(v)
}

// DecodeVoteResults decodes a JSON byte slice into a VoteResults.
func DecodeVoteResults(payload []byte) (*VoteResults, error) {
	var v VoteResults

	err := json.Unmarshal(payload, &v)
	if err != nil {
		return nil, err
	}

	return &v, nil
}

// EncodeVoteResultsReply encodes VoteResults into a JSON byte slice.
func EncodeVoteResultsReply(v VoteResultsReply) ([]byte, error) {
	return json.Marshal(v)
}

// DecodeVoteResultsReply decodes a JSON byte slice into a VoteResults.
func DecodeVoteResultsReply(payload []byte) (*VoteResultsReply, error) {
	var v VoteResultsReply

	err := json.Unmarshal(payload, &v)
	if err != nil {
		return nil, err
	}

	return &v, nil
}

// VoteSummary requests a summary of a proposal vote. This includes certain
// voting period parameters and a summary of the vote results.
type VoteSummary struct {
	Token string `json:"token"` // Censorship token
}

// EncodeVoteSummary encodes VoteSummary into a JSON byte slice.
func EncodeVoteSummary(v VoteSummary) ([]byte, error) {
	return json.Marshal(v)
}

// DecodeVoteSummary decodes a JSON byte slice into a VoteSummary.
func DecodeVoteSummary(payload []byte) (*VoteSummary, error) {
	var v VoteSummary

	err := json.Unmarshal(payload, &v)
	if err != nil {
		return nil, err
	}

	return &v, nil
}

// VoteOptionResult describes a vote option and the total number of votes that
// have been cast for this option.
type VoteOptionResult struct {
	ID          string `json:"id"`          // Single unique word identifying vote (e.g. yes)
	Description string `json:"description"` // Longer description of the vote.
	Bits        uint64 `json:"bits"`        // Bits used for this option
	Votes       uint64 `json:"votes"`       // Number of votes cast for this option
}

// VoteSummaryReply is the reply to the VoteSummary command and returns certain
// voting period parameters as well as a summary of the vote results.
type VoteSummaryReply struct {
	Authorized          bool               `json:"authorized"`          // Vote is authorized
	EndHeight           string             `json:"endheight"`           // End block height
	EligibleTicketCount int                `json:"eligibleticketcount"` // Number of eligible tickets
	QuorumPercentage    uint32             `json:"quorumpercentage"`    // Percent of eligible votes required for quorum
	PassPercentage      uint32             `json:"passpercentage"`      // Percent of total votes required to pass
	Results             []VoteOptionResult `json:"results"`             // Vote results
}

// EncodeVoteSummaryReply encodes VoteSummary into a JSON byte slice.
func EncodeVoteSummaryReply(v VoteSummaryReply) ([]byte, error) {
	return json.Marshal(v)
}

// DecodeVoteSummaryReply decodes a JSON byte slice into a VoteSummaryReply.
func DecodeVoteSummaryReply(payload []byte) (*VoteSummaryReply, error) {
	var v VoteSummaryReply

	err := json.Unmarshal(payload, &v)
	if err != nil {
		return nil, err
	}

	return &v, nil
}

// StartVoteTuple is used to return the StartVote and StartVoteReply for a
// record. StartVoteReply does not contain any record identifying data so it
// must be returned with the StartVote in order to know what record it belongs
// to.
type StartVoteTuple struct {
	StartVote      StartVote      `json:"startvote"`      // Start vote
	StartVoteReply StartVoteReply `json:"startvotereply"` // Start vote reply
}

// InventoryReply returns the decred plugin inventory.
type InventoryReply struct {
	AuthorizeVotes       []AuthorizeVote      `json:"authorizevotes"`       // Authorize votes
	AuthorizeVoteReplies []AuthorizeVoteReply `json:"authorizevotereplies"` // Authorize vote replies
	StartVoteTuples      []StartVoteTuple     `json:"startvotetuples"`      // Start vote tuples
	CastVotes            []CastVote           `json:"castvotes"`            // Cast votes
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

// LoadVoteResults creates a vote results entry in the cache for any proposals
// that have finsished voting but have not yet been added to the lazy loaded
// vote results table.
type LoadVoteResults struct {
	BestBlock uint64 `json:"bestblock"` // Best block height
}

// EncodeLoadVoteResults encodes a LoadVoteResults into a JSON byte slice.
func EncodeLoadVoteResults(lvr LoadVoteResults) ([]byte, error) {
	return json.Marshal(lvr)
}

// DecodeLoadVoteResults decodes a JSON byte slice into a LoadVoteResults.
func DecodeLoadVoteResults(payload []byte) (*LoadVoteResults, error) {
	var lvr LoadVoteResults

	err := json.Unmarshal(payload, &lvr)
	if err != nil {
		return nil, err
	}

	return &lvr, nil
}

// LoadVoteResultsReply is the reply to the LoadVoteResults command.
type LoadVoteResultsReply struct{}

// EncodeLoadVoteResultsReply encodes a LoadVoteResultsReply into a JSON
// byte slice.
func EncodeLoadVoteResultsReply(reply LoadVoteResultsReply) ([]byte, error) {
	return json.Marshal(reply)
}

// DecodeLoadVoteResultsReply decodes a JSON byte slice into a LoadVoteResults.
func DecodeLoadVoteResultsReply(payload []byte) (*LoadVoteResultsReply, error) {
	var reply LoadVoteResultsReply

	err := json.Unmarshal(payload, &reply)
	if err != nil {
		return nil, err
	}

	return &reply, nil
}
