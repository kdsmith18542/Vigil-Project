// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (c) 2015-2024 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/decred/dcrd/blockchain/stake/v5"
	"github.com/decred/dcrd/blockchain/v5/chaingen"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/crypto/rand"
	"github.com/decred/dcrd/database/v3"
	_ "github.com/decred/dcrd/database/v3/ffldb"
	"github.com/decred/dcrd/dcrutil/v4"
	"github.com/decred/dcrd/txscript/v4"
	"github.com/decred/dcrd/txscript/v4/sign"
	"github.com/decred/dcrd/wire"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/filter"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

const (
	// testDbType is the database backend type to use for the tests.
	testDbType = "ffldb"

	// blockDataNet is the expected network in the test block data.
	blockDataNet = wire.MainNet
)

// isSupportedDbType returns whether or not the passed database type is
// currently supported.
func isSupportedDbType(dbType string) bool {
	supportedDrivers := database.SupportedDrivers()
	for _, driver := range supportedDrivers {
		if dbType == driver {
			return true
		}
	}

	return false
}

// createTestDatabase creates a test database with the provided database type
// for the given network.
func createTestDatabase(t testing.TB, dbType string, net wire.CurrencyNet) (database.DB, error) {
	// Handle memory database specially since it doesn't need the disk specific
	// handling.
	var db database.DB
	if dbType == "memdb" {
		ndb, err := database.Create(dbType)
		if err != nil {
			return nil, fmt.Errorf("error creating db: %w", err)
		}
		db = ndb
	} else {
		// Create the directory for the test database.
		dbPath := t.TempDir()

		// Create the test database.
		ndb, err := database.Create(dbType, dbPath, net)
		if err != nil {
			return nil, fmt.Errorf("error creating db: %w", err)
		}
		db = ndb
	}
	t.Cleanup(func() {
		db.Close()
	})

	return db, nil
}

// createTestUtxoDatabase creates a test UTXO database with the provided
// database name. It also returns a teardown function the caller should invoke
// when done testing to clean up.
func createTestUtxoDatabase(t testing.TB) (*leveldb.DB, func(), error) {
	// Construct the database filepath
	dbPath := t.TempDir()

	// Open the database (will create it if needed).
	opts := opt.Options{
		Strict:      opt.DefaultStrict,
		Compression: opt.NoCompression,
		Filter:      filter.NewBloomFilter(10),
	}
	db, err := leveldb.OpenFile(dbPath, &opts)
	if err != nil {
		return nil, nil, err
	}

	// Setup a teardown function for cleaning up.  This function is returned to
	// the caller to be invoked when it is done testing.
	teardown := func() {
		_ = db.Close()
		_ = os.RemoveAll(dbPath)
	}

	return db, teardown, nil
}

// chainSetup is used to create a new db and chain instance with the genesis
// block already inserted.
func chainSetup(t testing.TB, params *chaincfg.Params) (*BlockChain, error) {
	if !isSupportedDbType(testDbType) {
		return nil, fmt.Errorf("unsupported db type %v", testDbType)
	}

	// Create a test block database.
	db, err := createTestDatabase(t, testDbType, blockDataNet)
	if err != nil {
		return nil, err
	}

	// Create a test UTXO database.
	utxoDb, teardownUtxoDb, err := createTestUtxoDatabase(t)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() {
		teardownUtxoDb()
	})

	// Copy the chain params to ensure any modifications the tests do to
	// the chain parameters do not affect the global instance.
	paramsCopy := *params

	// Create a SigCache instance.
	sigCache, err := txscript.NewSigCache(1000)
	if err != nil {
		return nil, err
	}

	// Create the main chain instance.
	utxoBackend := NewLevelDbUtxoBackend(utxoDb)
	chain, err := New(context.Background(),
		&Config{
			DB:          db,
			UtxoBackend: utxoBackend,
			ChainParams: &paramsCopy,
			TimeSource:  NewMedianTime(),
			SigCache:    sigCache,
			UtxoCache: NewUtxoCache(&UtxoCacheConfig{
				Backend: utxoBackend,
				FlushBlockDB: func() error {
					// Don't flush to disk since it is slow and this is used in a lot of
					// tests.
					return nil
				},
				MaxSize: 100 * 1024 * 1024, // 100 MiB
			}),
		})

	if err != nil {
		err := fmt.Errorf("failed to create chain instance: %w", err)
		return nil, err
	}

	return chain, nil
}

// newFakeChain returns a chain that is usable for synthetic tests.  It is
// important to note that this chain has no database associated with it, so
// it is not usable with all functions and the tests must take care when making
// use of it.
func newFakeChain(params *chaincfg.Params) *BlockChain {
	// Create a genesis block node and block index populated with it for use
	// when creating the fake chain below.
	node := newBlockNode(&params.GenesisBlock.Header, nil)
	node.status = statusDataStored | statusValidated
	node.isFullyLinked = true
	index := newBlockIndex(nil)
	index.bestHeader = node
	index.AddNode(node)

	// Generate a deployment ID map from the provided params.
	deploymentData, err := extractDeployments(params)
	if err != nil {
		panic(err)
	}

	return &BlockChain{
		deploymentData:                deploymentData,
		chainParams:                   params,
		index:                         index,
		bestChain:                     newChainView(node),
		recentBlocks:                  newRecentBlocksCache(),
		isVoterMajorityVersionCache:   make(map[[stakeMajorityCacheKeySize]byte]bool),
		isStakeMajorityVersionCache:   make(map[[stakeMajorityCacheKeySize]byte]bool),
		calcPriorStakeVersionCache:    make(map[[chainhash.HashSize]byte]uint32),
		calcVoterVersionIntervalCache: make(map[[chainhash.HashSize]byte]uint32),
		calcStakeVersionCache:         make(map[[chainhash.HashSize]byte]uint32),
	}
}

// newFakeNode creates a block node connected to the passed parent with the
// provided fields populated and fake values for the other fields.
func newFakeNode(parent *blockNode, blockVersion int32, stakeVersion uint32, bits uint32, timestamp time.Time) *blockNode {
	// Make up a header and create a block node from it.
	var prevHash chainhash.Hash
	var height uint32
	if parent != nil {
		prevHash = parent.hash
		height = uint32(parent.height + 1)
	}
	header := &wire.BlockHeader{
		Version:      blockVersion,
		PrevBlock:    prevHash,
		VoteBits:     0x01,
		Bits:         bits,
		Height:       height,
		Timestamp:    timestamp,
		Nonce:        rand.Uint32(),
		StakeVersion: stakeVersion,
	}
	node := newBlockNode(header, parent)
	node.status = statusDataStored | statusValidated
	node.isFullyLinked = parent == nil || parent.isFullyLinked
	return node
}

type treasuryVoteTuple struct {
	tspendHash chainhash.Hash
	vote       byte
}

// newFakeCreateVoteTx creates a fake vote transaction and appends treasury
// votes if provided.
func newFakeCreateVoteTx(tspendVotes []treasuryVoteTuple) *wire.MsgTx {
	var (
		voteSubsidy        = 5000000000
		ticketPrice        = 100000000
		opTrueRedeemScript = []byte{txscript.OP_DATA_1, txscript.OP_TRUE}
		stakeGenScript     = [26]byte{txscript.OP_SSGEN}
		blockScript        = [38]byte{txscript.OP_RETURN, txscript.OP_DATA_36}
		voteScript         = [4]byte{txscript.OP_RETURN, txscript.OP_DATA_2}
	)
	// Fake out stakeGenScript.
	tagOffset := 1 // Prefixed with OP_SSGEN
	stakeGenScript[tagOffset+0] = txscript.OP_DUP
	stakeGenScript[tagOffset+1] = txscript.OP_HASH160
	stakeGenScript[tagOffset+2] = txscript.OP_DATA_20
	stakeGenScript[tagOffset+23] = txscript.OP_EQUALVERIFY
	stakeGenScript[tagOffset+24] = txscript.OP_CHECKSIG

	// Generate and return the transaction with the proof-of-stake subsidy
	// coinbase and spending from the provided ticket along with the
	// previously described outputs.
	ticketHash := &chainhash.Hash{}
	tx := wire.NewMsgTx()
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: *wire.NewOutPoint(&chainhash.Hash{},
			wire.MaxPrevOutIndex, wire.TxTreeRegular),
		Sequence:    wire.MaxTxInSequenceNum,
		ValueIn:     int64(voteSubsidy),
		BlockHeight: wire.NullBlockHeight,
		BlockIndex:  wire.NullBlockIndex,
	})
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: *wire.NewOutPoint(ticketHash, 0,
			wire.TxTreeStake),
		Sequence:        wire.MaxTxInSequenceNum,
		ValueIn:         int64(ticketPrice),
		SignatureScript: opTrueRedeemScript,
	})
	tx.AddTxOut(wire.NewTxOut(0, blockScript[:]))
	tx.AddTxOut(wire.NewTxOut(0, voteScript[:]))
	tx.AddTxOut(wire.NewTxOut(int64(voteSubsidy+ticketPrice),
		stakeGenScript[:]))

	// Append tspend votes if set.
	if tspendVotes != nil {
		tx.Version = wire.TxVersionTreasury
		tspendScript := make([]byte, 0, 256)
		tspendScript = append(tspendScript, txscript.OP_RETURN,
			byte(len(tspendVotes)*33+2), 'T', 'V')
		for _, v := range tspendVotes {
			tspendScript = append(tspendScript, v.tspendHash[:]...)
			tspendScript = append(tspendScript, v.vote)
		}
		tx.AddTxOut(wire.NewTxOut(0, tspendScript))
	}
	return tx
}

// newFakeCreateTSpend creates a fake tspend transaction.
func newFakeCreateTSpend(privKey []byte, payouts []dcrutil.Amount, fee dcrutil.Amount, expiry uint32) *wire.MsgTx {
	// Calculate total payout.
	totalPayout := int64(0)
	for _, amount := range payouts {
		totalPayout += int64(amount)
	}
	valueIn := int64(fee) + totalPayout

	// OP_RETURN <8 byte LE ValueIn><24 byte random>
	// The TSpend TxIn ValueIn is encoded in the first 8 bytes to ensure
	// that it becomes signed. This is consensus enforced.
	var payload [32]byte
	binary.LittleEndian.PutUint64(payload[0:8], uint64(valueIn))
	rand.Read(payload[8:])
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_RETURN)
	builder.AddData(payload[:])
	opretScript, err := builder.Script()
	if err != nil {
		panic(err)
	}
	msgTx := wire.NewMsgTx()
	msgTx.Version = wire.TxVersionTreasury
	msgTx.Expiry = expiry
	msgTx.AddTxOut(wire.NewTxOut(0, opretScript))

	// OP_TGEN
	for _, amount := range payouts {
		// Generate valid script. This is a hex encoded blob from
		// generator.go.
		p2shOpTrueScript, err := hex.DecodeString("a914f5a8302ee8695bf836258b8f2b57b38a0be14e4787")
		if err != nil {
			panic(err)
		}
		script := make([]byte, len(p2shOpTrueScript)+1)
		script[0] = txscript.OP_TGEN
		copy(script[1:], p2shOpTrueScript)
		msgTx.AddTxOut(wire.NewTxOut(int64(amount), script))
	}

	// Treasury spend transactions have no inputs since the funds are
	// sourced from a special account, so previous outpoint is zero hash
	// and max index.
	msgTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: *wire.NewOutPoint(&chainhash.Hash{},
			wire.MaxPrevOutIndex, wire.TxTreeRegular),
		Sequence:        wire.MaxTxInSequenceNum,
		ValueIn:         valueIn,
		BlockHeight:     wire.NullBlockHeight,
		BlockIndex:      wire.NullBlockIndex,
		SignatureScript: nil,
	})

	// Calculate TSpend signature without SigHashType.
	sigscript, err := sign.TSpendSignatureScript(msgTx, privKey)
	if err != nil {
		panic(err)
	}
	msgTx.TxIn[0].SignatureScript = sigscript

	return msgTx
}

// chainedFakeNodes returns the specified number of nodes constructed such that
// each subsequent node points to the previous one to create a chain.  The first
// node will point to the passed parent which can be nil if desired.
func chainedFakeNodes(parent *blockNode, numNodes int) []*blockNode {
	nodes := make([]*blockNode, numNodes)
	tip := parent
	blockTime := time.Now()
	if tip != nil {
		blockTime = time.Unix(tip.timestamp, 0)
	}
	for i := 0; i < numNodes; i++ {
		blockTime = blockTime.Add(time.Second)
		node := newFakeNode(tip, 1, 1, 0, blockTime)
		tip = node

		nodes[i] = node
	}
	return nodes
}

// chainedFakeSkipListNodes returns the specified number of nodes populated with
// only the fields specifically needed to test the skip list functionality and
// constructed such that each subsequent node points to the previous one to
// create a chain.  The first node will point to the passed parent which can be
// nil if desired.
//
// This is used over the chainedFakeNodes function for skip list testing because
// the skip list tests involve large numbers of nodes which take much longer to
// create with all of the other fields populated by said function.
func chainedFakeSkipListNodes(parent *blockNode, numNodes int) []*blockNode {
	nodes := make([]*blockNode, numNodes)
	for i := 0; i < numNodes; i++ {
		node := &blockNode{parent: parent, height: int64(i)}
		if parent != nil {
			node.skipToAncestor = nodes[calcSkipListHeight(int64(i))]
		}
		parent = node

		nodes[i] = node
	}
	return nodes
}

// branchTip is a convenience function to grab the tip of a chain of block nodes
// created via chainedFakeNodes.
func branchTip(nodes []*blockNode) *blockNode {
	return nodes[len(nodes)-1]
}

// appendFakeVotes appends the passed number of votes to the node with the
// provided version and vote bits.
func appendFakeVotes(node *blockNode, numVotes uint16, voteVersion uint32, voteBits uint16) {
	for i := uint16(0); i < numVotes; i++ {
		node.votes = append(node.votes, stake.VoteVersionTuple{
			Version: voteVersion,
			Bits:    voteBits,
		})
	}
}

// findVoteChoiceIndex finds the provided choice ID within the given vote and
// returns the index of that choice along with a pointer to the choice or fails
// with a fatal test error when not found.
func findVoteChoiceIndex(t *testing.T, vote *chaincfg.Vote, choiceID string) (uint32, *chaincfg.Choice) {
	t.Helper()

	// Find the correct choice for the passed choice ID.
	for choiceIdx := range vote.Choices {
		choice := &vote.Choices[choiceIdx]
		if choice.Id == choiceID {
			return uint32(choiceIdx), choice
		}
	}

	t.Fatalf("unable to find vote choice for id %q", choiceID)
	panic("unreachable")
}

// findVoteChoice finds the provided choice ID within the given vote and returns
// a pointer to the found choice or fails with a fatal test error when not
// found.
func findVoteChoice(t *testing.T, vote *chaincfg.Vote, choiceID string) *chaincfg.Choice {
	t.Helper()

	_, choice := findVoteChoiceIndex(t, vote, choiceID)
	return choice
}

// findDeployment finds the provided vote ID within the deployments of the
// provided parameters and either returns the deployment version it was found in
// along with a pointer to the deployment or fails with a fatal test error when
// not found.
func findDeployment(t *testing.T, params *chaincfg.Params, voteID string) (uint32, *chaincfg.ConsensusDeployment) {
	t.Helper()

	// Find the correct deployment for the passed vote ID.
	for version, deployments := range params.Deployments {
		for i, deployment := range deployments {
			if deployment.Vote.Id == voteID {
				return version, &deployments[i]
			}
		}
	}

	t.Fatalf("unable to find deployment for id %q", voteID)
	panic("unreachable")
}

// findDeploymentChoice finds the provided choice ID within the given deployment
// params and returns a pointer to the found choice or fails with a fatal test
// error when not found.
func findDeploymentChoice(t *testing.T, deployment *chaincfg.ConsensusDeployment, choiceID string) *chaincfg.Choice {
	t.Helper()

	return findVoteChoice(t, &deployment.Vote, choiceID)
}

// findDeploymentAllYesChoices returns the deployment version and the OR'ed sum
// of the 'yes' choices for all the passed agendas.
//
// Note that all agendas must be in the same deployment version or this function
// will fail with a fatal test error.
func findDeploymentAllYesChoices(t *testing.T, params *chaincfg.Params, voteIDs []string) (uint32, uint16) {
	t.Helper()

	var yesBits uint16
	var deploymentVer uint32
	var foundIDs int
	for version, deployments := range params.Deployments {
		for _, deployment := range deployments {
			for _, wantID := range voteIDs {
				if deployment.Vote.Id == wantID {
					yesChoice := findDeploymentChoice(t, &deployment, "yes")
					deploymentVer = version
					foundIDs++
					yesBits |= yesChoice.Bits
				}
			}
		}

		if foundIDs == 0 {
			continue
		}

		// Agendas can only be voted simultaneously if they belong to
		// the same deployment version, so return an error if we found
		// some, but not all vote IDs in a specific version.
		if foundIDs != len(voteIDs) {
			t.Fatal("not all voteIDs were found in the same deployment version")
		}

		return deploymentVer, yesBits
	}

	t.Fatal("unable to find deployment for any of the provided vote IDs")
	panic("unreachable")
}

// reassignVoteMaskAndChoiceBits calculates and updates the masks and choice
// bits for all votes in the provided agendas so that they are non-overlapping.
func reassignVoteMaskAndChoiceBits(agendas []chaincfg.ConsensusDeployment) {
	choiceIdxShift := uint16(1)
	for agendaIdx := range agendas {
		vote := &agendas[agendaIdx].Vote
		maskBitsNeeded := uint16(bits.Len(uint(len(vote.Choices))))
		vote.Mask = ((1 << maskBitsNeeded) - 1) << choiceIdxShift
		for choiceIdx := range vote.Choices {
			vote.Choices[choiceIdx].Bits = uint16(choiceIdx) << choiceIdxShift
		}
		choiceIdxShift += maskBitsNeeded
	}
}

// mergeAgendas moves all the specified agendas into the same deployment,
// suitable for being voted at the same time.
//
// The agendas will be moved to the deployment that contains the first agenda
// in the voteIDs slice.
//
// Returns the resulting deployment version or fails with a fatal test error if
// any errors are encountered.
func mergeAgendas(t *testing.T, params *chaincfg.Params, voteIDs []string) uint32 {
	t.Helper()

	if len(voteIDs) < 2 {
		t.Fatal("at least 2 agenda IDs must be specified")
	}

	// The first agenda defines the destination deployment, where the
	// others will be moved to.
	targetDeployVer, _ := findDeployment(t, params, voteIDs[0])
	voteIDs = voteIDs[1:]
	targetDeploy := params.Deployments[targetDeployVer]

nextvote:
	for _, wantID := range voteIDs {
		for version, deployments := range params.Deployments {
			for i := 0; i < len(deployments); {
				deployment := deployments[i]

				if deployment.Vote.Id != wantID {
					i++
					continue
				}

				// Found where the agenda is. Move to target.
				targetDeploy = append(targetDeploy, deployment)
				params.Deployments[targetDeployVer] = targetDeploy
				deployments[i] = deployments[len(deployments)-1]
				deployments = deployments[:len(deployments)-1]
				params.Deployments[version] = deployments
				continue nextvote
			}
		}

		t.Fatalf("unable to find vote id %s", wantID)
	}
	reassignVoteMaskAndChoiceBits(params.Deployments[targetDeployVer])

	return targetDeployVer
}

// removeDeploymentTimeConstraints modifies the passed deployment to remove the
// voting time constraints by making it always available to vote and to never
// expire.
//
// NOTE: This will mutate the passed deployment, so ensure this function is
// only called with parameters that are not globally available.
func removeDeploymentTimeConstraints(deployment *chaincfg.ConsensusDeployment) {
	deployment.StartTime = 0               // Always available for vote.
	deployment.ExpireTime = math.MaxUint64 // Never expires.
}

// forceDeploymentResult modifies the passed deployment to force the provided
// choice ID as the result of provided vote ID or fails with a fatal test error
// if either are not found.
func forceDeploymentResult(t *testing.T, params *chaincfg.Params, voteID, choiceID string) {
	t.Helper()

	_, deployment := findDeployment(t, params, voteID)
	deployment.ForcedChoiceID = choiceID
}

// chaingenHarness provides a test harness which encapsulates a test instance, a
// chaingen generator instance, and a block chain instance to provide all of the
// functionality of the aforementioned types as well as several convenience
// functions such as block acceptance and rejection, expected tip checking, and
// threshold state checking.
//
// The chaingen generator is embedded in the struct so callers can directly
// access its method the same as if they were directly working with the
// underlying generator.
//
// Since chaingen involves creating fully valid and solved blocks, which is
// relatively expensive, only tests which actually require that functionality
// should make use of this harness.  In many cases, a much faster synthetic
// chain instance created by newFakeChain will suffice.
type chaingenHarness struct {
	*chaingen.Generator

	t     *testing.T
	chain *BlockChain
}

// newChaingenHarnessWithGen creates and returns a new instance of a chaingen
// harness that encapsulates the provided test instance and existing chaingen
// generator.
//
// This differs from newChaingenHarness in that it allows the caller to provide
// a chaingen generator to use instead of creating a new one.
//
// See the documentation for the chaingenHarness type for more details.
func newChaingenHarnessWithGen(t *testing.T, g *chaingen.Generator) *chaingenHarness {
	t.Helper()

	// Create a new database and chain instance to run tests against.
	chain, err := chainSetup(t, g.Params())
	if err != nil {
		t.Fatalf("Failed to setup chain instance: %v", err)
	}

	harness := chaingenHarness{
		Generator: g,
		t:         t,
		chain:     chain,
	}
	return &harness
}

// newChaingenHarness creates and returns a new instance of a chaingen harness
// that encapsulates the provided test instance.
//
// This differs from newChaingenHarnessWithGen in that it creates a new chaingen
// generator to use instead of allowing the caller to provide one.
//
// See the documentation for the chaingenHarness type for more details.
func newChaingenHarness(t *testing.T, params *chaincfg.Params) *chaingenHarness {
	t.Helper()

	// Create a test generator instance initialized with the genesis block as
	// the tip.
	g, err := chaingen.MakeGenerator(params)
	if err != nil {
		t.Fatalf("Failed to create generator: %v", err)
	}

	return newChaingenHarnessWithGen(t, &g)
}

// AcceptHeader processes the block header associated with the given name in the
// harness generator and expects it to be accepted, but not necessarily to the
// main chain.  It also ensures the underlying block index is consistent with
// the result.
func (g *chaingenHarness) AcceptHeader(blockName string) {
	g.t.Helper()

	header := &g.BlockByName(blockName).Header
	blockHash := header.BlockHash()
	blockHeight := header.Height
	g.t.Logf("Testing accept block header %q (hash %s, height %d)", blockName,
		blockHash, blockHeight)

	// Determine if the header is already known before attempting to process it.
	alreadyHaveHeader := g.chain.index.LookupNode(&blockHash) != nil

	err := g.chain.ProcessBlockHeader(header)
	if err != nil {
		g.t.Fatalf("block header %q (hash %s, height %d) should have been "+
			"accepted: %v", blockName, blockHash, blockHeight, err)
	}

	// Ensure the accepted header now exists in the block index.
	node := g.chain.index.LookupNode(&blockHash)
	if node == nil {
		g.t.Fatalf("accepted block header %q (hash %s, height %d) should have "+
			"been added to the block index", blockName, blockHash, blockHeight)
	}

	// Ensure the accepted header is not marked as known valid when it was not
	// previously known since that implies the block data is not yet available
	// and therefore it can't possibly be known to be valid.
	//
	// Also, ensure the accepted header is not marked as known invalid, as
	// having known invalid ancestors, or as known to have failed validation.
	status := g.chain.index.NodeStatus(node)
	if !alreadyHaveHeader && status.HasValidated() {
		g.t.Fatalf("accepted block header %q (hash %s, height %d) was not "+
			"already known, but is marked as known valid", blockName, blockHash,
			blockHeight)
	}
	if status.KnownInvalid() {
		g.t.Fatalf("accepted block header %q (hash %s, height %d) is marked "+
			"as known invalid", blockName, blockHash, blockHeight)
	}
	if status.KnownInvalidAncestor() {
		g.t.Fatalf("accepted block header %q (hash %s, height %d) is marked "+
			"as having a known invalid ancestor", blockName, blockHash,
			blockHeight)
	}
	if status.KnownValidateFailed() {
		g.t.Fatalf("accepted block header %q (hash %s, height %d) is marked "+
			"as having known to fail validation", blockName, blockHash,
			blockHeight)
	}
}

// AcceptBlockData processes the block associated with the given name in the
// harness generator and expects it to be accepted, but not necessarily to the
// main chain.
func (g *chaingenHarness) AcceptBlockData(blockName string) {
	g.t.Helper()

	msgBlock := g.BlockByName(blockName)
	blockHeight := msgBlock.Header.Height
	block := dcrutil.NewBlock(msgBlock)
	blockHash := block.Hash()
	g.t.Logf("Testing block %q (hash %s, height %d)", blockName, blockHash,
		blockHeight)

	_, err := g.chain.ProcessBlock(block)
	if err != nil {
		g.t.Fatalf("block %q (hash %s, height %d) should have been accepted: %v",
			blockName, blockHash, blockHeight, err)
	}
}

// AcceptBlockDataWithExpectedTip processes the block associated with the given
// name in the harness generator and expects it to be accepted, but not
// necessarily to the main chain and for the current best chain tip to be the
// provided value.
func (g *chaingenHarness) AcceptBlockDataWithExpectedTip(blockName, tipName string) {
	g.t.Helper()

	g.AcceptBlockData(blockName)
	g.ExpectTip(tipName)
}

// AcceptBlock processes the block associated with the given name in the
// harness generator and expects it to be accepted to the main chain.
func (g *chaingenHarness) AcceptBlock(blockName string) {
	g.t.Helper()

	msgBlock := g.BlockByName(blockName)
	blockHeight := msgBlock.Header.Height
	block := dcrutil.NewBlock(msgBlock)
	g.t.Logf("Testing block %q (hash %s, height %d)", blockName, block.Hash(),
		blockHeight)

	forkLen, err := g.chain.ProcessBlock(block)
	if err != nil {
		g.t.Fatalf("block %q (hash %s, height %d) should have been accepted: %v",
			blockName, block.Hash(), blockHeight, err)
	}

	// Ensure the block was accepted to the main chain as indicated by a fork
	// length of zero.
	isMainChain := forkLen == 0
	if !isMainChain {
		g.t.Fatalf("block %q (hash %s, height %d) unexpected main chain flag "+
			"-- got %v, want true", blockName, block.Hash(), blockHeight,
			isMainChain)
	}
}

// AcceptTipBlock processes the current tip block associated with the harness
// generator and expects it to be accepted to the main chain.
func (g *chaingenHarness) AcceptTipBlock() {
	g.t.Helper()

	g.AcceptBlock(g.TipName())
}

// RejectHeader expects the block header associated with the given name in the
// harness generator to be rejected with the provided error kind and also
// ensures the underlying block index is consistent with the result.
func (g *chaingenHarness) RejectHeader(blockName string, kind ErrorKind) {
	g.t.Helper()

	header := &g.BlockByName(blockName).Header
	blockHash := header.BlockHash()
	blockHeight := header.Height
	g.t.Logf("Testing reject block header %q (hash %s, height %d, reason %v)",
		blockName, blockHash, blockHeight, kind)

	// Determine if the header is already known before attempting to process it.
	alreadyHaveHeader := g.chain.index.LookupNode(&blockHash) != nil

	err := g.chain.ProcessBlockHeader(header)
	if err == nil {
		g.t.Fatalf("block header %q (hash %s, height %d) should not have been "+
			"accepted", blockName, blockHash, blockHeight)
	}

	// Ensure the error matches the value specified in the test instance.
	if !errors.Is(err, kind) {
		g.t.Fatalf("block header %q (hash %s, height %d) does not have "+
			"expected reject code -- got %v, want %v", blockName, blockHash,
			blockHeight, err, kind)
	}

	// Ensure the rejected header was not added to the block index when it was
	// not already previously successfully added and that it was not removed if
	// it was already previously added.
	node := g.chain.index.LookupNode(&blockHash)
	switch {
	case !alreadyHaveHeader && node == nil:
		// Header was not added as expected.
		return

	case !alreadyHaveHeader && node != nil:
		g.t.Fatalf("rejected block header %q (hash %s, height %d) was added "+
			"to the block index", blockName, blockHash, blockHeight)

	case alreadyHaveHeader && node == nil:
		g.t.Fatalf("rejected block header %q (hash %s, height %d) was removed "+
			"from the block index", blockName, blockHash, blockHeight)
	}

	// The header was previously added, so ensure it is not reported as having
	// been validated and that it is now known invalid.
	status := g.chain.index.NodeStatus(node)
	if status.HasValidated() {
		g.t.Fatalf("rejected block header %q (hash %s, height %d) is marked "+
			"as known valid", blockName, blockHash, blockHeight)
	}
	if !status.KnownInvalid() {
		g.t.Fatalf("rejected block header %q (hash %s, height %d) is NOT "+
			"marked as known invalid", blockName, blockHash, blockHeight)
	}
}

// RejectBlock expects the block associated with the given name in the harness
// generator to be rejected with the provided error kind.
func (g *chaingenHarness) RejectBlock(blockName string, kind ErrorKind) {
	g.t.Helper()

	msgBlock := g.BlockByName(blockName)
	blockHeight := msgBlock.Header.Height
	block := dcrutil.NewBlock(msgBlock)
	g.t.Logf("Testing reject block %q (hash %s, height %d, reason %v)",
		blockName, block.Hash(), blockHeight, kind)

	_, err := g.chain.ProcessBlock(block)
	if err == nil {
		g.t.Fatalf("block %q (hash %s, height %d) should not have been accepted",
			blockName, block.Hash(), blockHeight)
	}

	// Ensure the error matches the value specified in the test instance.
	if !errors.Is(err, kind) {
		g.t.Fatalf("block %q (hash %s, height %d) does not have expected reject "+
			"code -- got %v, want %v", blockName, block.Hash(), blockHeight,
			err, kind)
	}
}

// RejectTipBlock expects the current tip block associated with the harness
// generator to be rejected with the provided error kind.
func (g *chaingenHarness) RejectTipBlock(kind ErrorKind) {
	g.t.Helper()

	g.RejectBlock(g.TipName(), kind)
}

// ExpectTip expects the provided block to be the current tip of the main chain
// associated with the harness generator.
func (g *chaingenHarness) ExpectTip(tipName string) {
	g.t.Helper()

	// Ensure hash and height match.
	wantTip := g.BlockByName(tipName)
	best := g.chain.BestSnapshot()
	if best.Hash != wantTip.BlockHash() ||
		best.Height != int64(wantTip.Header.Height) {
		g.t.Fatalf("block %q (hash %s, height %d) should be the current tip "+
			"-- got %q (hash %s, height %d)", tipName, wantTip.BlockHash(),
			wantTip.Header.Height, g.BlockName(&best.Hash), best.Hash,
			best.Height)
	}
}

// ExpectUtxoSetState expects the provided block to be the last flushed block in
// the utxo set state in the utxo backend.
func (g *chaingenHarness) ExpectUtxoSetState(blockName string) {
	g.t.Helper()

	// Fetch the utxo set state from the utxo backend.
	gotState, err := g.chain.utxoCache.FetchBackendState()
	if err != nil {
		g.t.Fatalf("unexpected error fetching utxo set state: %v", err)
	}

	// Validate that the state matches the expected state.
	block := g.BlockByName(blockName)
	wantState := &UtxoSetState{
		lastFlushHeight: block.Header.Height,
		lastFlushHash:   block.BlockHash(),
	}
	if !reflect.DeepEqual(gotState, wantState) {
		g.t.Fatalf("mismatched utxo set state:\nwant: hash %s, height %d\n "+
			"got: hash %s, height %d\n", wantState.lastFlushHash,
			wantState.lastFlushHeight, gotState.lastFlushHash,
			gotState.lastFlushHeight)
	}
}

// AcceptedToSideChainWithExpectedTip expects the tip block associated with the
// generator to be accepted to a side chain, but the current best chain tip to
// be the provided value.
func (g *chaingenHarness) AcceptedToSideChainWithExpectedTip(tipName string) {
	g.t.Helper()

	msgBlock := g.Tip()
	blockHeight := msgBlock.Header.Height
	block := dcrutil.NewBlock(msgBlock)
	g.t.Logf("Testing block %q (hash %s, height %d)", g.TipName(), block.Hash(),
		blockHeight)

	forkLen, err := g.chain.ProcessBlock(block)
	if err != nil {
		g.t.Fatalf("block %q (hash %s, height %d) should have been accepted: %v",
			g.TipName(), block.Hash(), blockHeight, err)
	}

	// Ensure the block was accepted to a side chain as indicated by a non-zero
	// fork length.
	isMainChain := forkLen == 0
	if isMainChain {
		g.t.Fatalf("block %q (hash %s, height %d) unexpected main chain flag "+
			"-- got %v, want false", g.TipName(), block.Hash(), blockHeight,
			isMainChain)
	}

	g.ExpectTip(tipName)
}

// ExpectBestHeader expects the provided block header associated with the given
// name to be the one identified as the header of the chain associated with the
// harness generator with the most cumulative work that is NOT known to be
// invalid.
func (g *chaingenHarness) ExpectBestHeader(blockName string) {
	g.t.Helper()

	// Ensure hash and height match.
	want := g.BlockByName(blockName).Header
	bestHash, bestHeight := g.chain.BestHeader()
	if bestHash != want.BlockHash() || bestHeight != int64(want.Height) {
		g.t.Fatalf("block header %q (hash %s, height %d) should be the best "+
			"known header -- got %q (hash %s, height %d)", blockName,
			want.BlockHash(), want.Height, g.BlockName(&bestHash),
			bestHash, bestHeight)
	}
}

// ExpectBestInvalidHeader expects the provided block header associated with the
// given name to be the one identified as the header of the chain associated
// with the harness generator with the most cumulative work that is known to be
// invalid.  Note that the provided block name can be an empty string to
// indicate no such header should exist.
func (g *chaingenHarness) ExpectBestInvalidHeader(blockName string) {
	g.t.Helper()

	bestHash := g.chain.BestInvalidHeader()
	switch {
	case blockName != "" && bestHash != *zeroHash:
		want := g.BlockByName(blockName).Header
		bestHeader := g.BlockByHash(&bestHash).Header
		if bestHash != want.BlockHash() || bestHeader.Height != want.Height {
			g.t.Fatalf("block header %q (hash %s, height %d) should be the "+
				"best known invalid header -- got %q (hash %s, height %d)",
				blockName, want.BlockHash(), want.Height, g.BlockName(&bestHash),
				bestHash, bestHeader.Height)
		}

	case blockName != "" && bestHash == *zeroHash:
		want := g.BlockByName(blockName).Header
		g.t.Fatalf("block header %q (hash %s, height %d) should be the best "+
			"known invalid header -- got none", blockName, want.BlockHash(),
			want.Height)

	case blockName == "" && bestHash != *zeroHash:
		bestHeight := g.BlockByHash(&bestHash).Header.Height
		g.t.Fatalf("there should not be a best known invalid header -- got %q "+
			"(hash %s, height %d)", g.BlockName(&bestHash), bestHash,
			bestHeight)
	}
}

// ExpectIsCurrent expects the chain associated with the harness generator to
// report the given is current status.
func (g *chaingenHarness) ExpectIsCurrent(expected bool) {
	g.t.Helper()

	best := g.chain.BestSnapshot()
	isCurrent := g.chain.IsCurrent()
	if isCurrent != expected {
		g.t.Fatalf("mismatched is current status for block %q (hash %s, "+
			"height %d) -- got %v, want %v", g.BlockName(&best.Hash), best.Hash,
			best.Height, isCurrent, expected)
	}
}

// TestThresholdState queries the threshold state from the current tip block
// associated with the harness generator and expects the returned state to match
// the provided value.
func (g *chaingenHarness) TestThresholdState(id string, state ThresholdState) {
	g.t.Helper()

	tipHash := g.Tip().BlockHash()
	tipHeight := g.Tip().Header.Height
	s, err := g.chain.NextThresholdState(&tipHash, id)
	if err != nil {
		g.t.Fatalf("block %q (hash %s, height %d) unexpected error when "+
			"retrieving threshold state: %v", g.TipName(), tipHash, tipHeight,
			err)
	}

	if s.State != state {
		g.t.Fatalf("block %q (hash %s, height %d) unexpected threshold "+
			"state for %s -- got %v, want %v", g.TipName(), tipHash, tipHeight,
			id, s.State, state)
	}
}

// TestThresholdStateChoice queries the threshold state from the current tip
// block associated with the harness generator and expects the returned state
// and choice to match the provided value.
func (g *chaingenHarness) TestThresholdStateChoice(id string, state ThresholdState, choice *chaincfg.Choice) {
	g.t.Helper()

	tipHash := g.Tip().BlockHash()
	tipHeight := g.Tip().Header.Height
	s, err := g.chain.NextThresholdState(&tipHash, id)
	if err != nil {
		g.t.Fatalf("block %q (hash %s, height %d) unexpected error when "+
			"retrieving threshold state: %v", g.TipName(), tipHash, tipHeight,
			err)
	}

	if s.State != state {
		g.t.Fatalf("block %q (hash %s, height %d) unexpected threshold "+
			"state for %s -- got %v, want %v", g.TipName(), tipHash, tipHeight,
			id, s.State, state)
	}
	if !reflect.DeepEqual(s.Choice, choice) {
		gotChoiceID, wantChoiceID := "<nil>", "<nil>"
		if s.Choice != nil {
			gotChoiceID = s.Choice.Id
		}
		if choice != nil {
			wantChoiceID = choice.Id
		}
		g.t.Fatalf("block %q (hash %s, height %d) unexpected choice for %s -- "+
			"got %v, want %v", g.TipName(), tipHash, tipHeight, id, gotChoiceID,
			wantChoiceID)
	}
}

// ForceTipReorg forces the chain instance associated with the generator to
// reorganize the current tip of the main chain from the given block to the
// given block.  An error will result if the provided from block is not actually
// the current tip.
func (g *chaingenHarness) ForceTipReorg(fromTipName, toTipName string) {
	g.t.Helper()

	from := g.BlockByName(fromTipName)
	to := g.BlockByName(toTipName)
	g.t.Logf("Testing forced reorg from %q (hash %s, height %d) to %q (hash "+
		"%s, height %d)", fromTipName, from.BlockHash(), from.Header.Height,
		toTipName, to.BlockHash(), to.Header.Height)

	err := g.chain.ForceHeadReorganization(from.BlockHash(), to.BlockHash())
	if err != nil {
		g.t.Fatalf("failed to force header reorg from block %q (hash %s, "+
			"height %d) to block %q (hash %s, height %d): %v", fromTipName,
			from.BlockHash(), from.Header.Height, toTipName, to.BlockHash(),
			to.Header.Height, err)
	}
}

// InvalidateBlockAndExpectTip marks the block associated with the given name in
// the harness generator as invalid and expects the provided error along with
// the resulting current best chain tip to be the block associated with the
// given tip name.
func (g *chaingenHarness) InvalidateBlockAndExpectTip(blockName string, wantErr error, tipName string) {
	g.t.Helper()

	msgBlock := g.BlockByName(blockName)
	blockHeight := msgBlock.Header.Height
	block := dcrutil.NewBlock(msgBlock)
	g.t.Logf("Testing invalidate block %q (hash %s, height %d) with expected "+
		"error %v", blockName, block.Hash(), blockHeight, wantErr)

	err := g.chain.InvalidateBlock(block.Hash())
	if !errors.Is(err, wantErr) {
		g.t.Fatalf("invalidate block %q (hash %s, height %d) does not have "+
			"expected error -- got %q, want %v", blockName, block.Hash(),
			blockHeight, err, wantErr)
	}

	g.ExpectTip(tipName)
}

// ReconsiderBlockAndExpectTip reconsiders the block associated with the given
// name in the harness generator and expects the provided error along with the
// resulting current best chain tip to be the block associated with the given
// tip name.
func (g *chaingenHarness) ReconsiderBlockAndExpectTip(blockName string, wantErr error, tipName string) {
	g.t.Helper()

	msgBlock := g.BlockByName(blockName)
	blockHeight := msgBlock.Header.Height
	block := dcrutil.NewBlock(msgBlock)

	g.t.Logf("Testing reconsider block %q (hash %s, height %d) with expected "+
		"error %v", blockName, block.Hash(), blockHeight, wantErr)

	err := g.chain.ReconsiderBlock((block.Hash()))
	if !errors.Is(err, wantErr) {
		g.t.Fatalf("reconsider block %q (hash %s, height %d) does not have "+
			"expected error -- got %q, want %v", blockName, block.Hash(),
			blockHeight, err, wantErr)
	}

	g.ExpectTip(tipName)
}

// minUint32 is a helper function to return the minimum of two uint32s.
// This avoids a math import and the need to cast to floats.
func minUint32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

// generateToHeight generates enough blocks in the generator associated with the
// harness to reach the provided height assuming the blocks up to and including
// the provided from height have already been generated.  It also purchases the
// provided number of tickets per block after coinbase maturity.
//
// The accept flag specifies whether or not to accept the blocks to the chain
// instance associated with the harness as well.
//
// The function will fail with a fatal test error if it is called with a from
// height that is greater than or equal to the to height or a number of tickets
// that exceeds the max allowed for a block.
func (g *chaingenHarness) generateToHeight(fromHeight, toHeight uint32, buyTicketsPerBlock uint32, accept bool) {
	g.t.Helper()

	// Only allow this to be called with sane heights.
	tipHeight := fromHeight
	if toHeight <= tipHeight {
		g.t.Fatalf("not possible to generate to height %d when the current "+
			"height is already %d", toHeight, tipHeight)
	}

	// Only allow this to be called with a sane number of tickets to buy per
	// block.
	params := g.Params()
	maxOutsForTickets := uint32(params.TicketsPerBlock)
	if buyTicketsPerBlock > maxOutsForTickets {
		g.t.Fatalf("a max of %v outputs are available for ticket purchases "+
			"per block", maxOutsForTickets)
	}

	// Shorter versions of useful params for convenience.
	coinbaseMaturity := uint32(params.CoinbaseMaturity)
	stakeEnabledHeight := uint32(params.StakeEnabledHeight)

	// Add the required first block as needed.
	//
	//   genesis -> bfb
	if tipHeight == 0 {
		g.CreateBlockOne("bfb", 0)
		g.AssertTipHeight(1)
		if accept {
			g.AcceptTipBlock()
		}
		tipHeight++
	}
	intermediateHeight := uint32(1)

	// Generate enough blocks to have mature coinbase outputs to work with as
	// needed.
	//
	//   genesis -> bfb -> bm2 -> bm3 -> ... -> bm#
	alreadyAsserted := tipHeight >= coinbaseMaturity+1
	targetHeight := minUint32(coinbaseMaturity+1, toHeight)
	for ; tipHeight < targetHeight; tipHeight++ {
		blockName := fmt.Sprintf("bm%d", tipHeight-intermediateHeight)
		g.NextBlock(blockName, nil, nil)
		g.SaveTipCoinbaseOuts()
		if accept {
			g.AcceptTipBlock()
		}
	}
	intermediateHeight = targetHeight
	if !alreadyAsserted {
		g.AssertTipHeight(intermediateHeight)
	}

	// Generate enough blocks to reach the stake enabled height while creating
	// ticket purchases that spend from the coinbases matured above as needed.
	// This will also populate the pool of immature tickets.
	//
	//   ... -> bm# ... -> bse18 -> bse19 -> ... -> bse#
	var ticketsPurchased uint32
	alreadyAsserted = tipHeight >= stakeEnabledHeight
	targetHeight = minUint32(stakeEnabledHeight, toHeight)
	for ; tipHeight < targetHeight; tipHeight++ {
		var ticketOuts []chaingen.SpendableOut
		if buyTicketsPerBlock > 0 {
			// Purchase the specified number of tickets per block.
			outs := g.OldestCoinbaseOuts()
			ticketOuts = outs[1 : buyTicketsPerBlock+1]
			ticketsPurchased += buyTicketsPerBlock
		}

		blockName := fmt.Sprintf("bse%d", tipHeight-intermediateHeight)
		g.NextBlock(blockName, nil, ticketOuts)
		g.SaveTipCoinbaseOuts()
		if accept {
			g.AcceptTipBlock()
		}
	}
	intermediateHeight = targetHeight
	if !alreadyAsserted {
		g.AssertTipHeight(intermediateHeight)
	}

	targetPoolSize := uint32(g.Params().TicketPoolSize) * buyTicketsPerBlock
	for ; tipHeight < toHeight; tipHeight++ {
		var ticketOuts []chaingen.SpendableOut
		// Only purchase tickets until the target ticket pool size is reached.
		ticketsNeeded := targetPoolSize - ticketsPurchased
		ticketsNeeded = minUint32(ticketsNeeded, buyTicketsPerBlock)
		if ticketsNeeded > 0 {
			outs := g.OldestCoinbaseOuts()
			ticketOuts = outs[1 : ticketsNeeded+1]
			ticketsPurchased += ticketsNeeded
		}

		blockName := fmt.Sprintf("bsv%d", tipHeight-intermediateHeight)
		g.NextBlock(blockName, nil, ticketOuts)
		g.SaveTipCoinbaseOuts()
		if accept {
			g.AcceptTipBlock()
		}
	}
	g.AssertTipHeight(toHeight)
}

// AdvanceToHeight generates and accepts enough blocks to the chain instance
// associated with the harness to reach the provided height while purchasing the
// provided tickets per block after coinbase maturity.
func (g *chaingenHarness) AdvanceToHeight(height uint32, buyTicketsPerBlock uint32) {
	g.t.Helper()

	// Only allow this to be called with a sane height.
	tipHeight := g.Tip().Header.Height
	if height <= tipHeight {
		g.t.Fatalf("not possible to advance to height %d when the current "+
			"height is already %d", height, tipHeight)
	}

	const accept = true
	g.generateToHeight(tipHeight, height, buyTicketsPerBlock, accept)
}

// generateToStakeValidationHeight generates enough blocks in the generator
// associated with the harness to reach stake validation height.
//
// The accept flag specifies whether or not to accept the blocks to the chain
// instance associated with the harness as well.
//
// The function will fail with a fatal test error if it is not called with the
// harness at the genesis block which is the case when it is first created.
func (g *chaingenHarness) generateToStakeValidationHeight(accept bool) {
	g.t.Helper()

	// Only allow this to be called on a newly created harness.
	if g.Tip().Header.Height != 0 {
		g.t.Fatalf("chaingen harness instance must be at the genesis block " +
			"to generate to stake validation height")
	}

	// Shorter versions of useful params for convenience.
	params := g.Params()
	ticketsPerBlock := uint32(params.TicketsPerBlock)
	stakeValidationHeight := uint32(params.StakeValidationHeight)

	// Generate enough blocks in the associated harness generator to reach stake
	// validation height.
	g.generateToHeight(0, stakeValidationHeight, ticketsPerBlock, accept)
}

// GenerateToStakeValidationHeight generates enough blocks in the generator
// associated with the harness to reach stake validation height without
// accepting them to the chain instance associated with the harness.
//
// The function will fail with a fatal test error if it is not called with the
// harness at the genesis block which is the case when it is first created.
func (g *chaingenHarness) GenerateToStakeValidationHeight() {
	g.t.Helper()

	const accept = false
	g.generateToStakeValidationHeight(accept)
}

// AdvanceToStakeValidationHeight generates and accepts enough blocks to the
// chain instance associated with the harness to reach stake validation height.
//
// The function will fail with a fatal test error if it is not called with the
// harness at the genesis block which is the case when it is first created.
func (g *chaingenHarness) AdvanceToStakeValidationHeight() {
	g.t.Helper()

	const accept = true
	g.generateToStakeValidationHeight(accept)
}

// AdvanceFromSVHToActiveAgendas generates and accepts enough blocks with the
// appropriate vote bits set to reach one block prior to the specified agendas
// becoming active.
//
// The function will fail with a fatal test error if it is called when the
// harness is not at stake validation height or if the agendas are not all from
// the same deployment.
//
// WARNING: This function currently assumes the chain parameters were created
// via the quickVoteActivationParams.  It should be updated in the future to
// work with arbitrary params.
func (g *chaingenHarness) AdvanceFromSVHToActiveAgendas(voteIDs ...string) {
	g.t.Helper()

	if len(voteIDs) < 1 {
		g.t.Fatal("no vote IDs specified")
	}

	// Sum all yes bits from all the agendas.
	params := g.Params()
	deploymentVer, yesBits := findDeploymentAllYesChoices(g.t, params, voteIDs)

	// Shorter versions of useful params for convenience.
	stakeValidationHeight := params.StakeValidationHeight
	stakeVerInterval := params.StakeVersionInterval
	ruleChangeInterval := int64(params.RuleChangeActivationInterval)
	testThresholdState := func(state ThresholdState) {
		for _, voteID := range voteIDs {
			g.TestThresholdState(voteID, state)
		}
	}

	// Only allow this to be called on a harness at SVH.
	if g.Tip().Header.Height != uint32(stakeValidationHeight) {
		g.t.Fatalf("chaingen harness instance must be at stake validation " +
			"height to advance to active agendas")
	}

	// ---------------------------------------------------------------------
	// Generate enough blocks to reach one block before the next two stake
	// version intervals with block and vote versions for the agenda and
	// stake version 0.
	//
	// This will result in triggering enforcement of the stake version and
	// that the stake version is the deployment version.  The threshold
	// state for deployment will move to started since the next block also
	// coincides with the start of a new rule change activation interval for
	// the chosen parameters.
	//
	//   ... -> bsv# -> bvu0 -> bvu1 -> ... -> bvu#
	// ---------------------------------------------------------------------

	blocksNeeded := stakeValidationHeight + stakeVerInterval*2 - 1 -
		int64(g.Tip().Header.Height)
	for i := int64(0); i < blocksNeeded; i++ {
		outs := g.OldestCoinbaseOuts()
		blockName := fmt.Sprintf("bvu%d", i)
		g.NextBlock(blockName, nil, outs[1:],
			chaingen.ReplaceBlockVersion(int32(deploymentVer)),
			chaingen.ReplaceVoteVersions(deploymentVer))
		g.SaveTipCoinbaseOuts()
		g.AcceptTipBlock()
	}
	testThresholdState(ThresholdStarted)

	// ---------------------------------------------------------------------
	// Generate enough blocks to reach the next rule change interval with
	// block, stake, and vote versions for the agenda.  Also, set the vote
	// bits to include yes votes for the agenda.
	//
	// This will result in moving the threshold state for the agenda to
	// locked in.
	//
	//   ... -> bvu# -> bvli0 -> bvli1 -> ... -> bvli#
	// ---------------------------------------------------------------------

	blocksNeeded = stakeValidationHeight + ruleChangeInterval*2 - 1 -
		int64(g.Tip().Header.Height)
	for i := int64(0); i < blocksNeeded; i++ {
		outs := g.OldestCoinbaseOuts()
		blockName := fmt.Sprintf("bvli%d", i)
		g.NextBlock(blockName, nil, outs[1:],
			chaingen.ReplaceBlockVersion(int32(deploymentVer)),
			chaingen.ReplaceStakeVersion(deploymentVer),
			chaingen.ReplaceVotes(vbPrevBlockValid|yesBits, deploymentVer))
		g.SaveTipCoinbaseOuts()
		g.AcceptTipBlock()
	}
	g.AssertTipHeight(uint32(stakeValidationHeight + ruleChangeInterval*2 - 1))
	g.AssertBlockVersion(int32(deploymentVer))
	g.AssertStakeVersion(deploymentVer)
	testThresholdState(ThresholdLockedIn)

	// ---------------------------------------------------------------------
	// Generate enough blocks to reach the next rule change interval with
	// block, stake, and vote versions for the agenda.
	//
	// This will result in moving the threshold state for the agenda to
	// active thereby activating it.
	//
	//   ... -> bvli# -> bva0 -> bva1 -> ... -> bva#
	// ---------------------------------------------------------------------

	blocksNeeded = stakeValidationHeight + ruleChangeInterval*3 - 1 -
		int64(g.Tip().Header.Height)
	for i := int64(0); i < blocksNeeded; i++ {
		outs := g.OldestCoinbaseOuts()
		blockName := fmt.Sprintf("bva%d", i)
		g.NextBlock(blockName, nil, outs[1:],
			chaingen.ReplaceBlockVersion(int32(deploymentVer)),
			chaingen.ReplaceStakeVersion(deploymentVer),
			chaingen.ReplaceVoteVersions(deploymentVer),
		)
		g.SaveTipCoinbaseOuts()
		g.AcceptTipBlock()
	}
	g.AssertTipHeight(uint32(stakeValidationHeight + ruleChangeInterval*3 - 1))
	g.AssertBlockVersion(int32(deploymentVer))
	g.AssertStakeVersion(deploymentVer)
	testThresholdState(ThresholdActive)
}

// mustParseHash converts the passed big-endian hex string into a chainhash.Hash.
// It will panic if there is an error. This function should only be used in tests.
func mustParseHash(s string) *chainhash.Hash {
	hash, err := chainhash.NewHashFromStr(s)
	if err != nil {
		panic(err)
	}
	return hash
}
