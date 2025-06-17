package rpcserver

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrjson/v4"
	"github.com/decred/dcrd/wire"
	
	"github.com/decred/dcrd/internal/rpcserver/types"
	"github.com/decred/dcrd/blockchain"
	"github.com/decred/dcrd/mining"
	"github.com/decred/dcrd/syncmgr"
	"github.com/decred/dcrd/connmgr"
	"math/big"
	"encoding/binary"
	"github.com/decred/dcrd/internal/kawpow"
)

// Server is a copy of the main Server type from rpcserver.go
// with just the fields we need for KawPoW operations
type Server struct {
	cfg            *Config
	workState      *workState
}

// workState is a minimal version of the workState struct from rpcserver.go
type workState struct {
	workSem semaphore
}

// semaphore is a minimal version of the semaphore implementation
type semaphore chan struct{}

func (s semaphore) release() { <-s }

// Config contains the configuration required by the RPC server
type Config struct {
	Chain             *blockchain.BlockChain
	CPUMiner          *CPUMiner
	GenerateNewBlock  func() (*mining.BlockTemplate, error)
	SyncMgr           *syncmgr.SyncManager
	ConnMgr           *connmgr.ConnManager
	MiningAddrs       []string
	AllowUnsyncedMining bool
}

// CPUMiner is a minimal version of the CPUMiner struct from rpcserver.go
type CPUMiner struct {
	mining bool
}

func (c *CPUMiner) IsMining() bool {
	return c.mining
}

// ConnMgr is a minimal version of the ConnMgr struct from rpcserver.go
type ConnMgr struct {
	connectedCount int
}

func (c *ConnMgr) ConnectedCount() int {
	return c.connectedCount
}

// SyncMgr is a minimal version of the SyncMgr struct from rpcserver.go
type SyncMgr struct {
}

func (s *SyncMgr) SubmitBlock(header *wire.BlockHeader) error {
	// Implementation will be added in next step
	return nil
}

// rpcInternalErr is a helper function to create internal RPC errors
func rpcInternalErr(err error, context string) error {
	return &dcrjson.RPCError{
		Code:    dcrjson.ErrRPCInternal.Code,
		Message: context + ": " + err.Error(),
	}
}

// rpcMiscError is a helper function to create misc RPC errors
func rpcMiscError(message string) error {
	return &dcrjson.RPCError{
		Code:    dcrjson.ErrRPCMisc.Code,
		Message: message,
	}
}

// rpcDecodeHexError is a helper function to create decode hex errors
func rpcDecodeHexError(data string) error {
	return &dcrjson.RPCError{
		Code:    dcrjson.ErrRPCDecodeHex.Code,
		Message: "Invalid parameter " + data,
	}
}

// isKawPowActive returns whether KawPoW proof of work is active for the block
// AFTER the provided block hash.
func (s *Server) isKawPowActive(prevBlkHash *chainhash.Hash) (bool, error) {
	chain := s.cfg.Chain
	isActive, err := chain.IsKawPowActive(prevBlkHash)
	if err != nil {
		context := fmt.Sprintf("Could not obtain KawPoW status for block %s", prevBlkHash)
		return false, rpcInternalErr(err, context)
	}
	return isActive, nil
}

// handleGetWorkKawPow implements the getwork command for KawPoW mining.
func (s *Server) handleGetWorkKawPow(ctx context.Context, cmd interface{}) (interface{}, error) {
	if s.cfg.CPUMiner.IsMining() {
		return nil, rpcMiscError("getwork polling is disallowed " +
			"while CPU mining is enabled. Please disable CPU " +
			"mining and try again.")
	}

	// Check for payment addresses
	if len(s.cfg.MiningAddrs) == 0 {
		err := errors.New("no payment addresses specified via --miningaddr")
		return nil, rpcInternalErr(err, "Configuration")
	}

	// Check for connected peers
	if !s.cfg.AllowUnsyncedMining && s.cfg.ConnMgr.ConnectedCount() == 0 {
		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCClientNotConnected,
			Message: "Decred is not connected",
		}
	}

	// Check chain sync status
	chain := s.cfg.Chain
	_, bestHeaderHeight := chain.BestHeader()
	bestHeight := chain.BestSnapshot().Height
	initialChainState := bestHeaderHeight == 0 && bestHeight == 0
	if !s.cfg.AllowUnsyncedMining && !initialChainState && !chain.IsCurrent() {
		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCClientInInitialDownload,
			Message: "Decred is downloading blocks...",
		}
	}

	c := cmd.(*types.GetWorkCmd)

	// Handle work submission if data is provided
	if c.Data != nil && *c.Data != "" {
		return s.handleGetWorkSubmissionKawPow(ctx, *c.Data)
	}

	// Handle work request
	return s.handleGetWorkRequestKawPow(ctx)
}

// handleGetWorkRequestKawPow handles KawPoW work requests
func (s *Server) handleGetWorkRequestKawPow(ctx context.Context) (interface{}, error) {
	// Get the current best block header
	chain := s.cfg.Chain
	prevHash := chain.BestSnapshot().Hash
	
	// Check if KawPoW is active
	isKawPowActive, err := s.isKawPowActive(prevHash)
	if err != nil {
		return nil, err
	}
	if !isKawPowActive {
		return nil, rpcMiscError("KawPoW is not currently active")
	}

	// Generate a new block template
	template, err := s.cfg.GenerateNewBlock()
	if err != nil {
		return nil, rpcInternalErr(err, "Failed to generate block template")
	}

	// Serialize the block header for KawPoW
	data, err := serializeGetWorkDataKawPow(&template.Block.Header)
	if err != nil {
		return nil, rpcInternalErr(err, "Failed to serialize work data")
	}

	// Return the work data in hex format
	return hex.EncodeToString(data), nil
}

// handleGetWorkSubmissionKawPow handles KawPoW work submissions
func (s *Server) handleGetWorkSubmissionKawPow(ctx context.Context, data string) (interface{}, error) {
	// Decode the submitted work
	workBytes, err := hex.DecodeString(data)
	if err != nil {
		return nil, rpcDecodeHexError(data)
	}

	// Deserialize the block header
	var header wire.BlockHeader
	err = header.Deserialize(bytes.NewReader(workBytes))
	if err != nil {
		return nil, rpcInternalErr(err, "Failed to deserialize block header")
	}

	// Verify the KawPoW proof of work
	isValid, err := s.CheckKawPoWProof(&header)
	if err != nil {
		return nil, rpcInternalErr(err, "Failed to verify KawPoW proof")
	}
	if !isValid {
		return "rejected", nil
	}

	// Submit the valid block
	err = s.cfg.SyncMgr.SubmitBlock(&header)
	if err != nil {
		return nil, rpcInternalErr(err, "Failed to submit block")
	}

	return nil, nil
}

// serializeGetWorkDataKawPow serializes the block header for KawPoW mining
func serializeGetWorkDataKawPow(header *wire.BlockHeader) ([]byte, error) {
	// KawPoW requires the full header plus 64-bit nonce and mix digest fields
	data := make([]byte, 0, wire.MaxBlockHeaderPayload+8+32)
	buf := bytes.NewBuffer(data)
	
	// Serialize the block header
	err := header.Serialize(buf)
	if err != nil {
		return nil, rpcInternalErr(err, "Failed to serialize header")
	}
	
	// Add padding for 64-bit nonce and 32-byte mix digest
	pad := make([]byte, 8+32)
	buf.Write(pad)
	
	return buf.Bytes(), nil
}

// handleGetWork handles the getwork command
func handleGetWork(ctx context.Context, s *Server, cmd interface{}) (interface{}, error) {
	if s.cfg.CPUMiner.IsMining() {
		return nil, rpcMiscError("getwork polling is disallowed " +
			"while CPU mining is enabled. Please disable CPU " +
			"mining and try again.")
	}

	// Get current best block hash
	chain := s.cfg.Chain
	prevHash := chain.BestSnapshot().Hash
	
	// Check if KawPoW is active
	isKawPowActive, err := s.isKawPowActive(prevHash)
	if err != nil {
		return nil, err
	}
	
	// Delegate to appropriate handler
	if isKawPowActive {
		return s.handleGetWorkKawPow(ctx, cmd)
	}
	
	// Default to original handler
	c := cmd.(*types.GetWorkCmd)
	if c.Data != nil && *c.Data != "" {
		return handleGetWorkSubmission(ctx, s, *c.Data)
	}
	return handleGetWorkRequest(ctx, s)
}

// CheckKawPoWProof verifies a block header's KawPoW proof of work
func (s *Server) CheckKawPoWProof(header *wire.BlockHeader) (bool, error) {
	// Get current blockchain state
	chain := s.cfg.Chain
	prevHash := chain.BestSnapshot().Hash
	
	// Check if KawPoW is active
	isKawPowActive, err := s.isKawPowActive(prevHash)
	if err != nil {
		return false, err
	}
	if !isKawPowActive {
		return false, errors.New("KawPoW is not currently active")
	}

	// Serialize header for hashing
	headerBytes, err := serializeGetWorkDataKawPow(header)
	if err != nil {
		return false, err
	}

	// Extract nonce from header (last 8 bytes)
	nonce := binary.LittleEndian.Uint64(headerBytes[len(headerBytes)-40:len(headerBytes)-32])
	
	// Extract mix digest from header (last 32 bytes)
	mixDigest := headerBytes[len(headerBytes)-32:]
	
	// Calculate expected seed hash
	seed, err := kawpow.CalcSeedHash(header.Height, header.Timestamp.Unix())
	if err != nil {
		return false, err
	}

	// Verify the proof
	hash, calculatedMix, err := kawpow.Hash(header.Height, header.Timestamp.Unix(), seed, headerBytes[:wire.MaxBlockHeaderPayload], nonce)
	if err != nil {
		return false, err
	}

	// Check mix digest matches
	if !bytes.Equal(mixDigest, calculatedMix[:]) {
		return false, nil
	}

	// Check hash meets target difficulty
	targetDifficulty := blockchain.CompactToBig(header.Bits)
	hashNum := new(big.Int).SetBytes(hash[:])
	if hashNum.Cmp(targetDifficulty) > 0 {
		return false, nil
	}

	return true, nil
}
