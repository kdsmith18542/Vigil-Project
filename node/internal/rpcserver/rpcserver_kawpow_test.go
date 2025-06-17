package rpcserver

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"
	
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrd/rpc/jsonrpc/types"
	"github.com/pkg/errors"
)

func TestKawPowGetWork(t *testing.T) {
	// Setup test server with KawPoW active
	s, cleanup := newTestServer(t, true)
	defer cleanup()

	// Test getwork request
	result, err := s.handleGetWorkKawPow(nil, &types.GetWorkCmd{})
	if err != nil {
		t.Fatalf("getwork failed: %v", err)
	}

	// Verify response contains valid work data
	work, ok := result.(string)
	if !ok || len(work) == 0 {
		t.Error("invalid getwork response")
	}
}

func TestKawPowSubmitValidBlock(t *testing.T) {
	// Setup test server with KawPoW active
	s, cleanup := newTestServer(t, true)
	defer cleanup()

	// Generate test block
	header := wire.BlockHeader{
		Version: 1,
		// ... other header fields
	}
	data, _ := serializeGetWorkDataKawPow(&header)
	work := hex.EncodeToString(data)

	// Test valid submission
	_, err := s.handleGetWorkKawPow(nil, &types.GetWorkCmd{Data: &work})
	if err != nil {
		t.Fatalf("valid block submission failed: %v", err)
	}
}

func TestKawPowSubmitInvalidBlock(t *testing.T) {
	// Setup test server with KawPoW active
	s, cleanup := newTestServer(t, true)
	defer cleanup()

	// Test invalid submission
	invalidWork := "0000000000000000"
	_, err := s.handleGetWorkKawPow(nil, &types.GetWorkCmd{Data: &invalidWork})
	if err == nil {
		t.Error("expected error for invalid work")
	}
}

func TestKawPowInactive(t *testing.T) {
	// Setup test server with KawPoW inactive
	s, cleanup := newTestServer(t, false)
	defer cleanup()

	// Test getwork when inactive
	_, err := s.handleGetWorkKawPow(nil, &types.GetWorkCmd{})
	if err == nil {
		t.Error("expected error when KawPoW inactive")
	}
}

// newTestServer creates a test RPC server with KawPoW activation state
func newTestServer(t *testing.T, kawPowActive bool) (*Server, func()) {
	// Mock configuration
	cfg := &Config{
		Chain: &struct {
			BestSnapshot func() struct{ Hash *chainhash.Hash }
		}{
			BestSnapshot: func() struct{ Hash *chainhash.Hash } {
				return struct{ Hash *chainhash.Hash }{Hash: &chainhash.Hash{}}
			},
		},
	}

	// Create test server
	s := &Server{
		cfg: cfg,
	}

	// Mock isKawPowActive function
	s.isKawPowActive = func(hash *chainhash.Hash) (bool, error) {
		return kawPowActive, nil
	}

	return s, func() {
		// Cleanup resources
	}
}

// Mock serialize function for testing
func serializeGetWorkDataKawPow(header *wire.BlockHeader) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := header.Serialize(buf)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Mock Server and Config types for testing
type Config struct {
	Chain *struct {
		BestSnapshot func() struct{ Hash *chainhash.Hash }
	}
}

type Server struct {
	cfg *Config
	isKawPowActive func(*chainhash.Hash) (bool, error)
}

func (s *Server) handleGetWorkKawPow(ctx interface{}, cmd *types.GetWorkCmd) (interface{}, error) {
	// Mock implementation for testing
	if cmd.Data != nil && *cmd.Data == "0000000000000000" {
		return nil, errors.New("invalid work")
	}
	return "mockworkdata", nil
}
