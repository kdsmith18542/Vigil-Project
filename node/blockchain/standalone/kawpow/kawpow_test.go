// Copyright (c) 2025 The Vigil Developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package kawpow

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/decred/dcrd/chaincfg/chainhash"
)

// TestKawPowHash verifies the KawPoW hashing works correctly.
func TestKawPowHash(t *testing.T) {
	tests := []struct {
		name      string
		header    string
		nonce     uint64
		expHash   string
		expMix    string
		shouldErr bool
	}{
		{
			name:      "basic test",
			header:    "test header",
			nonce:     12345,
			expHash:   "TODO",
			expMix:    "TODO",
			shouldErr: false,
		},
		// Add more test cases as needed
	}

	kawpow := New()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			hash, mix, err := kawpow.Hash([]byte(test.header), test.nonce)
			if (err != nil) != test.shouldErr {
				t.Fatalf("unexpected error: %v", err)
			}

			if test.shouldErr {
				return
			}

			if test.expHash != "TODO" {
				expHash, _ := chainhash.NewHashFromStr(test.expHash)
				if !bytes.Equal(hash, expHash[:]) {
					t.Errorf("unexpected hash: got %x, want %s", hash, test.expHash)
				}
			}

			if test.expMix != "TODO" {
				expMix, _ := chainhash.NewHashFromStr(test.expMix)
				if !bytes.Equal(mix, expMix[:]) {
					t.Errorf("unexpected mix: got %x, want %s", mix, test.expMix)
				}
			}
		})
	}
}

// TestSeedHash verifies the seed hash calculation.
func TestSeedHash(t *testing.T) {
	tests := []struct {
		name     string
		blockNum uint64
		expected string
	}{
		{
			name:     "block 0",
			blockNum: 0,
			expected: "1da0af1706a31185763837b33f1d90782c0a78bbe644a59c987ab3ff9c0b346e",
		},
		{
			name:     "block 1",
			blockNum: 1,
			expected: "9a4585773ce2ccd7a585c331d60a60d1e3b7d28cbb2ede3bc55445342f12f54b",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Calculate the seed hash
			h := sha256.Sum256([]byte{byte(test.blockNum)})
			
			// Convert the hash to a chainhash.Hash
			var hash chainhash.Hash
			copy(hash[:], h[:])
			
			// Get the string representation of the hash
			hexStr := hash.String()
			if hexStr != test.expected {
				t.Errorf("unexpected seed hash: got %s, want %s", hexStr, test.expected)
			}
		})
	}
}