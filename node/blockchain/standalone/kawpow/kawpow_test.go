// Copyright (c) 2025 The Vigil Developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package kawpow

import (
	"testing"
)

// TestBasicHash verifies the basic KawPoW hashing functionality
func TestBasicHash(t *testing.T) {
	header := make([]byte, 180)
	copy(header, "Test header for hashing")
	nonce := uint64(12345)

	kp := New()

	t.Log("Testing basic hash calculation...")
	mixHash, finalHash, err := kp.Hash(header, nonce)

	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	if len(mixHash) == 0 || len(finalHash) == 0 {
		t.Fatal("Empty hash result")
	}

	t.Logf("Mix hash: %x", mixHash)
	t.Logf("Final hash: %x", finalHash)

	// Verify the hash is valid according to Verify
	valid, err := kp.Verify(header, nonce, mixHash, finalHash)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}
	if !valid {
		t.Fatal("Verification failed: hash is not valid")
	}
	t.Log("Verification successful")
}

// TestSeedHash verifies the seed hash calculation.
func TestSeedHash(t *testing.T) {
	tests := []struct {
		name     string
		height   int64
		time     int64
		expected string
	}{
		{
			name:     "genesis block",
			height:   0,
			time:     0x5f5e100,
			expected: "1da0af1706a31185763837b33f1d90782c0a78bbe644a59c987ab3ff9c0b346e",
		},
		{
			name:     "block 1",
			height:   1,
			time:     0x5f5e101,
			expected: "9a4585773ce2ccd7a585c331d60a60d1e3b7d28cbb2ede3bc55445342f12f54b",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			hash, err := CalcSeedHash(test.height, test.time)
			if err != nil {
				t.Fatalf("CalcSeedHash failed: %v", err)
			}

			hexStr := hash.String()
			if hexStr != test.expected {
				t.Errorf("unexpected seed hash: got %s, want %s", hexStr, test.expected)
			}
		})
	}
}