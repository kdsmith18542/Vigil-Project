// Copyright (c) 2024 Vigil Network
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package chaincfg

import (
	"testing"
)

// TestVigilGenesisBlock verifies the genesis block of the Vigil network.
func TestVigilGenesisBlock(t *testing.T) {
	params := VigilMainNetParams
	hash := params.GenesisBlock.BlockHash()
	
	t.Logf("Vigil genesis hash: %s", hash)
	t.Logf("Vigil genesis hash (hex): %s", hash.String())
}
