package blockchain

import (
	"math/big"
	
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrd/blockchain/standalone"
)

func checkProofOfWork(header *wire.BlockHeader, powLimit *big.Int) error {
	// For Vigil, we only use KawPoW (V2) for all blocks
	powHash := header.PowHashV2()
	
	// Verify the PoW using KawPoW algorithm
	err := standalone.CheckProofOfWork(&powHash, header.Bits, powLimit, &header.MixDigest)
	return standaloneToChainRuleError(err)
}

func standaloneToChainRuleError(err error) error {
	if err == nil {
		return nil
	}
	return ruleError(ErrInvalidPoW, err.Error())
}
