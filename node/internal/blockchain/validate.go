package blockchain

import (
	"math/big"
	
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrd/blockchain/standalone"
)

func checkProofOfWork(header *wire.BlockHeader, powLimit *big.Int) error {
	powHashV1 := header.PowHashV1()
	err := standalone.CheckProofOfWork(&powHashV1, header.Bits, powLimit)
	if err != nil {
		powHashV2 := header.PowHashV2()
		err = standalone.CheckProofOfWork(&powHashV2, header.Bits, powLimit)
	}
	return standaloneToChainRuleError(err)
}

func standaloneToChainRuleError(err error) error {
	if err == nil {
		return nil
	}
	return ruleError(ErrInvalidPoW, err.Error())
}
