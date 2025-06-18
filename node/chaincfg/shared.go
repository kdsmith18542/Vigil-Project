package chaincfg

import (
	"math/big"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrd/chaincfg/chainhash"
)

var (
	MainPowLimit = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 224), big.NewInt(1))
	GenesisBlock wire.MsgBlock
	GenesisHash  chainhash.Hash
)
