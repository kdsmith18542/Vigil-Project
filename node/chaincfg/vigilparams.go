package chaincfg

import (
	"time"
)

// VigilMainNetParams defines the network parameters for the main Vigil network.
var VigilMainNetParams = Params{
	Name:        "mainnet",
	Net:         0xd9b40001, // Unique network ID for Vigil
	DefaultPort: "9250",
	DNSSeeds: []DNSSeed{
		{Host: "seed.vigil.network", HasFiltering: true},
	},

	// Chain parameters
	GenesisBlock:             &GenesisBlock,
	GenesisHash:              GenesisHash,
	PowLimit:                 MainPowLimit,
	PowLimitBits:             0x1d00ffff,
	ReduceMinDifficulty:      false,
	MinDiffReductionTime:     0,
	GenerateSupported:        true,
	MaximumBlockSizes:       []int{393216},
	MaxTxSize:                393216,
	TargetTimePerBlock:       150 * time.Second, // 2.5 minutes
	WorkDiffAlpha:            1,
	WorkDiffWindowSize:       144,
	WorkDiffWindows:          20,
	TargetTimespan:           150 * 144 * time.Second, // 6 hours
	RetargetAdjustmentFactor: 4,

	// Add other required parameters with default values
	AcceptNonStdTxs:         false,
	CoinbaseMaturity:        256,
}
