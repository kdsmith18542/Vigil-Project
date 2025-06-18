module vigil.network/node/blockchain/standalone

go 1.17

require (
	vigil.network/node/chaincfg/chainhash v0.0.0
	github.com/decred/dcrd/wire v1.7.0
)

require (
	github.com/decred/dcrd/crypto/blake256 v1.0.1 // indirect
	github.com/klauspost/cpuid/v2 v2.0.9 // indirect
	lukechampine.com/blake3 v1.3.0 // indirect
)

replace (
	vigil.network/node/chaincfg/chainhash => ../../../chaincfg/chainhash
)
