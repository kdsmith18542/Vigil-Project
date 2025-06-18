module vigil.network/node

go 1.23.0

replace (
	vigil.network/node/blockchain/standalone => ./node/blockchain/standalone
	vigil.network/node/blockchain/standalone/kawpow => ./node/blockchain/standalone/kawpow
	vigil.network/node/chaincfg => ./node/chaincfg
	vigil.network/node/chaincfg/chainhash => ./node/chaincfg/chainhash
)
