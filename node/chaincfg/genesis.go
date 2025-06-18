package chaincfg

import (
	"time"

	"vigil.network/node/chaincfg/chainhash"
	"github.com/decred/dcrd/wire"
)

func init() {
	// Initialize genesis block
	GenesisBlock = wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:   1,
			PrevBlock: chainhash.Hash{}, // Zero hash
			MerkleRoot: *mustParseHash("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"),
			Timestamp:  time.Unix(0x61c402e0, 0), // 2025-06-17 00:00:00 UTC
			Bits:       0x1d00ffff,
			Nonce:      0x7c2bac1d,
		},
		Transactions: []*wire.MsgTx{
			// Genesis transaction
			{
				Version: 1,
				TxIn: []*wire.TxIn{
					{
						PreviousOutPoint: wire.OutPoint{
							Hash:  chainhash.Hash{},
							Index: 0xffffffff,
						},
						SignatureScript: []byte{
							0x04, 0xff, 0xff, 0x00, 0x1d, 0x01, 0x04, 'V', 'i', 'g', 'i', 'l', ' ', 'G', 'e', 'n', 'e', 's', 'i', 's', ' ', 'B', 'l', 'o', 'c', 'k',
						},
						Sequence: 0xffffffff,
					},
				},
				TxOut: []*wire.TxOut{
					{
						Value: 0x12a05f200, // 50 VGL
						PkScript: []byte{
							0x41, // OP_DATA_65
							0x04, 0x67, 0x8a, 0xfd, 0xb0, 0xfe, 0x55, 0x48, 0x27,
							0x19, 0x67, 0xf1, 0xa6, 0x71, 0x30, 0xb7, 0x10, 0x5c,
							0xd6, 0x75, 0xbe, 0x77, 0x66, 0x2f, 0x32, 0x2d, 0x35,
							0x12, 0x3b, 0x9c, 0x7c, 0x23, 0x5d, 0xbc, 0xd0, 0xb6,
							0x96, 0xfd, 0x2d, 0x4d, 0x8e, 0xf6, 0x21, 0x47, 0x4f,
							0x52, 0x54, 0x45, 0x44, 0x20, 0x42, 0x59, 0x20, 0x56,
							0x49, 0x47, 0x49, 0x4c, 0x20, 0x54, 0x45, 0x41, 0x4d,
							0xac, // OP_CHECKSIG
						},
					},
				},
				LockTime: 0,
			},
		},
	}
	GenesisHash = GenesisBlock.BlockHash()
}

// mustParseHash converts the passed big-endian hex string into a
// chainhash.Hash and will panic if there is an error.
func mustParseHash(s string) *chainhash.Hash {
	hash, err := chainhash.NewHashFromStr(s)
	if err != nil {
		panic(err)
	}
	return hash
}
