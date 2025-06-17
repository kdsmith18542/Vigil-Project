package rpcserver

import (
	"bytes"
	"github.com/decred/dcrd/wire"
)

// serializeGetWorkData returns serialized data that represents work to be
// solved for KawPoW mining. It includes the serialized block header with
// the 64-bit nonce and mix digest fields.
func serializeGetWorkDataKawPow(header *wire.BlockHeader) ([]byte, error) {
	// KawPoW requires a larger buffer to accommodate the 64-bit nonce and mix digest
	const kawpowDataLen = wire.MaxBlockHeaderPayload + 32 // Additional space for mix digest
	
	// Serialize the block header
	data := make([]byte, 0, kawpowDataLen)
	buf := bytes.NewBuffer(data)
	err := header.Serialize(buf)
	if err != nil {
		return nil, rpcInternalErr(err, "Failed to serialize data")
	}
	
	// Expand to full size and zero-pad
	data = data[:kawpowDataLen]
	return data, nil
}
