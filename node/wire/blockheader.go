// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (c) 2015-2023 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"fmt"
	"io"
	"time"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/internal/kawpow"
)

// MaxBlockHeaderPayload is the maximum number of bytes a block header can be.
// Version 4 bytes + PrevBlock 32 bytes + MerkleRoot 32 bytes + StakeRoot 32
// bytes + VoteBits 2 bytes + FinalState 6 bytes + Voters 2 bytes + FreshStake 1
// byte + Revocations 1 bytes + PoolSize 4 bytes + Bits 4 bytes + SBits 8 bytes
// + Height 4 bytes + Size 4 bytes + Timestamp 4 bytes + Nonce 8 bytes +
// MixDigest 32 bytes + ExtraData 32 bytes + StakeVersion 4 bytes.
// --> Total 212 bytes.
const MaxBlockHeaderPayload = 84 + (chainhash.HashSize * 4) + 4

// BlockHeader defines information about a block and is used in the decred
// block (MsgBlock) and headers (MsgHeaders) messages.
type BlockHeader struct {
	// Version of the block.  This is not the same as the protocol version.
	Version int32

	// Hash of the previous block in the block chain.
	PrevBlock chainhash.Hash

	// Merkle tree reference to hash of all transactions for the block.
	MerkleRoot chainhash.Hash

	// Merkle tree reference to hash of all stake transactions for the block.
	StakeRoot chainhash.Hash

	// Votes on the previous merkleroot and yet undecided parameters.
	VoteBits uint16

	// Final state of the PRNG used for ticket selection in the lottery.
	FinalState [6]byte

	// Number of participating voters for this block.
	Voters uint16

	// Number of new sstx in this block.
	FreshStake uint8

	// Number of ssrtx present in this block.
	Revocations uint8

	// Size of the ticket pool.
	PoolSize uint32

	// Difficulty target for the block.
	Bits uint32

	// Stake difficulty target.
	SBits int64

	// Height is the block height in the block chain.
	Height uint32

	// Size is the size of the serialized block in its entirety.
	Size uint32

	// Time the block was created.  This is, unfortunately, encoded as a
	// uint32 on the wire and therefore is limited to 2106.
	Timestamp time.Time

	// Nonce is the 64-bit nonce required for KawPoW mining
	Nonce uint64

	// MixDigest is the mix hash produced by KawPoW mining
	MixDigest [32]byte

	// ExtraData is used for any other extra data that might be used in consensus
	ExtraData [32]byte

	// StakeVersion used for voting.
	StakeVersion uint32
}

// blockHeaderLen is a constant that represents the number of bytes for a block
// header.
const blockHeaderLen = 180

// BlockHash computes the block identifier hash for the given block header.
func (h *BlockHeader) BlockHash() chainhash.Hash {
	// Encode the header and hash everything prior to the number of
	// transactions.  Ignore the error returns since there is no way the encode
	// could fail except being out of memory which would cause a run-time panic.
	buf := bytes.NewBuffer(make([]byte, 0, MaxBlockHeaderPayload))
	_ = writeBlockHeader(buf, 0, h)

	return chainhash.HashH(buf.Bytes())
}

// PowHashV1 calculates and returns the version 1 proof of work hash for the
// block header.
//
// NOTE: This is the original proof of work hash function used at Decred launch
// and applies to all blocks prior to the activation of DCP0011.
func (h *BlockHeader) PowHashV1() chainhash.Hash {
	return h.BlockHash()
}

// PowHashV2 calculates and returns the version 2 proof of work hash as defined
// in DCP0011 for the block header.
func (h *BlockHeader) PowHashV2() chainhash.Hash {
	// KawPoW requires the full header bytes to calculate the hash.
	// The `Bytes()` method returns the serialized header including nonce and mix digest.
	headerBytes, err := h.Bytes()
	if err != nil {
		// This should ideally not happen if MaxBlockHeaderPayload is correct and
		// serialization doesn't fail due to out-of-memory.
		panic(fmt.Sprintf("Failed to serialize block header for KawPoW hash: %v", err))
	}

	// Create a new KawPoW hasher and compute the hash.
	kp := kawpow.New()
	finalHash, _, err := kp.Hash(headerBytes[:len(headerBytes)-32], h.Nonce) // Pass headerBytes excluding MixDigest
	if err != nil {
		// This should ideally not happen if the KawPoW implementation is solid.
		panic(fmt.Sprintf("Failed to compute KawPoW hash: %v", err))
	}

	var hash chainhash.Hash
	copy(hash[:], finalHash)
	return hash
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
// See Deserialize for decoding block headers stored to disk, such as in a
// database, as opposed to decoding block headers from the wire.
func (h *BlockHeader) BtcDecode(r io.Reader, pver uint32) error {
	return readBlockHeader(r, pver, h)
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
// See Serialize for encoding block headers to be stored to disk, such as in a
// database, as opposed to encoding block headers for the wire.
func (h *BlockHeader) BtcEncode(w io.Writer, pver uint32) error {
	return writeBlockHeader(w, pver, h)
}

// Deserialize decodes a block header from r into the receiver using a format
// that is suitable for long-term storage such as a database while respecting
// the Version field.
func (h *BlockHeader) Deserialize(r io.Reader) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of readBlockHeader.
	return readBlockHeader(r, 0, h)
}

// FromBytes deserializes a block header byte slice.
func (h *BlockHeader) FromBytes(b []byte) error {
	r := bytes.NewReader(b)
	return h.Deserialize(r)
}

// Serialize encodes a block header from r into the receiver using a format
// that is suitable for long-term storage such as a database while respecting
// the Version field.
func (h *BlockHeader) Serialize(w io.Writer) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of writeBlockHeader.
	return writeBlockHeader(w, 0, h)
}

// Bytes returns a byte slice containing the serialized contents of the block
// header.
func (h *BlockHeader) Bytes() ([]byte, error) {
	buf := bytes.NewBuffer(make([]byte, 0, MaxBlockHeaderPayload))
	err := h.Serialize(buf)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// BytesNoNonce returns the serialized bytes of the block header without the nonce.
// This is used by the KawPoW algorithm.
func (h *BlockHeader) BytesNoNonce() []byte {
	buf := bytes.NewBuffer(make([]byte, 0, MaxBlockHeaderPayload))
	_ = writeBlockHeaderNoNonce(buf, 0, h)
	return buf.Bytes()
}

// NewBlockHeader returns a new BlockHeader using the provided previous block
// hash, merkle root hash, difficulty bits, and nonce used to generate the
// block with defaults for the remaining fields.
func NewBlockHeader(version int32, prevHash *chainhash.Hash,
	merkleRootHash *chainhash.Hash, stakeRoot *chainhash.Hash, voteBits uint16,
	finalState [6]byte, voters uint16, freshStake uint8, revocations uint8,
	poolsize uint32, bits uint32, sbits int64, height uint32, size uint32,
	timestamp time.Time, nonce uint64, mixDigest [32]byte, extraData [32]byte, stakeVersion uint32) *BlockHeader {

	// Limit the timestamp to one second precision since the protocol
	// doesn't support better.
	return &BlockHeader{
		Version:      version,
		PrevBlock:    *prevHash,
		MerkleRoot:   *merkleRootHash,
		StakeRoot:    *stakeRoot,
		VoteBits:     voteBits,
		FinalState:   finalState,
		Voters:       voters,
		FreshStake:   freshStake,
		Revocations:  revocations,
		PoolSize:     poolsize,
		Bits:         bits,
		SBits:        sbits,
		Height:       height,
		Size:         size,
		Timestamp:    timestamp,
		Nonce:        nonce,
		MixDigest:    mixDigest,
		ExtraData:    extraData,
		StakeVersion: stakeVersion,
	}
}

// readBlockHeader reads a Decred block header from r.  See Deserialize for
// decoding block headers stored to disk, such as in a database, as opposed to
// decoding from the wire.
func readBlockHeader(r io.Reader, pver uint32, bh *BlockHeader) error {
	return readElements(r, &bh.Version, &bh.PrevBlock, &bh.MerkleRoot,
		&bh.StakeRoot, &bh.VoteBits, &bh.FinalState, &bh.Voters,
		&bh.FreshStake, &bh.Revocations, &bh.PoolSize, &bh.Bits,
		&bh.SBits, &bh.Height, &bh.Size, (*uint32Time)(&bh.Timestamp),
		&bh.Nonce, &bh.MixDigest, &bh.ExtraData, &bh.StakeVersion)
}

// writeBlockHeader writes a Decred block header to w.  See Serialize for
// encoding block headers to be stored to disk, such as in a database, as
// opposed to encoding for the wire.
func writeBlockHeader(w io.Writer, pver uint32, bh *BlockHeader) error {
	sec := uint32(bh.Timestamp.Unix())
	return writeElements(w, bh.Version, &bh.PrevBlock, &bh.MerkleRoot,
		&bh.StakeRoot, bh.VoteBits, bh.FinalState, bh.Voters,
		bh.FreshStake, bh.Revocations, bh.PoolSize, bh.Bits, bh.SBits,
		bh.Height, bh.Size, sec, bh.Nonce, bh.MixDigest, bh.ExtraData,
		bh.StakeVersion)
}

// writeBlockHeaderNoNonce writes a Decred block header to w without the nonce.
// See Serialize for encoding block headers to be stored to disk, such as in a
// database, as opposed to encoding for the wire.
func writeBlockHeaderNoNonce(w io.Writer, pver uint32, bh *BlockHeader) error {
	sec := uint32(bh.Timestamp.Unix())
	return writeElements(w, bh.Version, &bh.PrevBlock, &bh.MerkleRoot,
		&bh.StakeRoot, bh.VoteBits, bh.FinalState, bh.Voters,
		bh.FreshStake, bh.Revocations, bh.PoolSize, bh.Bits, bh.SBits,
		bh.Height, bh.Size, sec, 0, bh.MixDigest, bh.ExtraData,
		bh.StakeVersion)
}
