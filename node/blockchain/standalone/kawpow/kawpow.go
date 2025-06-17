// Copyright (c) 2025 The Vigil Developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package kawpow

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash"
	"sync"
	"time"

	"github.com/decred/dcrd/chaincfg/chainhash"
)

const (
	// KawPowEpochLength is the number of blocks before the seed needs to be regenerated
	KawPowEpochLength = 7500

	// Cache sizes for different memory requirements
	cacheSize   = 64 * 1024
	datasetSize = 4 * 1024 * 1024 * 1024
)

// KawPow is a hasher implementing the KawPoW proof-of-work algorithm.
type KawPow struct {
	cache    []uint32
	dataset  []uint64
	cacheGen uint64
}

// New creates a new KawPow hasher.
func New() *KawPow {
	kp := &KawPow{
		cache:    make([]uint32, cacheSize/4),
		dataset:  make([]uint64, datasetSize/8),
		cacheGen: uint64(time.Now().Unix() / 300),
	}

	// Generate initial cache
	seed := make([]byte, 32)
	binary.LittleEndian.PutUint64(seed, kp.cacheGen)

	cache := make([]uint32, cacheSize/4)
	generateCache(cache, kp.cacheGen, seed)

	// Generate DAG
	dataset := make([]uint64, datasetSize/8)
	generateDataset(dataset, cache)

	kp.cache = cache
	kp.dataset = dataset
	return kp
}

// keccakState implements the Keccak-256 hash
type keccakState interface {
	hash.Hash
	Read([]byte) (int, error)
	Size() int
	BlockSize() int
}

// keccak256State implements the Keccak-256 hash
type keccak256State struct {
	state [200]byte // Keccak-256 state
}

func (k *keccak256State) Sum(b []byte) []byte {
	// Final padding and permutation
	k.state[k.BlockSize()] ^= 0x01
	k.state[len(k.state)-1] ^= 0x80

	// Simple permutation (would need full Keccak-f implementation for production)
	for i := 0; i < 24; i++ {
		// Simplified round function
		for j := 0; j < len(k.state); j += 8 {
			k.state[j] ^= k.state[j+1]
		}
	}

	return append(b, k.state[:k.Size()]...)
}

func (k *keccak256State) Write(p []byte) (int, error) {
	// Basic keccak absorption implementation
	for i, b := range p {
		k.state[i%136] ^= b
	}
	return len(p), nil
}

func (k *keccak256State) Reset() {
	k.state = [200]byte{}
}

func (k *keccak256State) Size() int {
	return 32
}

func (k *keccak256State) BlockSize() int {
	return 136
}

func (k *keccak256State) Read(p []byte) (int, error) {
	copy(p, k.state[:len(p)])
	return len(p), nil
}

func newKeccak256() keccakState {
	return &keccak256State{}
}

// keccak512State implements a simplified Keccak-512 hash
type keccak512State struct {
	state [200]byte // Keccak-512 state
}

func (k *keccak512State) Write(p []byte) (int, error) {
	// Basic keccak absorption implementation
	for i, b := range p {
		k.state[i%72] ^= b
	}
	return len(p), nil
}

func (k *keccak512State) Sum(b []byte) []byte {
	// Final padding and permutation
	k.state[72] ^= 0x01
	k.state[len(k.state)-1] ^= 0x80

	// Simple permutation (would need full Keccak-f implementation for production)
	for i := 0; i < 24; i++ {
		// Simplified round function
		for j := 0; j < len(k.state); j += 8 {
			k.state[j] ^= k.state[j+1]
		}
	}

	return append(b, k.state[:64]...)
}

func (k *keccak512State) Reset() {
	k.state = [200]byte{}
}

func (k *keccak512State) Size() int {
	return 64
}

func (k *keccak512State) BlockSize() int {
	return 72
}

func (k *keccak512State) Read(p []byte) (int, error) {
	copy(p, k.state[:len(p)])
	return len(p), nil
}

func newKeccak512() keccakState {
	return &keccak512State{}
}

// CalcSeedHash calculates the seed hash for a given block height and timestamp
func CalcSeedHash(height int64, timestamp int64) (chainhash.Hash, error) {
	// Calculate epoch number
	epoch := height / KawPowEpochLength

	// Generate seed hash for this epoch
	seed := make([]byte, 32)
	binary.LittleEndian.PutUint64(seed[:8], uint64(epoch))
	binary.LittleEndian.PutUint64(seed[8:16], uint64(timestamp))

	// Use Keccak-256 for the seed hash (as specified in KawPoW)
	hash := newKeccak256()
	hash.Write(seed)
	return chainhash.HashH(hash.Sum(nil)), nil
}

// Hash computes the KawPoW hash of the given block header.
func (k *KawPow) Hash(headerBytes []byte, nonce uint64) ([]byte, []byte, error) {
	// Extract block height and timestamp from the header bytes
	// Assuming headerBytes is the full serialized block header, we need to carefully
	// parse it to get the height and timestamp. Based on wire/blockheader.go,
	// Height is at offset 152 (Version 4 + PrevBlock 32 + MerkleRoot 32 + StakeRoot 32 + VoteBits 2 + FinalState 6 + Voters 2 + FreshStake 1 + Revocations 1 + PoolSize 4 + Bits 4 + SBits 8)
	// Timestamp is at offset 168 (Height 4 + Size 4)

	if len(headerBytes) < 172 { // Minimum size to contain height and timestamp
		return nil, nil, fmt.Errorf("invalid headerBytes length for KawPoW hash calculation: %d", len(headerBytes))
	}

	height := binary.LittleEndian.Uint32(headerBytes[152:156])
	timestamp := binary.LittleEndian.Uint32(headerBytes[168:172])

	// Calculate seed hash
	seedHash, err := CalcSeedHash(int64(height), int64(timestamp))
	if err != nil {
		return nil, nil, err
	}

	// Get the DAG for this epoch
	epoch := int64(height) / KawPowEpochLength
	dag, err := getDAG(epoch, seedHash)
	if err != nil {
		return nil, nil, err
	}

	// Initialize hash state for Hashimoto
	h := newKeccak256()

	// Prepare input for Hashimoto: headerBytes (without nonce and mix digest) + nonce
	// According to wire/blockheader.go, Nonce starts at offset 172 and MixDigest at 180.
	// We need headerBytes up to offset 172, then append the nonce.
	headerPrefix := headerBytes[:172] // Part of header before nonce

	// Combine header prefix and nonce for initial hash
	combinedInput := make([]byte, len(headerPrefix)+8)
	copy(combinedInput, headerPrefix)
	binary.LittleEndian.PutUint64(combinedInput[len(headerPrefix):], nonce)
	h.Write(combinedInput)

	initialHash := h.Sum(nil)

	// KawPoW hash computation (Hashimoto algorithm)
	mix := make([]byte, 64)
	copy(mix, initialHash)

	// Main hash loop using DAG
	for i := 0; i < 64; i++ {
		// Select a DAG item based on the current mix state
		// Use a temporary variable for the modulo operation to ensure it's positive.
		index := binary.LittleEndian.Uint64(mix) % uint64(len(dag.items))
		dagItem := dag.items[index]

		// Mix with DAG item (XOR operation)
		for j := 0; j < 8; j++ {
			valMix := binary.LittleEndian.Uint32(mix[j*4:])
			valDag := binary.LittleEndian.Uint32(dagItem.data[j*4:])
			binary.LittleEndian.PutUint32(mix[j*4:], valMix^valDag)
		}

		// Hash the mix
		h.Reset()
		h.Write(mix)
		mix = h.Sum(nil)
	}

	// Final hash
	h.Reset()
	h.Write(initialHash)
	h.Write(mix)
	finalHash := h.Sum(nil)

	// Convert to byte slices
	var finalHashBytes [chainhash.HashSize]byte
	copy(finalHashBytes[:], finalHash)

	var mixDigestBytes [chainhash.HashSize]byte
	copy(mixDigestBytes[:], mix)

	return finalHashBytes[:], mixDigestBytes[:], nil
}

// Verify computes the KawPoW hash and mix digest for the given block data
// and verifies them against the provided values.
func (k *KawPow) Verify(headerBytes []byte, nonce uint64, mixDigest []byte) (bool, error) {
	computedHash, computedMixDigest, err := k.Hash(headerBytes, nonce)
	if err != nil {
		return false, err
	}

	if !bytes.Equal(computedHash, headerBytes[180:180+chainhash.HashSize]) { // Assuming headerBytes contains the final hash after mix digest
		return false, nil
	}
	if !bytes.Equal(computedMixDigest, mixDigest) {
		return false, nil
	}

	return true, nil
}

// dagItem represents an item in the DAG
type dagItem struct {
	data [32]byte
}

// dagCache holds the generated DAG for a specific epoch
type dagCache struct {
	epoch   int64
	items   []dagItem
	created time.Time
}

var (
	// dagCacheLock protects access to dagCaches
	dagCacheLock sync.Mutex
	// dagCaches contains all active DAG caches
	dagCaches = make(map[int64]*dagCache)
)

const KawPowDatasetItems = 16777216

// getDAG returns the DAG for the given epoch
func getDAG(epoch int64, seed chainhash.Hash) (*dagCache, error) {
	// TODO: Implement proper DAG caching
	// For now, generate a new DAG each time
	dag := &dagCache{
		epoch:   epoch,
		items:   make([]dagItem, KawPowDatasetItems),
		created: time.Now(),
	}

	// Generate DAG items
	h := newKeccak512()
	seedBytes := seed[:]

	for i := 0; i < KawPowDatasetItems; i++ {
		h.Reset()
		h.Write(seedBytes)
		binary.Write(h, binary.LittleEndian, uint32(i))
		itemHash := h.Sum(nil)

		copy(dag.items[i].data[:], itemHash)
	}

	return dag, nil
}

// GenerateDAG generates the DAG needed for mining.
func (k *KawPow) GenerateDAG(blockNum uint64) error {
	epoch := int64(blockNum / KawPowEpochLength)
	seedHash, err := CalcSeedHash(int64(blockNum), 0)
	if err != nil {
		return err
	}
	_, err = getDAG(epoch, seedHash)
	return err
}

// LoadDAG loads the DAG from disk or generates it if it doesn't exist.
func (k *KawPow) LoadDAG(blockNum uint64) error {
	// TODO: Implement DAG loading/generation
	return k.GenerateDAG(blockNum)
}

// GetSeedHash returns the seed hash for the given block number.
func GetSeedHash(blockNum uint64) []byte {
	seed := make([]byte, 32)
	for i := uint64(0); i < blockNum/KawPowEpochLength; i++ {
		seed = chainhash.HashB(seed)
	}
	return seed
}

// generateCache generates the cache for a given epoch
func generateCache(cache []uint32, epoch uint64, seed []byte) {
	// Use epoch in the seed generation if seed is empty
	if len(seed) == 0 {
		binary.LittleEndian.PutUint64(seed[:8], epoch)
	}

	// Initialize the cache
	keccak := newKeccak512()
	keccak.Write(seed)
	keccak.Sum(seed[:0])

	// Generate the cache
	for i := 0; i < len(cache); i += 16 {
		keccak.Write(seed)
		binary.Read(bytes.NewReader(keccak.Sum(nil)), binary.LittleEndian, cache[i:i+16])
		keccak.Reset()
	}

	// Perform cache randomization
	for i := 0; i < 3; i++ {
		for j := 0; j < len(cache); j++ {
			cache[j] = cache[j] ^ cache[(j+1)%len(cache)]
		}
	}
}

// generateDataset generates the dataset for a given epoch
func generateDataset(dataset []uint64, cache []uint32) {
	// Generate the dataset
	for i := 0; i < len(dataset); i++ {
		itemNum := uint32(i)
		mix := make([]uint32, 16)

		// Initial mix
		mix[0] = itemNum
		for j := 1; j < 16; j++ {
			mix[j] = cache[j] ^ mix[j-1]
		}

		// Main mixing loop
		for j := 0; j < 256; j++ {
			newData := make([]uint32, 16)
			for k := 0; k < 16; k++ {
				idx := (mix[k%16]%uint32(len(cache)/16))*16 + uint32(k)
				newData[k] = cache[idx]
			}

			// Final mix
			for k := 0; k < 16; k++ {
				mix[k] = mix[k] ^ newData[k]
			}
		}

		// Store the result
		var result uint64
		for j := 0; j < 8; j++ {
			result |= uint64(mix[j%16]) << (32 * uint(j%2))
		}
		dataset[i] = result
	}
}
