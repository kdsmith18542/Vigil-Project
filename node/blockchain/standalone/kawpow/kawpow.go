// Copyright (c) 2025 The Vigil Developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package kawpow

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/bits"
	"sync"
	"time"

	"vigil.network/node/chaincfg/chainhash"
)

const (
	// KawPowEpochLength is the number of blocks before the seed needs to be regenerated
	KawPowEpochLength = 7500

	// Cache sizes for different memory requirements
	cacheSize   = 16 * 1024 * 1024  // 16MB
	datasetSize = 2 * 1024 * 1024 * 1024  // 2GB
	cacheRounds = 3  // Number of rounds for cache generation
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
		cache:   make([]uint32, cacheSize/4),
		dataset:  make([]uint64, datasetSize/8),
		cacheGen: uint64(time.Now().Unix() / 300),
	}

	// Generate initial cache
	seed := make([]byte, 32)
	binary.LittleEndian.PutUint64(seed, kp.cacheGen)

	var seedHash chainhash.Hash
	copy(seedHash[:], seed)

	// Generate cache and dataset
	kp.cache = kp.generateCache(seedHash)
	kp.dataset = kp.generateDataset(kp.cache)

	return kp
}

// generateCache generates the cache for the given seed.
func (k *KawPow) generateCache(seed chainhash.Hash) []uint32 {
	size := cacheSize / 4
	cache := make([]uint32, size)

	// Initialize the cache with the seed
	hash := k.keccak512(seed[:])

	// Copy the hash into the cache
	for i := 0; i < len(hash)/4 && i < len(cache); i++ {
		cache[i] = binary.LittleEndian.Uint32(hash[i*4:])
	}

	// Generate the cache
	for i := 1; i < cacheRounds; i++ {
		hash = k.keccak512(hash)
		for j := 0; j < len(hash)/4 && i*len(hash)/4+j < len(cache); j++ {
			cache[i*len(hash)/4+j] = binary.LittleEndian.Uint32(hash[j*4:])
		}
	}

	return cache
}

// generateDataset generates the dataset for the given cache.
func (k *KawPow) generateDataset(cache []uint32) []uint64 {
	size := datasetSize / 8
	dataset := make([]uint64, size)

	// Generate the dataset using the cache
	for i := 0; i < len(dataset); i++ {
		// Calculate the parent index
		parentIndex := i % len(cache)
		
		// Get the parent value from cache
		parent := uint64(cache[parentIndex])
		
		// Calculate the new value using the parent and the cache
		newValue := parent ^ uint64(i)
		
		// Store the new value in the dataset
		dataset[i] = newValue
		
		// Update the cache for the next iteration
		if i < len(cache) {
			cache[i] = uint32((newValue * 0x5bd1e995) ^ (newValue >> 31))
		}
	}

	return dataset
}

// keccakState implements the Keccak hash interface
type keccakState interface {
	io.Writer
	Sum([]byte) []byte
	Reset()
	Size() int
	BlockSize() int
	Read([]byte) (int, error)
}

// keccakF1600 implements the Keccak-f[1600] permutation
type keccakF1600 struct {
	a        [25]uint64
	rate     int
	off      int
	buf      []byte
	hashSize int
}

// NewKeccak256 creates a new Keccak-256 hash
func NewKeccak256() keccakState {
	return &keccakF1600{rate: 136, hashSize: 32}
}

// NewKeccak512 creates a new Keccak-512 hash
func NewKeccak512() keccakState {
	return &keccakF1600{rate: 72, hashSize: 64}
}

// Reset resets the hash to its initial state
func (k *keccakF1600) Reset() {
	k.a = [25]uint64{}
	k.off = 0
	k.buf = k.buf[:0]
}

// Write adds more data to the running hash
func (k *keccakF1600) Write(p []byte) (int, error) {
	if k.buf == nil {
		k.buf = make([]byte, 0, k.rate)
	}

	n := len(p)
	k.buf = append(k.buf, p...)

	// Process full blocks
	for len(k.buf) >= k.rate {
		k.absorb(k.buf[:k.rate])
		k.buf = k.buf[k.rate:]
	}

	return n, nil
}

// Sum appends the current hash to b and returns the resulting slice
func (k *keccakF1600) Sum(b []byte) []byte {
	hash := make([]byte, k.hashSize)
	k.finalize(hash)
	return append(b, hash...)
}

// finalize completes the hash and writes the result to hash
func (k *keccakF1600) finalize(hash []byte) {
	// Pad with 1 bit and 0 bits up to rate bytes
	k.buf = append(k.buf, 0x01)
	for len(k.buf) < k.rate {
		k.buf = append(k.buf, 0)
	}
	k.absorb(k.buf[:k.rate])

	// Squeeze the state into the hash
	for i := 0; i < k.hashSize/8; i++ {
		binary.LittleEndian.PutUint64(hash[i*8:], k.a[i])
	}
}

// Size returns the number of bytes Sum will return
func (k *keccakF1600) Size() int {
	return k.hashSize
}

// BlockSize returns the hash's underlying block size
func (k *keccakF1600) BlockSize() int {
	return k.rate
}

// Read reads more data from the hash
func (k *keccakF1600) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	if len(k.buf) == 0 {
		return 0, io.EOF
	}

	n := copy(p, k.buf)
	k.buf = k.buf[n:]
	return n, nil
}

// absorb absorbs a full block of data into the state
func (k *keccakF1600) absorb(data []byte) {
	for i := 0; i < k.rate/8; i++ {
		k.a[i] ^= binary.LittleEndian.Uint64(data[i*8:])
	}
	k.permute()
}

// permute applies the Keccak-f[1600] permutation to the state.
func (k *keccakF1600) permute() {
	var bc [5]uint64
	var t uint64

	for round := 0; round < 24; round++ {
		// Theta step
		for x := 0; x < 5; x++ {
			bc[x] = k.a[x] ^ k.a[x+5] ^ k.a[x+10] ^ k.a[x+15] ^ k.a[x+20]
		}

		for x := 0; x < 5; x++ {
			t = bc[(x+4)%5] ^ bits.RotateLeft64(bc[(x+1)%5], 1)
			for y := 0; y < 5; y++ {
				k.a[x+5*y] ^= t
			}
		}

		// Rho and Pi steps
		t = k.a[1]
		x, y := 1, 0
		for i := 0; i < 24; i++ {
			x, y = y, (2*x+3*y)%5
			t, k.a[x+5*y] = k.a[x+5*y], bits.RotateLeft64(t, int(rhoOffset[i]))
		}

		// Chi step
		for y := 0; y < 5; y++ {
			for x := 0; x < 5; x++ {
				bc[x] = k.a[x+5*y]
			}
			for x := 0; x < 5; x++ {
				k.a[x+5*y] = bc[x] ^ (^bc[(x+1)%5] & bc[(x+2)%5])
			}
		}

		// Iota step
		k.a[0] ^= rc[round]
	}
}

// keccak256 computes the Keccak-256 hash of the input.
func (k *KawPow) keccak256(data []byte) []byte {
	h := NewKeccak256()
	h.Write(data)
	return h.Sum(nil)
}

// keccak512 computes the Keccak-512 hash of the input.
func (k *KawPow) keccak512(data []byte) []byte {
	h := NewKeccak512()
	h.Write(data)
	return h.Sum(nil)
}

// hashimoto implements the KawPoW hash function.
func (k *KawPow) hashimoto(headerHash []byte, nonce, datasetSize uint64) ([]byte, []byte) {
	if len(headerHash) != 32 {
		panic(fmt.Sprintf("invalid header hash length: %d", len(headerHash)))
	}
	if datasetSize == 0 || datasetSize%128 != 0 {
		panic(fmt.Sprintf("invalid dataset size: %d", datasetSize))
	}
	// Implementation of the KawPoW hash function
	// This is a more complete implementation that uses the DAG for mixing

	// Create a buffer with header + nonce
	headerNonce := make([]byte, len(headerHash)+8)
	copy(headerNonce, headerHash)
	binary.LittleEndian.PutUint64(headerNonce[len(headerHash):], nonce)

	// Calculate initial mix hash (keccak512 of header + nonce)
	mix := k.keccak512(headerNonce)


	// Number of mixing rounds (KawPoW uses 64 rounds)
	const mixRounds = 64

	// Calculate the number of 32-byte words in the DAG
	words := datasetSize / 32

	// Calculate the number of 32-byte words per mix (KawPoW uses 128 words)
	const mixBytes = 128 * 32 // 128 words * 32 bytes per word
	const mixWords = mixBytes / 4 // 1024 32-bit words

	// Create a buffer for the mix
	mixBuffer := make([]uint32, mixWords)

	// Initialize mix buffer with the initial hash
	for i := 0; i < len(mixBuffer); i++ {
		if i*4+4 <= len(mix) {
			mixBuffer[i] = binary.LittleEndian.Uint32(mix[i*4:])
		}
	}

	// Main mixing loop
	for i := 0; i < mixRounds; i++ {
		// Calculate the new mix data index
		parent := fnv(uint32(i)^mixBuffer[i%len(mixBuffer)], mixBuffer[(i+1)%len(mixBuffer)]) % uint32(words)
		
		// Get the parent data from the DAG
		parentData := make([]byte, 64) // 64 bytes per DAG item
		for j := 0; j < 16; j++ { // 16 uint32s = 64 bytes
			if int(parent)*16+j < len(k.dataset) {
				binary.LittleEndian.PutUint32(parentData[j*4:], uint32(k.dataset[int(parent)*16+j]))
			}
		}

		// Mix the parent data with the current mix
		for j := 0; j < len(mixBuffer); j++ {
			if j*4+4 <= len(parentData) {
				mixBuffer[j] = fnv(mixBuffer[j], binary.LittleEndian.Uint32(parentData[j*4:]))
			}
		}
	}

	// Compress the mix
	compressedMix := make([]byte, 32)
	for i := 0; i < len(mixBuffer) && i < 8; i++ {
		binary.LittleEndian.PutUint32(compressedMix[i*4:], mixBuffer[i])
	}

	// Calculate the final hash (keccak256 of header + compressed mix + nonce)
	hashInput := make([]byte, len(headerHash)+len(compressedMix)+8)
	copy(hashInput, headerHash)
	copy(hashInput[len(headerHash):], compressedMix)
	binary.LittleEndian.PutUint64(hashInput[len(headerHash)+len(compressedMix):], nonce)

	result := k.keccak256(hashInput)

	return compressedMix, result
}

// fnv implements the Fowler-Noll-Vo hash function
func fnv(a, b uint32) uint32 {
	return (a * 0x01000193) ^ b
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
// It returns the mix hash and the final hash.
func (k *KawPow) Hash(headerBytes []byte, nonce uint64) ([]byte, []byte, error) {
	log.Printf("KawPow.Hash called with header length: %d, nonce: %d", len(headerBytes), nonce)
	
	if len(headerBytes) < 172 { // Ensure header is large enough for height and timestamp
		return nil, nil, fmt.Errorf("header too short (got %d, want at least 172)", len(headerBytes))
	}

	height := binary.LittleEndian.Uint32(headerBytes[152:156])
	timestamp := binary.LittleEndian.Uint32(headerBytes[168:172])
	log.Printf("Extracted height: %d, timestamp: %d", height, timestamp)

	log.Println("Calculating seed hash...")
	seedHash, err := CalcSeedHash(int64(height), int64(timestamp))
	if err != nil {
		log.Printf("Error calculating seed hash: %v", err)
		return nil, nil, err
	}
	log.Printf("Seed hash: %x", seedHash)

	log.Println("Generating cache...")
	cache := k.generateCache(seedHash)
	log.Printf("Generated cache with %d items", len(cache))

	if k.dataset == nil {
		log.Println("Generating dataset...")
		k.dataset = k.generateDataset(cache)
	}

	if len(k.dataset) == 0 {
		err := fmt.Errorf("empty dataset generated")
		log.Println(err)
		return nil, nil, err
	}

	log.Println("Hashing header with Keccak-256...")
	headerHash := k.keccak256(headerBytes)
	log.Printf("Header hash: %x", headerHash)

	log.Println("Running hashimoto...")
	mixHash, result := k.hashimoto(headerHash, nonce, uint64(len(k.dataset)*8))

	if len(mixHash) == 0 || len(result) == 0 {
		err := fmt.Errorf("empty hash result from hashimoto")
		log.Println(err)
		return nil, nil, err
	}

	log.Printf("Hashimoto completed. Mix hash: %x, Result: %x", mixHash, result)
	return mixHash, result, nil
}

// Verify computes the KawPoW hash and mix digest for the given block data
// Verify verifies the nonce of a block's header.
func (k *KawPow) Verify(headerBytes []byte, nonce uint64, mixDigest, hash []byte) (bool, error) {
	// Calculate the hash and mix digest
	computedMix, computedHash, err := k.Hash(headerBytes, nonce)
	if err != nil {
		return false, err
	}

	// Compare the computed values with the provided ones
	if !bytes.Equal(computedMix, mixDigest) {
		return false, nil
	}

	if !bytes.Equal(computedHash, hash) {
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

// Constants for Keccak-f[1600] permutation
var (
	rhoOffset [24]uint
	rc        [24]uint64
)

func init() {
	// Initialize rho offsets
	rhoOffsets := []uint{
		1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
		27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
	}
	copy(rhoOffset[:], rhoOffsets)

	// Initialize round constants
	rcValues := []uint64{
		0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
		0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
		0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
		0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
		0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
		0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
		0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
		0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
	}
	copy(rc[:], rcValues)
}

// Helper functions for backward compatibility
func newKeccak256() keccakState {
	return NewKeccak256()
}

func newKeccak512() keccakState {
	return NewKeccak512()
}
