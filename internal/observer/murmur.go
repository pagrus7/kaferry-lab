package observer

import (
	"encoding/binary"
	"errors"
)

var errPartitionCount = errors.New("partition count must be positive")

// Murmur2 is a local implementation of Kafka's published MurmurHash2 variant.
// Its tests use fixed Apache Kafka 3.9.2 golden hashes, never another lab function
// to calculate expected hashes. The nil-key routing policy is separate.
func Murmur2(key []byte) uint32 {
	const m uint32 = 0x5bd1e995
	h := uint32(0x9747b28c) ^ uint32(len(key))
	for len(key) >= 4 {
		k := binary.LittleEndian.Uint32(key)
		k *= m
		k ^= k >> 24
		k *= m
		h *= m
		h ^= k
		key = key[4:]
	}
	switch len(key) {
	case 3:
		h ^= uint32(key[2]) << 16
		fallthrough
	case 2:
		h ^= uint32(key[1]) << 8
		fallthrough
	case 1:
		h ^= uint32(key[0])
		h *= m
	}
	h ^= h >> 13
	h *= m
	h ^= h >> 15
	return h
}
func KeyPartition(key []byte, partitions int32) (int32, error) {
	if partitions <= 0 {
		return 0, errPartitionCount
	}
	return int32((Murmur2(key) & 0x7fffffff) % uint32(partitions)), nil
}
