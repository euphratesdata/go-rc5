// Copyright 2017 Marc Wilson, Scorpion Compute. All rights
// reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

package rc5

import (
	"crypto/cipher"
)

const (
	W64 		= 64		// word size in bits
	WW64		= W64 / 8 	// word size in bytes
	B64 		= 128 		// block size in bits
	BB64 		= B64 / 8 	// block size in bytes
	P64			= 0xb7e151628aed2a6b
  	Q64 		= 0x9e3779b97f4a7c15
)

type cipher64 struct {
	K 				[]byte 			// secret key
	b 				uint 			// byte length of secret key
	R 				uint 			// number of rounds
	S 				[]uint64 		// expanded key table
	T 				uint 			// number of words in expanded key table
}

func getUint64(b []byte) uint64 {
	return uint64(b[0]) 	   |
		   uint64(b[1]) <<   8 |
		   uint64(b[2]) <<  16 |
		   uint64(b[3]) <<  24 |
		   uint64(b[4]) <<  32 |
		   uint64(b[5]) <<  40 |
		   uint64(b[6]) <<  48 |
		   uint64(b[7]) <<  56
}

func get64(b []byte) (uint64, uint64) {
	return getUint64(b[:8]), getUint64(b[8:])
}

func put64(dst[] byte, a uint64, b uint64) {
	dst[0] = byte(a)
	dst[1] = byte(a >>  8)
	dst[2] = byte(a >> 16)
	dst[3] = byte(a >> 24)
	dst[4] = byte(a >> 32)
	dst[5] = byte(a >> 40)
	dst[6] = byte(a >> 48)
	dst[7] = byte(a >> 56)
	dst[8] = byte(b)
	dst[9] = byte(b >>  8)
	dst[10] = byte(b >> 16)
	dst[11] = byte(b >> 24)
	dst[12] = byte(b >> 32)
	dst[13] = byte(b >> 40)
	dst[14] = byte(b >> 48)
	dst[15] = byte(b >> 56)
}

func putUint64(k uint64) []byte {
	b := make([]byte, 8)
	b[0] = byte(k)
	b[1] = byte(k >>  8)
	b[2] = byte(k >> 16)
	b[3] = byte(k >> 24)
	b[4] = byte(k >> 32)
	b[5] = byte(k >> 40)
	b[6] = byte(k >> 48)
	b[7] = byte(k >> 56)
	return b
}

func rotl64(k uint64, r uint64) uint64 {
	return (k << r) | (k >> (64 - r))
}

func rotr64(k uint64, r uint64) uint64 {
	return (k >> r) | (k << (64 - r))
}

func NewCipher64(key []byte, rounds uint) (cipher.Block, error) {
	// key length in range [0, 2040] bits -> [0, 255] bytes
	if n := len(key); n > 255 {
		return nil, KeySizeError(n)
	}
	return newCipher64(key, rounds)
}

func newCipher64(key []byte, rounds uint) (*cipher64, error) {
	S, T := newKeyTable64(rounds)
	L, LL := bytesToWords64(key, rounds)
	S, T = expandKeyTable64(S, T, L, LL)

    c := cipher64{
    	key,
    	uint(len(key) / 8),
    	rounds,
    	S,
    	T,
    }
    return &c, nil
}

func (c *cipher64) BlockSize() int { return B64 }

func (c *cipher64) Encrypt(dst, src []byte) {
	A, B := get64(src)
	A, B = A + c.S[0], B + c.S[1]

	for i := uint(1); i <= c.R; i++ {
		A = rotl64(A^B, B&63) + c.S[2 * i]
		B = rotl64(B^A, A&63) + c.S[2 * i + 1]
	}

	put64(dst, A, B)
}

func (c *cipher64) Decrypt(dst, src []byte) {
	A, B := get64(src)

	for i := int(c.R); i >= 1; i-- {
		B = rotr64(B - c.S[2 *i + 1], A&63) ^ A
		A = rotr64(A - c.S[2 * i], B&63) ^ B
	}

	B = B - c.S[1]
	A = A - c.S[0]

	put64(dst, A, B)
}

func newKeyTable64(R uint) ([]uint64, uint) {
	T := 2 * (R + 1)
	S := make([]uint64, T)

    S[0] = P64
    for i := uint(1); i < T; i++  {
    	S[i] = S[i-1] + Q64
    }

    return S, T
}

func bytesToWords64(key []byte, blockSize uint) ([]uint64, uint) {
	LL := uint(len(key) / WW64)
	L := make([]uint64, LL)

	for i := uint(0); i < LL; i++ {
		L[i] = getUint64(key[:WW64])
		key = key[WW64:]
	}

	return L, LL
}

func expandKeyTable64(S []uint64, T uint, L []uint64, LL uint) ([]uint64, uint) {
	k := 3 * T
	if (LL > T) {
		k = 3 * LL
	}

	A, B := uint64(0), uint64(0)
	i, j := uint(0), uint(0)

	for ; k > 0; k-- {
        A = rotl64(S[i] + A + B, 3)
        S[i] = A
        B = rotl64(L[j] + A + B, (A + B)&63)
        L[j] = B
        i = (i + 1) % T
        j = (j + 1) % LL
    }

    return S, T
}
