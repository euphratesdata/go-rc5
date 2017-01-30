// Copyright 2017 Marc Wilson, Scorpion Compute. All rights
// reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

package rc5

import (
	"crypto/cipher"
)

const (
	W32 		= 32		// word size in bits
	WW32		= W32 / 8 	// word size in bytes
	B32 		= 64 		// block size in bits
	BB32 		= B32 / 8 	// block size in bytes
	P32			= 0xb7e15163
  	Q32 		= 0x9e3779b9
)

type cipher32 struct {
	K 				[]byte 			// secret key
	b 				uint 			// byte length of secret key
	R 				uint 			// number of rounds
	S 				[]uint32 		// expanded key table
	T 				uint 			// number of words in expanded key table
}

func getUint32(b []byte) uint32 {
	return uint32(b[0]) 	   |
		   uint32(b[1]) <<   8 |
		   uint32(b[2]) <<  16 |
		   uint32(b[3]) <<  24
}

func get32(b []byte) (uint32, uint32) {
	return getUint32(b[:4]), getUint32(b[4:])
}

func put32(dst[] byte, a uint32, b uint32) {
	dst[0] = byte(a)
	dst[1] = byte(a >>  8)
	dst[2] = byte(a >> 16)
	dst[3] = byte(a >> 24)
	dst[4] = byte(b)
	dst[5] = byte(b >>  8)
	dst[6] = byte(b >> 16)
	dst[7] = byte(b >> 24)
}

func putUint32(k uint32) []byte {
	b := make([]byte, 4)
	b[0] = byte(k)
	b[1] = byte(k >>  8)
	b[2] = byte(k >> 16)
	b[3] = byte(k >> 24)
	return b
}

func rotl32(k uint32, r uint32) uint32 {
	return (k << r) | (k >> (32 - r))
}

func rotr32(k uint32, r uint32) uint32 {
	return (k >> r) | (k << (32 - r))
}

func NewCipher32(key []byte, rounds uint) (cipher.Block, error) {
	// key length in range [0, 2040] bits -> [0, 255] bytes
	if n := len(key); n > 255 {
		return nil, KeySizeError(n)
	}
	return newCipher32(key, 12)
}

func newCipher32(key []byte, rounds uint) (*cipher32, error) {
	S, T := newKeyTable32(rounds)
	L, LL := bytesToWords32(key, rounds)
	S, T = expandKeyTable32(S, T, L, LL)

    c := cipher32{
    	key,
    	uint(len(key) / 8),
    	rounds,
    	S,
    	T,
    }
    return &c, nil
}

func (c *cipher32) BlockSize() int { return B32 }

func (c *cipher32) Encrypt(dst, src []byte) {
	A, B := get32(src)
	A, B = A + c.S[0], B + c.S[1]

	for i := uint(1); i <= c.R; i++ {
		A = rotl32(A^B, B&31) + c.S[2 * i]
		B = rotl32(B^A, A&31) + c.S[2 * i + 1]
	}

	put32(dst, A, B)
}

func (c *cipher32) Decrypt(dst, src []byte) {
	A, B := get32(src)

	for i := int(c.R); i >= 1; i-- {
		B = rotr32(B - c.S[2 *i + 1], A&31) ^ A
		A = rotr32(A - c.S[2 * i], B&31) ^ B
	}

	B = B - c.S[1]
	A = A - c.S[0]

	put32(dst, A, B)
}

func newKeyTable32(R uint) ([]uint32, uint) {
	T := 2 * (R + 1)
	S := make([]uint32, T)

    S[0] = P32
    for i := uint(1); i < T; i++  {
    	S[i] = S[i-1] + Q32
    }

    return S, T
}

func bytesToWords32(key []byte, blockSize uint) ([]uint32, uint) {
	LL := uint(len(key) / WW32)
	L := make([]uint32, LL)

	for i := uint(0); i < LL; i++ {
		L[i] = getUint32(key[:WW32])
		key = key[WW32:]
	}

	return L, LL
}

func expandKeyTable32(S []uint32, T uint, L []uint32, LL uint) ([]uint32, uint) {
	k := 3 * T
	if (LL > T) {
		k = 3 * LL
	}

	A, B := uint32(0), uint32(0)
	i, j := uint(0), uint(0)

	for ; k > 0; k-- {
        A = rotl32(S[i] + A + B, 3)
        S[i] = A
        B = rotl32(L[j] + A + B, (A + B)&31)
        L[j] = B
        i = (i + 1) % T
        j = (j + 1) % LL
    }

    return S, T
}
