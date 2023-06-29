// Copyright 2017 Marc Wilson, Scorpion Compute. All rights
// reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

package rc5

import (
	"crypto/cipher"
	"math/big"

	"github.com/euphratesdata/go-bigmath"
)

var one = big.NewInt(1)
var two = big.NewInt(2)

func p(w uint) *big.Int {
	b := make([]byte, uint(w / 8) + 1)
	b[0] = 1
	e := bigmath.E(100)
	e.Sub(e, big.NewRat(2, 1))
	e.Mul(e, new(big.Rat).SetInt(new(big.Int).SetBytes(b)))
	return bigmath.Odd(bigmath.Floor(e))
}

func q(w uint) *big.Int {
	b := make([]byte, uint(w / 8) + 1)
	b[0] = 1
	phi := bigmath.Phi(2000)
	phi.Sub(phi, big.NewRat(1, 1))
	phi.Mul(phi, new(big.Rat).SetInt(new(big.Int).SetBytes(b)))
	return bigmath.Odd(bigmath.Floor(phi))
}

type cipherBig struct {
	K 				[]byte 			// secret key
	b 				uint 			// byte length of secret key
	R 				uint 			// number of rounds
	S 				[]*big.Int 		// expanded key table
	T 				uint 			// number of words in expanded key table
	W 				uint			// word size in bits
	WW				uint 		 	// word size in bytes
	B 				uint			// block size in bits
	BB 				uint 			// block size in bytes
	ROTL 			rot 			// rotate left method
	ROTR 			rot 			// rotate right method
	MASK 			*big.Int 		// bit mask
}

type rot func(*big.Int, uint) *big.Int

func NewCipherBig(key []byte, rounds uint, wordSize uint) (cipher.Block, error) {
	// key length in range [0, 2040] bits -> [0, 255] bytes
	if n := len(key); n > 255 {
		return nil, KeySizeError(n)
	}
	return newCipherBig(key, rounds, wordSize)
}

func newCipherBig(key []byte, rounds uint, wordSize uint) (*cipherBig, error) {
	b := uint(len(key))
	ROTL, ROTR := newRotate(wordSize)
	W := wordSize
	WW := W / 8
	S, T := newKeyTable(rounds, wordSize)
	L, LL := bytesToWords(key, WW)
	S, T = expandKeyTable(S, T, L, LL, ROTL, wordSize)
	MASK := bigmath.Mask(wordSize)

    cipher :=cipherBig {
    	key,
    	b,
    	rounds,
    	S,
    	T,
    	wordSize,
    	wordSize / 8,
    	2 * wordSize,
    	2 * wordSize / 8,
    	ROTL,
    	ROTR,
    	MASK,
    }

    return &cipher, nil
}

func (c *cipherBig) BlockSize() int { return int(c.B) }

func (c *cipherBig) Encrypt(dst, src []byte) {
	SRC := make([]byte, len(src))
	copy(SRC, src)

	A := new(big.Int).SetBytes(reverse(SRC[:c.WW]))
	A.Add(A, c.S[0]).And(A, c.MASK)
	B := new(big.Int).SetBytes(reverse(SRC[c.WW:]))
	B.Add(B, c.S[1]).And(B, c.MASK)

	for i := 1; i <= int(c.R); i++ {
		A = A.Xor(A, B)
		A = c.ROTL(A, uint(B.Uint64())&(c.W - 1))
		A.Add(A, c.S[2 * i])
		B = B.Xor(B, A)
		B = c.ROTL(B, uint(A.Uint64())&(c.W - 1))
		B.Add(B, c.S[2 * i + 1])
	}
	
	DST := make([]byte, len(SRC))
	copy(DST[:c.WW], reverse(A.Bytes()))
	copy(DST[c.WW:], reverse(B.Bytes()))
	copy(dst, DST)
}

func (c *cipherBig) Decrypt(dst, src []byte) {
	SRC := make([]byte, len(src))
	copy(SRC, src)

	A := new(big.Int).SetBytes(reverse(SRC[:c.WW]))
	B := new(big.Int).SetBytes(reverse(SRC[c.WW:]))

	for i := int(c.R); i >= 1; i-- {
		B.Sub(B, c.S[2 * i + 1])
		B = c.ROTR(B, uint(A.Uint64())&(c.W - 1))
		B = B.Xor(B, A)
		A.Sub(A, c.S[2 * i])
		A = c.ROTR(A, uint(B.Uint64())&(c.W - 1))
		A = A.Xor(A, B)
	}

	A.Sub(A, c.S[0]).And(A, c.MASK)
	B.Sub(B, c.S[1]).And(B, c.MASK)

	DST := make([]byte, len(SRC))
	copy(DST[:c.WW], reverse(A.Bytes()))
	copy(DST[c.WW:], reverse(B.Bytes()))
	copy(dst, DST)
}

func newKeyTable(R uint, W uint) ([]*big.Int, uint) {
	P := p(W)
	Q := q(W)
	M := new(big.Int).Lsh(one, W)
	T := 2 * (R + 1)
	S := make([]*big.Int, T)

    S[0] = P
    for i := uint(1); i < T; i++  {
    	m := new(big.Int).Add(S[i-1], Q)
    	S[i] = m.Mod(m, M)
    }

    return S, T
}

func newRotate(s uint) (rot, rot) {
	mask := bigmath.Mask(s)

	left := func(i *big.Int, r uint) *big.Int {
		return bigmath.RotateLeft(i, r, s, mask)
	}

	right := func(i *big.Int, r uint) *big.Int {
		return bigmath.RotateRight(i, r, s, mask)
	}

	return left, right
}

func deepCopy(src []*big.Int) []*big.Int {
	dst := make([]*big.Int, len(src))
	for i := 0; i < len(src); i++ {
		dst[i] = new(big.Int).Set(src[i])
	}
	return dst
}

func reverse(bytes []byte) []byte {
	length := len(bytes)
	for i := 0; i < length / 2; i++ {
		j := length - i - 1
		bytes[i], bytes[j] = bytes[j], bytes[i]
	}
	return bytes
}

func bytesToWords(key []byte, WW uint) ([]*big.Int, uint) {
	LL := uint(len(key)) / WW
	K := make([]byte, len(key))
	copy(K, key)
	L := make([]*big.Int, LL)
	for i := uint(0); i < LL; i++ {
		L[i] = new(big.Int).SetBytes(reverse(K[:WW]))
		K = K[WW:]
	}

	return L, LL
}

func expandKeyTable(S []*big.Int, T uint, L []*big.Int, LL uint, ROTL rot, W uint) ([]*big.Int, uint) {
	k := 3 * T
	if (LL > T) {
		k = 3 * LL
	}

    A := big.NewInt(0)
	B := big.NewInt(0)
	i, j := uint(0), uint(0)

	for ; k > 0; k-- {
		S[i] = ROTL(S[i].Add(S[i], A).Add(S[i], B), 3)
		A = new(big.Int).Set(S[i])
        L[j] = ROTL(L[j].Add(L[j], A).Add(L[j], B), uint(A.Uint64() + B.Uint64())&(W - 1))
        B = new(big.Int).Set(L[j])
        i = (i + 1) % T;
        j = (j + 1) % LL;
	}

	return S, T
}
