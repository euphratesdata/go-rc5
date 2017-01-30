// Copyright 2017 Marc Wilson, Scorpion Compute. All rights
// reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.
	
package rc5

import (
	"bytes"
	"math/big"
	"math/rand"
	"testing"
)

func TestCipherBig32(t *testing.T) {
	random := rand.New(rand.NewSource(99))
	max := 500

	rounds := uint(12)
	wordSize := uint(32)

	encrypted := make([]byte, 8)
	encryptedBig := make([]byte, 8)
	decrypted := make([]byte, 8)
	decryptedBig := make([]byte, 8)

	key := make([]byte, 16)
	value := make([]byte, 8)
	for i := 0; i < max; i++ {
    	random.Read(key)
    	random.Read(value)

    	cipher32, _ := NewCipher32(key, rounds)
    	cipherBig, _ := NewCipherBig(key, rounds, wordSize)

		cipher32.Encrypt(encrypted, value)
		cipherBig.Encrypt(encryptedBig, value)

		if !bytes.Equal(encrypted, encryptedBig) {
			t.Errorf("encrypt failed: % 02x != % 02x\n", encrypted, encryptedBig)	
		}

		cipher32.Decrypt(decrypted, encrypted)
		cipherBig.Decrypt(decryptedBig, encryptedBig)

		if !bytes.Equal(decrypted, value) {
			t.Errorf("cipher32.Decrypt failed: % 02x != % 02x\n", decrypted, value)	
		}

		if !bytes.Equal(decryptedBig, value) {
			t.Errorf("cipherBig.Decrypt failed: % 02x != % 02x\n", decryptedBig, value)	
		}
	}
}

func TestCipherBig64(t *testing.T) {
	random := rand.New(rand.NewSource(99))
	max := 500

	rounds := uint(12)
	wordSize := uint(64)

	encrypted := make([]byte, 16)
	encryptedBig := make([]byte, 16)
	decrypted := make([]byte, 16)
	decryptedBig := make([]byte, 16)

	key := make([]byte, 32)
	value := make([]byte, 16)
	for i := 0; i < max; i++ {
    	random.Read(key)
    	random.Read(value)

    	cipher64, _ := NewCipher64(key, rounds)
    	cipherBig, _ := NewCipherBig(key, rounds, wordSize)

		cipher64.Encrypt(encrypted, value)
		cipherBig.Encrypt(encryptedBig, value)

		if !bytes.Equal(encrypted, encryptedBig) {
			t.Errorf("encrypt failed: % 02x != % 02x\n", encrypted, encryptedBig)	
		}
		
		cipher64.Decrypt(decrypted, encrypted)
		cipherBig.Decrypt(decryptedBig, encryptedBig)

		if !bytes.Equal(decrypted, value) {
			t.Errorf("cipher64.Decrypt failed: % 02x != % 02x\n", decrypted, value)	
		}

		if !bytes.Equal(decryptedBig, value) {
			t.Errorf("cipherBig.Decrypt failed: % 02x != % 02x\n", decryptedBig, value)	
		}
	}
}

func TestP(t *testing.T) {
	var p_values = []struct {
		w uint
		p *big.Int
	} {
		{16, new(big.Int).SetUint64(0xB7E1)},
		{32, new(big.Int).SetUint64(0xB7E15163)},
		{64, new(big.Int).SetUint64(0xB7E151628AED2A6B)},
	}
	
	for _, value := range p_values {
		Pw := p(value.w)
		if Pw.Cmp(value.p) != 0 {
			d := new(big.Int)
			d.Sub(Pw, value.p)
			t.Errorf("p(%v) == %s, want %d. Diff: %d", value.w, Pw, value.p, d)	
		}
	}
}

func TestQ(t *testing.T) {
	var q_values = []struct {
		w uint
		q *big.Int
	} {
		{16, new(big.Int).SetUint64(0x9E37)},
		{32, new(big.Int).SetUint64(0x9E3779B9)},
		{64, new(big.Int).SetUint64(0x9E3779B97F4A7C15)},
	}

	for _, value := range q_values {
		Qw := q(value.w)
		if Qw.Cmp(value.q) != 0 {
			d := new(big.Int)
			d.Sub(Qw, value.q)
			t.Errorf("q(%v) == %s, want %d. Diff: %d", value.w, Qw, value.q, d)
		}
	}
}
