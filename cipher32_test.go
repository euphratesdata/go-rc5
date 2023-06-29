// Copyright 2017 Marc Wilson, Scorpion Compute. All rights
// reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

package rc5

import (
	"bytes"
	"encoding/hex"
	"math/rand"
	"testing"
)

const (
	encKey        = "30D5DDB906436F6D3C5B21FCCC2B6A3B30D5DDB9"
	plainData     = "010000000000000000804200626F743083626F7400000000CB5257151757F728FD704666598D4A730000000000000007"
	encryptedData = "4D840AB1DD57828AD4DD25DF8EE253009622FC479AE35A2A085181144C4E32B6EED1CE0666A649B50473E6D49DECEE94"
)

func TestCipher32(t *testing.T) {
	random := rand.New(rand.NewSource(99))
	max := 5000

	var encrypted [8]byte
	var decrypted [8]byte

	for i := 0; i < max; i++ {
		key := make([]byte, 16)
		random.Read(key)
		value := make([]byte, 8)
		random.Read(value)

		cipher, _ := NewCipher32(key, 12)

		cipher.Encrypt(encrypted[:], value)
		cipher.Decrypt(decrypted[:], encrypted[:])

		if !bytes.Equal(decrypted[:], value[:]) {
			t.Errorf("encryption/decryption failed: % 02x != % 02x\n", decrypted, value)
		}
	}
}

func TestCipher32Known(t *testing.T) {

	var (
		key, _       = hex.DecodeString(encKey)
		plain, _     = hex.DecodeString(plainData)
		encrypted, _ = hex.DecodeString(encryptedData)

		cipher, _ = NewCipher32(key, 16)

		cipherText = make([]uint8, len(plain))
		plainText  = make([]uint8, len(plain))
	)

	for i := 0; i < len(plain); i += 8 {
		cipher.Encrypt(cipherText[i:i+8], plain[i:i+8])
	}

	for i := 0; i < len(encrypted); i += 8 {
		cipher.Decrypt(plainText[i:i+8], encrypted[i:i+8])
	}

	if !bytes.Equal(encrypted, cipherText) {
		t.Errorf("encryption failed: %X != %s\n", cipherText, encryptedData)
	}

	if !bytes.Equal(plain, plainText) {
		t.Errorf("decryption failed: %X != %s\n", plainText, plainData)
	}

}
