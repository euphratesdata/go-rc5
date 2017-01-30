// Copyright 2017 Marc Wilson, Scorpion Compute. All rights
// reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

package rc5

import (
	"bytes"
	"testing"
	"math/rand"
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
