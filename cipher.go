// Copyright 2017 Marc Wilson, Scorpion Compute. All rights
// reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

package rc5

import "crypto/cipher"

func NewCipher(key []byte, rounds uint, wordSize uint) (cipher.Block, error) {
	// key length in range [0, 2040] bits -> [0, 255] bytes
	if n := len(key); n > 255 {
		return nil, KeySizeError(n)
	}

	switch wordSize {
		case 16:
		    return newCipher16(key, rounds)
		case 32:
		    return newCipher32(key, rounds)
		case 64:
		    return newCipher64(key, rounds)
		default:
		    return newCipherBig(key, rounds, wordSize)
	}
}