// Copyright 2017 Marc Wilson, Scorpion Compute. All rights
// reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

package rc5

import (
	"strconv"
)

type KeySizeError int

func (k KeySizeError) Error() string {
	return "scorpioncompute.com/rc5: invalid key size " + strconv.Itoa(int(k))
}
