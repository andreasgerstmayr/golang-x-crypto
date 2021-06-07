// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !linux !cgo android cmd_go_bootstrap msan no_openssl

package boring

import (
	"crypto/internal/boring/sig"
	"hash"
)

var enabled = false

// Unreachable marks code that should be unreachable
// when BoringCrypto is in use. It is a no-op without BoringCrypto.
func Unreachable() {
	// Code that's unreachable when using BoringCrypto
	// is exactly the code we want to detect for reporting
	// standard Go crypto.
	sig.StandardCrypto()
}

// UnreachableExceptTests marks code that should be unreachable
// when BoringCrypto is in use. It is a no-op without BoringCrypto.
func UnreachableExceptTests() {}

// This is a noop withotu BoringCrytpo.
func PanicIfStrictFIPS(v interface{}) {}

func Pbkdf2Key(password, salt []byte, iter, keyLen int, h func() hash.Hash) error {
	panic("boringcrypto: not available")
}
