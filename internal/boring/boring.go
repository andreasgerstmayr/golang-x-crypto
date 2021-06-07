// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux
// +build !android
// +build !no_openssl
// +build !cmd_go_bootstrap
// +build !msan

package boring

// #include "goboringcrypto.h"
// #cgo LDFLAGS: -ldl
import "C"
import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"hash"
	"os"
	"runtime"
)

const (
	fipsOn  = C.int(1)
	fipsOff = C.int(0)
)

// Enabled controls whether FIPS crypto is enabled.
var enabled = false

// When this variable is true, the go crypto API will panic when a caller
// tries to use the API in a non-compliant manner.  When this is false, the
// go crytpo API will allow existing go crypto APIs to be used even
// if they aren't FIPS compliant.  However, all the unerlying crypto operations
// will still be done by OpenSSL.
var strictFIPS = false

func init() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Check if we can `dlopen` OpenSSL
	if C._goboringcrypto_DLOPEN_OPENSSL() == C.NULL {
		return
	}

	// Initialize the OpenSSL library.
	C._goboringcrypto_OPENSSL_setup()

	// Check to see if the system is running in FIPS mode, if so
	// enable "boring" mode to call into OpenSSL for FIPS compliance.
	if fipsModeEnabled() {
		enableBoringFIPSMode()
	}
	//sig.BoringCrypto()
}

func enableBoringFIPSMode() {
	enabled = true

	if C._goboringcrypto_OPENSSL_thread_setup() != 1 {
		panic("boringcrypto: OpenSSL thread setup failed")
	}
	//fipstls.Force()
}

func fipsModeEnabled() bool {
	return os.Getenv("GOLANG_FIPS") == "1" ||
		C._goboringcrypto_FIPS_mode() == fipsOn
}

var (
	emptySha1   = sha1.Sum([]byte{})
	emptySha256 = sha256.Sum256([]byte{})
)

func hashToMD(h hash.Hash) *C.GO_EVP_MD {
	emptyHash := h.Sum([]byte{})

	switch {
	case bytes.Equal(emptyHash, emptySha1[:]):
		return C._goboringcrypto_EVP_sha1()
	case bytes.Equal(emptyHash, emptySha256[:]):
		return C._goboringcrypto_EVP_sha256()
	}
	return nil
}
