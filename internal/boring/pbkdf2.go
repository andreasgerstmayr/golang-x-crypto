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
import "C"
import (
	"fmt"
	"hash"
	"unsafe"
)

func Pbkdf2Key(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	fmt.Printf("fips active\n")
	ch := h()
	md := hashToMD(ch)
	if md == nil {
		return nil
	}

	out := make([]byte, keyLen)
	C._goboringcrypto_PKCS5_PBKDF2_HMAC((*C.char)(unsafe.Pointer(&password[0])), C.int(len(password)), (*C.uchar)(unsafe.Pointer(&salt[0])), C.int(len(salt)), C.int(iter), md, C.int(keyLen), (*C.uchar)(unsafe.Pointer(&out[0])))
	return out
}
