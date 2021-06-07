// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This header file describes the BoringCrypto ABI as built for use in Go.
// The BoringCrypto build for Go (which generates goboringcrypto_*.syso)
// takes the standard libcrypto.a from BoringCrypto and adds the prefix
// _goboringcrypto_ to every symbol, to avoid possible conflicts with
// code wrapping a different BoringCrypto or OpenSSL.
//
// To make this header standalone (so that building Go does not require
// having a full set of BoringCrypto headers), the struct details are not here.
// Instead, while building the syso, we compile and run a C++ program
// that checks that the sizes match. The program also checks (during compilation)
// that all the function prototypes match the BoringCrypto equivalents.
// The generation of the checking program depends on the declaration
// forms used below (one line for most, multiline for enums).

// Always include our header file, drop the rest.
// This could also be done with an ifdef and a
// flag set during link, but this is simpler since
// we will always want this and can compile it out in
// other ways already.
#if 1
#include "goopenssl.h"
#else

#include <stdlib.h> // size_t
#include <stdint.h> // uint8_t

// This symbol is hidden in BoringCrypto and marked as a constructor,
// but cmd/link's internal linking mode doesn't handle constructors.
// Until it does, we've exported the symbol and can call it explicitly.
// (If using external linking mode, it will therefore be called twice,
// once explicitly and once as a constructor, but that's OK.)
/*unchecked*/ void _goboringcrypto_BORINGSSL_bcm_power_on_self_test(void);

// #include <openssl/crypto.h>
int _goboringcrypto_FIPS_mode(void);
void* _goboringcrypto_OPENSSL_malloc(size_t);

// #include <openssl/digest.h>
/*unchecked (opaque)*/ typedef struct GO_EVP_MD { char data[1]; } GO_EVP_MD;
const GO_EVP_MD* _goboringcrypto_EVP_md4(void);
const GO_EVP_MD* _goboringcrypto_EVP_md5(void);
const GO_EVP_MD* _goboringcrypto_EVP_md5_sha1(void);
const GO_EVP_MD* _goboringcrypto_EVP_sha1(void);
const GO_EVP_MD* _goboringcrypto_EVP_sha224(void);
const GO_EVP_MD* _goboringcrypto_EVP_sha256(void);
const GO_EVP_MD* _goboringcrypto_EVP_sha384(void);
const GO_EVP_MD* _goboringcrypto_EVP_sha512(void);
int _goboringcrypto_EVP_MD_type(const GO_EVP_MD*);
size_t _goboringcrypto_EVP_MD_size(const GO_EVP_MD*);

#endif
