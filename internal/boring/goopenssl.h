// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
// +build linux
// +build !android
// +build !no_openssl
// +build !cmd_go_bootstrap
// +build !msan

// This header file describes the OpenSSL ABI as built for use in Go.

#include <stdlib.h> // size_t
#include <stdint.h> // uint8_t

#include <openssl/ossl_typ.h>

#define unlikely(x) __builtin_expect(!!(x), 0)
#define DEFINEFUNC(ret, func, args, argscall)        \
	typedef ret(*_goboringcrypto_PTR_##func) args;   \
	static _goboringcrypto_PTR_##func _g_##func = 0; \
	static inline ret _goboringcrypto_##func args    \
	{                                                \
		if (unlikely(!_g_##func))                    \
		{                                            \
			_g_##func = dlsym(handle, #func);        \
		}                                            \
		return _g_##func argscall;                   \
	}

#define DEFINEFUNCINTERNAL(ret, func, args, argscall)        \
	typedef ret(*_goboringcrypto_internal_PTR_##func) args;   \
	static _goboringcrypto_internal_PTR_##func _g_internal_##func = 0; \
	static inline ret _goboringcrypto_internal_##func args    \
	{                                                \
		if (unlikely(!_g_internal_##func))                    \
		{                                            \
			_g_internal_##func = dlsym(handle, #func);        \
		}                                            \
		return _g_internal_##func argscall;                   \
	}

#define DEFINEMACRO(ret, func, args, argscall)    \
	static inline ret _goboringcrypto_##func args \
	{                                             \
		return func argscall;                     \
	}

#include <dlfcn.h>

static void* handle;
static void*
_goboringcrypto_DLOPEN_OPENSSL(void)
{
	if (handle)
	{
		return handle;
	}
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	handle = dlopen("libcrypto.so.10", RTLD_NOW | RTLD_GLOBAL);
#else
	handle = dlopen("libcrypto.so.1.1", RTLD_NOW | RTLD_GLOBAL);
#endif
	return handle;
}

#include <openssl/opensslv.h>
#include <openssl/ssl.h>

DEFINEFUNCINTERNAL(int, OPENSSL_init, (void), ())

static void
_goboringcrypto_OPENSSL_setup(void) {
	_goboringcrypto_internal_OPENSSL_init();
}

#include <openssl/err.h>
DEFINEFUNCINTERNAL(void, ERR_print_errors_fp, (FILE* fp), (fp))
DEFINEFUNCINTERNAL(unsigned long, ERR_get_error, (void), ())
DEFINEFUNCINTERNAL(void, ERR_error_string_n, (unsigned long e, unsigned char *buf, size_t len), (e, buf, len))

#include <openssl/crypto.h>

DEFINEFUNCINTERNAL(int, CRYPTO_num_locks, (void), ())
static inline int
_goboringcrypto_CRYPTO_num_locks(void) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	return _goboringcrypto_internal_CRYPTO_num_locks();
#else
	return CRYPTO_num_locks();
#endif
}
DEFINEFUNCINTERNAL(void, CRYPTO_set_id_callback, (unsigned long (*id_function)(void)), (id_function))
static inline void
_goboringcrypto_CRYPTO_set_id_callback(unsigned long (*id_function)(void)) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	_goboringcrypto_internal_CRYPTO_set_id_callback(id_function);
#else
	CRYPTO_set_id_callback(id_function);
#endif
}
DEFINEFUNCINTERNAL(void, CRYPTO_set_locking_callback,
	(void (*locking_function)(int mode, int n, const char *file, int line)), 
	(locking_function))
static inline void
_goboringcrypto_CRYPTO_set_locking_callback(void (*locking_function)(int mode, int n, const char *file, int line)) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	_goboringcrypto_internal_CRYPTO_set_locking_callback(locking_function);
#else
	CRYPTO_set_locking_callback(locking_function);
#endif
}

int _goboringcrypto_OPENSSL_thread_setup(void);

DEFINEFUNC(int, FIPS_mode, (void), ())
DEFINEFUNC(int, FIPS_mode_set, (int r), (r))

#include <openssl/evp.h>

typedef EVP_MD GO_EVP_MD;
DEFINEFUNC(const GO_EVP_MD *, EVP_md4, (void), ())
DEFINEFUNC(const GO_EVP_MD *, EVP_md5, (void), ())
DEFINEFUNC(const GO_EVP_MD *, EVP_sha1, (void), ())
DEFINEFUNC(const GO_EVP_MD *, EVP_sha224, (void), ())
DEFINEFUNC(const GO_EVP_MD *, EVP_sha256, (void), ())
DEFINEFUNC(const GO_EVP_MD *, EVP_sha384, (void), ())
DEFINEFUNC(const GO_EVP_MD *, EVP_sha512, (void), ())
DEFINEFUNC(int, EVP_MD_type, (const GO_EVP_MD *arg0), (arg0))
DEFINEFUNCINTERNAL(size_t, EVP_MD_size, (const GO_EVP_MD *arg0), (arg0))
DEFINEFUNCINTERNAL(const GO_EVP_MD*, EVP_md5_sha1, (void), ())

DEFINEFUNC(int, PKCS5_PBKDF2_HMAC,
    (const char *pass, int passlen, const unsigned char *salt, int saltlen, int iter, EVP_MD *digest, int keylen, unsigned char *out),
    (pass, passlen, salt, saltlen, iter, digest, keylen, out))
