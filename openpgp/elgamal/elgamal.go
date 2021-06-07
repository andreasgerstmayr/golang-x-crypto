// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package elgamal implements ElGamal encryption, suitable for OpenPGP,
// as specified in "A Public-Key Cryptosystem and a Signature Scheme Based on
// Discrete Logarithms," IEEE Transactions on Information Theory, v. IT-31,
// n. 4, 1985, pp. 469-472.
//
// This form of ElGamal embeds PKCS#1 v1.5 padding, which may make it
// unsuitable for other protocols. RSA should be used in preference in any
// case.
package elgamal // import "golang.org/x/crypto/openpgp/elgamal"

import (
	"io"
	"math/big"
)

// PublicKey represents an ElGamal public key.
type PublicKey struct {
	G, P, Y *big.Int
}

// PrivateKey represents an ElGamal private key.
type PrivateKey struct {
	PublicKey
	X *big.Int
}

// Encrypt encrypts the given message to the given public key. The result is a
// pair of integers. Errors can result from reading random, or because msg is
// too large to be encrypted to the public key.
func Encrypt(random io.Reader, pub *PublicKey, msg []byte) (c1, c2 *big.Int, err error) {
	panic("ElGamal encryption not available")
}

// Decrypt takes two integers, resulting from an ElGamal encryption, and
// returns the plaintext of the message. An error can result only if the
// ciphertext is invalid. Users should keep in mind that this is a padding
// oracle and thus, if exposed to an adaptive chosen ciphertext attack, can
// be used to break the cryptosystem.  See ``Chosen Ciphertext Attacks
// Against Protocols Based on the RSA Encryption Standard PKCS #1'', Daniel
// Bleichenbacher, Advances in Cryptology (Crypto '98),
func Decrypt(priv *PrivateKey, c1, c2 *big.Int) (msg []byte, err error) {
	panic("ElGamal encryption not available")
}

// nonZeroRandomBytes fills the given slice with non-zero random octets.
func nonZeroRandomBytes(s []byte, rand io.Reader) (err error) {
	_, err = io.ReadFull(rand, s)
	if err != nil {
		return
	}

	for i := 0; i < len(s); i++ {
		for s[i] == 0 {
			_, err = io.ReadFull(rand, s[i:i+1])
			if err != nil {
				return
			}
		}
	}

	return
}
