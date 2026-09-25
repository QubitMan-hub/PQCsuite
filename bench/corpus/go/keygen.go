package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
)

func newKeys(bits int, c elliptic.Curve) (*rsa.PrivateKey, *ecdsa.PrivateKey, error) {
	r, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	e, err := ecdsa.GenerateKey(c, rand.Reader)
	return r, e, err
}
