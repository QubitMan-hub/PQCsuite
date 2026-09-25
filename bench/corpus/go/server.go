package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
)

func config() *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS10,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
	}
}

func keys() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func legacyID(b []byte) [20]byte {
	return sha1.Sum(b)
}

func pq() (*mlkem.DecapsulationKey768, error) {
	return mlkem.GenerateKey768()
}
