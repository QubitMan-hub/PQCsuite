package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"os"
)

func main() {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	artifact, _ := os.ReadFile(os.Args[1])
	digest := sha256.Sum256(artifact)
	sig, _ := ecdsa.SignASN1(rand.Reader, key, digest[:])
	os.WriteFile(os.Args[1]+".sig", sig, 0o644)
}
