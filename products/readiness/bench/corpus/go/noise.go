package tunnel

import "github.com/flynn/noise"

func handshake() (*noise.HandshakeState, error) {
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)
	return noise.NewHandshakeState(noise.Config{CipherSuite: cs, Pattern: noise.HandshakeIK, Initiator: true})
}

func open(kind string, key []byte) (interface{}, error) {
	switch kind {
	case "AES256":
		return newGCM(key)
	}
	return nil, nil
}
