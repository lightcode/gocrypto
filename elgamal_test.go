package main

import (
	"bytes"
	"testing"
)

func TestElgamalEncryption(t *testing.T) {
	keys := GenerateElgamalKeys(160)

	m := make([][]byte, 2)
	m[0] = randomBytes(180 / 8)
	m[1] = []byte{0, 0, 54, 89, 75, 31, 0, 0, 0}

	for _, m1 := range m {
		c := ElgamalEncrypt(&keys.ElgamalPublicKey, m1)

		m2 := ElgamalDecrypt(keys, c)

		if !bytes.Equal(m1, m2) {
			t.Error("Le chiffrement/déchiffrement Elgamal a échoué")
		}
	}
}
