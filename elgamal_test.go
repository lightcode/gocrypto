package main

import (
	"bytes"
	"testing"
)

func TestElgamalEncryption(t *testing.T) {
	keys := GenerateElgamalKeys(160)

	m1 := randomBytes(180 / 8)

	c := ElgamalEncrypt(&keys.ElgamalPublicKey, m1)

	m2 := ElgamalDecrypt(keys, c)

	if !bytes.Equal(m1, m2) {
		t.Error("Le chiffrement/déchiffrement Elgamal a échoué")
	}
}
