package main

import (
	"bytes"
	"testing"
)

func TestElgamalEncryption(t *testing.T) {
	pair := GenerateElgamalKeyPair(160)

	m1 := randomBytes(180 / 8)

	c := ElgamalEncrypt(&pair.ElgamalPublicKey, m1)

	m2 := ElgamalDecrypt(pair, c)

	if !bytes.Equal(m1, m2) {
		t.Error("Le chiffrement/déchiffrement Elgamal a échoué")
	}
}
