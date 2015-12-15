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

func TestElgamalKeyStorage(t *testing.T) {
	priv := GenerateElgamalKeys(160)
	pub := priv.ElgamalPublicKey

	// Test avec la clé publique
	tpub := LoadPublicKey(pub.GetBytes())
	if tpub.Q.Cmp(pub.Q) != 0 || tpub.H.Cmp(pub.H) != 0 || tpub.G.Cmp(pub.G) != 0 {
		t.Error("Les deux clés publiques ne sont pas égales.")
	}

	// Test de la clé privée
	tpriv := LoadPrivateKey(priv.GetBytes())
	if tpriv.Q.Cmp(priv.Q) != 0 || tpriv.H.Cmp(priv.H) != 0 || tpriv.G.Cmp(priv.G) != 0 || tpriv.X.Cmp(priv.X) != 0 {
		t.Error("Les deux clés privées ne sont pas égales.")
	}

}
