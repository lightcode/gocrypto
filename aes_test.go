package main

import (
	"bytes"
	"testing"
)

var state = randomBytes(192 / 8)

func TestSubBytes(t *testing.T) {
	a := make([]byte, len(state))
	copy(a, state)

	subBytes(a)

	if bytes.Equal(a, state) {
		t.Error("La fonction subBytes n'a rien changé")
	}

	invSubBytes(a)

	if !bytes.Equal(a, state) {
		t.Error("la fonction subBytes n'est pas inversible")
	}
}

func TestShiftRows(t *testing.T) {
	a := make([]byte, len(state))
	copy(a, state)

	shiftRows(a)

	if bytes.Equal(a, state) {
		t.Error("La fonction shiftRows n'a rien changé")
	}

	invShiftRows(a)

	if !bytes.Equal(a, state) {
		t.Error("la fonction shiftRows n'est pas inversible")
	}
}

func TestMixColumns(t *testing.T) {
	a := make([]byte, len(state))
	copy(a, state)

	mixColumns(a)

	if bytes.Equal(a, state) {
		t.Error("La fonction mixColumns n'a rien changé")
	}

	invMixColumns(a)

	if !bytes.Equal(a, state) {
		t.Error("la fonction mixColumns n'est pas inversible")
	}
}

func TestEncryptData(t *testing.T) {
	plain := []byte{15, 19, 87, 13, 46, 43, 1, 2, 3, 4, 5, 6, 7, 8, 9, 8}
	k := randomBytes(256 / 8)
	C := AESEncrypt(plain, k)
	m := AESDecrypt(C, k)

	if !bytes.Equal(m, plain) {
		t.Error("Le texte n'a pas été correctement déchiffrée")
	}
}
