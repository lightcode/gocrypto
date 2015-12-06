package main

import (
	"testing"
)

func TestSubBytes(t *testing.T) {
	a := []byte{0x52, 0x59, 0x6A, 0xD5, 0x30}
	b := make([]byte, len(a))
	copy(b, a)

	subBytes(a)

	if CompareSlice(a, b) {
		t.Error("La fonction subBytes n'a rien changé")
	}

	invSubBytes(a)

	if !CompareSlice(a, b) {
		t.Error("la fonction subBytes n'est pas inversible")
	}
}

func TestShiftRows(t *testing.T) {
	a := []byte{34, 34, 1, 3, 5, 43, 34, 32, 67, 12, 14, 16, 18, 234, 236, 43}
	b := make([]byte, len(a))
	copy(b, a)

	shiftRows(a)

	if CompareSlice(a, b) {
		t.Error("La fonction shiftRows n'a rien changé")
	}

	invShiftRows(a)

	if !CompareSlice(a, b) {
		t.Error("la fonction shiftRows n'est pas inversible")
	}
}

func TestMixColumns(t *testing.T) {
	a := []byte{0xdb, 0x13, 0x53, 0x45, 5, 43, 34, 32, 67, 12, 14, 16, 18, 234, 236, 43}
	b := make([]byte, len(a))
	copy(b, a)

	mixColumns(a)

	if CompareSlice(a, b) {
		t.Error("La fonction mixColumns n'a rien changé")
	}

	invMixColumns(a)

	if !CompareSlice(a, b) {
		t.Error("la fonction mixColumns n'est pas inversible")
	}
}

func TestEncryptData(t *testing.T) {
	plain := []byte{15, 19, 87, 13, 46, 43, 1, 2, 3, 4, 5, 6, 7, 8, 9, 8}
	k := randomBytes(256 / 8)
	C := AESEncrypt(plain, k)
	m := AESDecrypt(C, k)

	if !CompareSlice(m, plain) {
		t.Error("Le texte n'a pas été correctement déchiffrée")
	}
}

func TestEncryptBlock(t *testing.T) {
	a := []byte{34, 34, 1, 3, 5, 43, 34, 32, 67, 12, 14, 16, 18, 234, 236, 43}
	k := []byte{12, 14, 16, 18, 234, 236, 43, 34, 34, 1, 3, 5, 43, 34, 32, 67}

	b := make([]byte, len(a))
	copy(b, a)

	encryptBlock(a, k)

	if CompareSlice(a, b) {
		t.Error("La fonction encryptBlock n'a rien changé")
	}

	decryptBlock(a, k)

	if !CompareSlice(a, b) {
		t.Error("la fonction encryptBlock n'est pas inversible")
	}
}
