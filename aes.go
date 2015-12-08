package main

import "fmt"

// Effectue un XOR bit à bit entre le block et la clé
func addRoundKey(b, k []byte) {
	for i := range b {
		b[i] = k[i] ^ b[i]
	}
}

// Substitue un octet par un autre en suivant la
// Rijndael S-box
func subByte(b byte) byte {
	return sbox[b]
}

// Effectue les substitutions avec subByte sur tous
// les bytes du tableau
func subBytes(b []byte) {
	for i := range b {
		b[i] = subByte(b[i])
	}
}

// Inverse la substitution effectué avec la Rijndael S-box
func invSubByte(b byte) byte {
	return inv_sbox[b]
}

// Inverse de la fonction subBytes
func invSubBytes(b []byte) {
	for i := range b {
		b[i] = invSubByte(b[i])
	}
}

// Mélange les lignes du state
func shiftRows(b []byte) {
	b[4], b[5], b[6], b[7] = b[5], b[6], b[7], b[4]
	b[8], b[9], b[10], b[11] = b[10], b[11], b[8], b[9]
	b[12], b[13], b[14], b[15] = b[15], b[12], b[13], b[14]
}

// Inverse de la fonction shiftRows
func invShiftRows(b []byte) {
	b[5], b[6], b[7], b[4] = b[4], b[5], b[6], b[7]
	b[10], b[11], b[8], b[9] = b[8], b[9], b[10], b[11]
	b[15], b[12], b[13], b[14] = b[12], b[13], b[14], b[15]
}

// Effectue la multiplication dans le corps de Rijndael
func gmul(a, b byte) byte {
	var p byte
	var hiBitSet byte

	for i := 0; i < 8; i++ {
		if (b & 1) != 0 {
			p ^= a
		}
		hiBitSet = a & 0x80
		a <<= 1
		if hiBitSet != 0 {
			a ^= 0x1b // x^8 + x^4 + x^3 + x + 1
		}
		b >>= 1
	}
	return p
}

// Mélange les colonnes du block
func mixColumns(b []byte) {
	var a = make([]byte, len(b))

	for i := 0; i < 4; i++ {
		a[i] = gmul(2, b[i]) ^ gmul(3, b[i+4]) ^ b[i+8] ^ b[i+12]
		a[i+4] = b[i] ^ gmul(2, b[i+4]) ^ gmul(3, b[i+8]) ^ b[i+12]
		a[i+8] = b[i] ^ b[i+4] ^ gmul(2, b[i+8]) ^ gmul(3, b[i+12])
		a[i+12] = gmul(3, b[i]) ^ b[i+4] ^ b[i+8] ^ gmul(2, b[i+12])
	}

	copy(b, a)
}

// Inverse de la fonction mixColumns
func invMixColumns(b []byte) {
	var a = make([]byte, len(b))
	for i := 0; i < 4; i++ {
		a[i] = gmul(14, b[i]) ^ gmul(11, b[i+4]) ^ gmul(13, b[i+8]) ^ gmul(9, b[i+12])
		a[i+4] = gmul(9, b[i]) ^ gmul(14, b[i+4]) ^ gmul(11, b[i+8]) ^ gmul(13, b[i+12])
		a[i+8] = gmul(13, b[i]) ^ gmul(9, b[i+4]) ^ gmul(14, b[i+8]) ^ gmul(11, b[i+12])
		a[i+12] = gmul(11, b[i]) ^ gmul(13, b[i+4]) ^ gmul(9, b[i+8]) ^ gmul(14, b[i+12])
	}
	copy(b, a)
}

// Génère les différentes sous-clés
func keyExpansion(key []byte, nr int) []byte {
	finalKey := make([]byte, nr*len(key))
	for i := range finalKey {
		finalKey[i] = subByte(key[i%len(key)])
	}
	return finalKey
}

// Chiffre un block de 128 bits de text en clair
func encryptBlock(block, key []byte) {
	var currentKey []byte

	// Taille de la clé en octet
	keySize := len(key)

	// Vérifie que le block a une taille de 16 octets (128 bits)
	if len(block) != 16 {
		panic(fmt.Sprintf("Wrong size of plaintext block (must be 128, not %d bits)", len(block)*8))
	}

	// Vérifie que la clé fait bien 128, 196 ou 256 bits
	switch keySize * 8 {
	case 128, 196, 256:
		break
	default:
		panic(fmt.Sprintf("Wrong size of key (%d bits)", len(key)*8))
	}

	// Calcul le nombre de colonne de la matrice
	nk := len(key) / 4

	// Cacule le nombre de tournées nr
	nr := 6 + nk

	// Génère toutes les clés
	roundKeys := keyExpansion(key, nr)

	// Applique la première clé sur la block
	key0 := subKey(roundKeys, 0, keySize)
	addRoundKey(block, key0)

	for i := 1; i < nr; i++ {
		subBytes(block)
		shiftRows(block)
		mixColumns(block)
		currentKey = subKey(roundKeys, i, keySize)
		addRoundKey(block, currentKey)
	}

	// Dernière tournée
	subBytes(block)
	shiftRows(block)
	lastKey := subKey(roundKeys, nr-1, keySize)
	addRoundKey(block, lastKey)
}

// Déchiffre un block de 128 bits
func decryptBlock(block, key []byte) {
	var currentKey []byte

	// Taille de la clé en octet
	keySize := len(key)

	// Vérifie que le block a une taille de 16 octets (128 bits)
	if len(block) != 16 {
		panic(fmt.Sprintf("Wrong size of plaintext block (must be 128, not %d bits)", len(block)*8))
	}

	// Vérifie que la clé fait bien 128, 196 ou 256 bits
	switch keySize * 8 {
	case 128, 196, 256:
		break
	default:
		panic(fmt.Sprintf("Wrong size of key (%d bits)", len(key)*8))
	}

	// Calcul le nombre de colonne de la matrice
	nk := len(key) / 4

	// Cacule le nombre de tournées nr
	nr := 6 + nk

	// Génère toutes les clés
	roundKeys := keyExpansion(key, nr)

	// Applique la première clé sur la block
	lastKey := subKey(roundKeys, nr-1, keySize)
	addRoundKey(block, lastKey)
	invSubBytes(block)
	invShiftRows(block)

	for i := (nr - 1); i > 0; i-- {
		currentKey = subKey(roundKeys, i, keySize)
		addRoundKey(block, currentKey)
		invMixColumns(block)
		invShiftRows(block)
		invSubBytes(block)
	}

	key0 := subKey(roundKeys, 0, keySize)
	addRoundKey(block, key0)
}

// Retourne la i-ème clé de la clé étendue
func subKey(ke []byte, i, keySize int) []byte {
	return ke[i*keySize : (i+1)*keySize]
}

// AESEncrypt chiffre avec l'agorithme AES un tableau de
// byte avec une clé k de taille 128, 192 ou 256 bits
func AESEncrypt(data, k []byte) (c []byte) {
	var block []byte

	data = addPadding(data, 128)
	c = make([]byte, 0, len(data))

	for i := 0; i < (len(data) / 16); i++ {
		block = data[i*16 : (i+1)*16]
		encryptBlock(block, k)
		c = append(c, block...)
	}

	return c
}

// AESDecrypt déchiffre avec l'agorithme AES un tableau
// de byte avec une clé k de taille 128, 192 ou 256 bits
func AESDecrypt(cipher, k []byte) []byte {
	var block []byte

	m := make([]byte, 0, len(cipher))

	for i := 0; i < (len(cipher) / 16); i++ {
		block = cipher[i*16 : (i+1)*16]
		decryptBlock(block, k)
		m = append(m, block...)
	}

	m = removePadding(m)

	return m
}

// GenerateAESKey génère une clé AES de size bytes
func GenerateAESKey(size int) []byte {
	return randomBytes(size)
}
