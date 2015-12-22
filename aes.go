package main

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

var mixMat = []byte{2, 3, 1, 1, 1, 2, 3, 1, 1, 1, 2, 3, 3, 1, 1, 2}
var mixMatInv = []byte{14, 11, 13, 9, 9, 14, 11, 13, 13, 9, 14, 11, 11, 13, 9, 14}

// Applique une fonction de mélange en fonction d'une matrice d'entrée
func applyMixColumns(b, mat []byte) {
	var a = make([]byte, len(b))

	ncol := len(b) / 4

	for i := 0; i < ncol; i++ {
		for j := 0; j < 4; j++ {
			a[(ncol*j)+i] = gmul(mat[j*4], b[i]) ^ gmul(mat[j*4+1], b[ncol+i]) ^ gmul(mat[j*4+2], b[(2*ncol)+i]) ^ gmul(mat[j*4+3], b[(3*ncol)+i])
		}
	}

	copy(b, a)
}

// Mélange les colonnes du state
func mixColumns(b []byte) {
	applyMixColumns(b, mixMat)
}

// Inverse la fonction de mélange de l'état
func invMixColumns(b []byte) {
	applyMixColumns(b, mixMatInv)
}

// Génère les différentes sous-clés
func keyExpansions(key []byte, nr int) []byte {
	keys := make([]byte, nr*len(key))

	copy(keys[0:len(key)], key)

	for i := len(key); i < len(keys); i++ {
		keys[i] = subByte(keys[i-len(key)])
	}

	return keys
}

// Retourne la i-ème clé de la clé étendue
func subKey(ke []byte, i, keySize int) []byte {
	return ke[i*keySize : (i+1)*keySize]
}

// AESEncrypt chiffre avec l'agorithme AES un tableau de
// byte avec une clé key de taille 128, 192 ou 256 bits
func AESEncrypt(data, key []byte) []byte {
	var (
		block      []byte
		currentKey []byte
	)

	// Taille de la clé en octet
	keySize := len(key)

	// Calcul le nombre de colonne de la matrice
	nk := len(key) / 4

	// Cacule le nombre de tournées nr
	nr := 6 + nk

	// Génère toutes les clés
	roundKeys := keyExpansions(key, nr)

	data = addPadding(data, keySize*8)
	cipher := make([]byte, 0, len(data))

	for i := 0; i < len(data)/keySize; i++ {
		block = data[i*keySize : (i+1)*keySize]

		// Applique la première clé sur la block
		key0 := subKey(roundKeys, 0, keySize)
		addRoundKey(block, key0)

		for j := 1; j < nr; j++ {
			subBytes(block)
			shiftRows(block)
			mixColumns(block)
			currentKey = subKey(roundKeys, j, keySize)
			addRoundKey(block, currentKey)
		}

		// Dernière tournée
		subBytes(block)
		shiftRows(block)
		lastKey := subKey(roundKeys, nr-1, keySize)
		addRoundKey(block, lastKey)

		cipher = append(cipher, block...)
	}

	return cipher
}

// AESDecrypt déchiffre avec l'agorithme AES un tableau
// de byte avec une clé k de taille 128, 192 ou 256 bits
func AESDecrypt(cipher, key []byte) []byte {
	var (
		block      []byte
		currentKey []byte
	)

	// Taille de la clé en octet
	keySize := len(key)

	// Calcule le nombre de colonne de la matrice
	nk := len(key) / 4

	// Cacule le nombre de tournées nr
	nr := 6 + nk

	// Génère toutes les clés
	roundKeys := keyExpansions(key, nr)

	m := make([]byte, 0, len(cipher))

	for i := 0; i < (len(cipher) / keySize); i++ {
		block = cipher[i*keySize : (i+1)*keySize]

		// Applique la première clé sur la block
		lastKey := subKey(roundKeys, nr-1, keySize)
		addRoundKey(block, lastKey)
		invSubBytes(block)
		invShiftRows(block)

		for j := (nr - 1); j > 0; j-- {
			currentKey = subKey(roundKeys, j, keySize)
			addRoundKey(block, currentKey)
			invMixColumns(block)
			invShiftRows(block)
			invSubBytes(block)
		}

		key0 := subKey(roundKeys, 0, keySize)
		addRoundKey(block, key0)

		m = append(m, block...)
	}

	m = removePadding(m)

	return m
}

// GenerateAESKey génère une clé AES de size bytes
func GenerateAESKey(size int) []byte {
	return randomBytes(size)
}
