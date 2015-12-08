package main

import "math/big"

const elgamalBlockSize = 128 / 8

// ElgamalPublicKey représente une clé publique
type ElgamalPublicKey struct {
	KeySize int      // Taille de la clé
	Q       *big.Int // Q est l'ordre du corps Zp
	G       *big.Int // G est le générateur du corps Zp
	H       *big.Int // H = G^X (où x est la clé privée)
}

// ElgamalPrivateKey représente une clé privée
type ElgamalPrivateKey struct {
	X *big.Int // X est généré aléatoirement lors de la création des clés
}

// ElgamalKeyPair représente un paire de clés (publique, privée)
type ElgamalKeyPair struct {
	ElgamalPublicKey
	ElgamalPrivateKey
}

// Teste si le nombre x peut être mis sous la forme
// x = 2 * m   où m est premier
// Revoie :
//    - (décomposition, true) si la factorisation a fonctionné
//    - ([], false) si la factorisation n'a pas fonctionné
func factorize(x *big.Int) ([]*big.Int, bool) {
	var res []*big.Int
	T := new(big.Int)
	n := new(big.Int).Set(x)

	// Vérifie si n est divisible par 2
	if T.Mod(n, N_TWO).Cmp(N_ZERO) == 0 {
		n.Div(n, N_TWO)

		if n.Bit(0) == 0 {
			return res, false
		}

		if probablyPrime(n, 25) {
			res = append(res, new(big.Int).Set(n), N_TWO)
			return res, true
		}
	}

	return res, false
}

// Génère un groupe cyclique Zp, trouve un générateur g et renvoie (p, g)
// p est un nombre entier de size bits (size est multiple de 8)
func generateCyclicGroup(size int) (p, g *big.Int) {
	T := new(big.Int)

	for {
		p = generateRandomPrime(size / 8)
		f, e := factorize(T.Sub(p, N_ONE))
		if !e {
			continue
		}
		g = findGenerator(p, f)
		return p, g
	}

}

// Renvoie vrai si g est générateur du Groupe Zp
func isGenerator(p, g *big.Int, k []*big.Int) bool {
	pMinus1 := new(big.Int).Sub(p, N_ONE)

	if new(big.Int).Exp(g, pMinus1, p).Cmp(N_ONE) != 0 {
		return false
	}

	for _, n := range k {
		if new(big.Int).Exp(g, n, p).Cmp(N_ONE) == 0 {
			return false
		}
	}
	return true
}

// Trouve un nombre générateur aléatoire dans Zp
func findGenerator(p *big.Int, f []*big.Int) *big.Int {
	T := new(big.Int)

	for {
		// Génère un nombre aléatoire compris entre 2 et p-1
		g := randRange(N_TWO, T.Sub(p, N_ONE))
		if isGenerator(p, g, f) {
			return g
		}
	}
}

// GenerateElgamalKeyPair génère une paire de clés et la renvoie
func GenerateElgamalKeyPair(size int) *ElgamalKeyPair {
	p, g := generateCyclicGroup(size)

	// Calcul de l'ordre de Zp
	q := new(big.Int).Sub(p, N_ONE)

	// Calcul de x
	x := randRange(N_ONE, new(big.Int).Sub(q, N_ONE))

	// Calcul de h
	h := new(big.Int).Exp(g, x, p)

	return &ElgamalKeyPair{
		ElgamalPublicKey{G: g, Q: q, H: h, KeySize: size},
		ElgamalPrivateKey{X: x},
	}
}

func elgamalEncryptBytes(pubkey *ElgamalPublicKey, plaintext []byte) (c1bytes, c2bytes []byte) {
	// Calcul du nombre de d'élément de Zp
	p := new(big.Int).Add(pubkey.Q, N_ONE)

	// On choisit aléatoirement un nombre entre 1 et (q-1)
	y := randRange(N_ONE, new(big.Int).Sub(pubkey.Q, N_ONE))

	// Calcule de la première partie du message chiffré
	c1 := new(big.Int).Exp(pubkey.G, y, p)

	// Calcul de "s" le secret partagé
	s := new(big.Int).Exp(pubkey.H, y, p)

	// Taille du bloc en mots de 8 bits
	plainBlockSize := elgamalBlockSize
	cipherBlockSize := pubkey.KeySize / 8

	// Calcul du nombre de bloc à chiffrer
	nblock := len(plaintext) / plainBlockSize

	c2bytes = make([]byte, cipherBlockSize*nblock)

	// Chiffrement du message bloc par bloc
	for i := 0; i < nblock; i++ {
		// Traduit le bloc en un nombre dans Zp
		m := new(big.Int).SetBytes(plaintext[i*plainBlockSize : (i+1)*plainBlockSize])

		// Calcule de c2 = m * s
		c2 := new(big.Int).Mul(m, s)
		c2.Mod(c2, p)

		// Copie de c2 dans le chiffré final
		copy(c2bytes[i*cipherBlockSize:(i+1)*cipherBlockSize], c2.Bytes())
	}

	return c1.Bytes(), c2bytes
}

func elgamalDecryptBytes(keys *ElgamalKeyPair, c1bytes, c2bytes []byte) (plaintext []byte) {
	c1 := new(big.Int).SetBytes(c1bytes)

	// Taille du bloc en mots de 8 bits
	plainBlockSize := elgamalBlockSize
	cipherBlockSize := keys.KeySize / 8

	// Calcul du nombre de bloc
	nblock := len(c2bytes) / cipherBlockSize

	plaintext = make([]byte, nblock*plainBlockSize)

	// Calcul du nombre de d'élément de Zp
	p := new(big.Int).Add(keys.Q, N_ONE)

	// Calcul du secret partagé
	s := new(big.Int).Exp(c1, keys.X, p)

	// Calcul de l'inverse de s
	sInverse := new(big.Int).ModInverse(s, p)

	// Chiffrement du message bloc par bloc
	for i := 0; i < nblock; i++ {
		// Lecture d'un block et conversion en entier dans Zp
		c2 := new(big.Int).SetBytes(c2bytes[i*cipherBlockSize : (i+1)*cipherBlockSize])

		// Calcul de l'inverse de c2 dans Zp
		mPrime := new(big.Int).Mul(c2, sInverse)
		mPrime.Mod(mPrime, p)

		// Copie du résultat dans le tableau de sortie
		copy(plaintext[i*plainBlockSize:(i+1)*plainBlockSize], mPrime.Bytes())
	}

	return plaintext
}

// ElgamalDecrypt déchiffre les messages chiffrés avec la
// fonction ElgamalEncrypt
func ElgamalDecrypt(keys *ElgamalKeyPair, ciphertext []byte) (plaintext []byte) {
	// Récupère la taille de c1
	c1size := ciphertext[len(ciphertext)-1]

	c1bytes, c2bytes := ciphertext[0:c1size], ciphertext[c1size:len(ciphertext)-1]

	plaintext = elgamalDecryptBytes(keys, c1bytes, c2bytes)

	plaintext = removePadding(plaintext)

	return plaintext
}

// ElgamalEncrypt chiffre les messages d'une taille quelconque et renvoie le
// résultat sous la forme de bytes représentant c1 et c2 :
// ciphertext = c1 | c2 | len(c1)
func ElgamalEncrypt(pubkey *ElgamalPublicKey, plaintext []byte) (ciphertext []byte) {
	// On ajoute un padding au message en clair pour que sa taille soit un multiple
	// de la taille de la clé
	plaintext = addPadding(plaintext, elgamalBlockSize*8)

	c1, c2 := elgamalEncryptBytes(pubkey, plaintext)

	// Concataine la taille de c1 en mot de 8 bits, c1 et c2 dans un même tableau
	ciphertext = make([]byte, len(c1)+len(c2)+1)
	copy(ciphertext[0:len(c1)], c1)
	copy(ciphertext[len(c1):len(ciphertext)-1], c2)
	ciphertext[len(ciphertext)-1] = byte(len(c1))

	return ciphertext
}
