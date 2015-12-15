package main

import "math/big"

// Taille mininale de p pour éviter de couper
// les messages en trop petite taille
const elgamalMinSize = 128

// ElgamalPublicKey représente une clé publique
type ElgamalPublicKey struct {
	Q *big.Int // Q est l'ordre du corps Zp
	G *big.Int // G est le générateur du corps Zp
	H *big.Int // H = G^X (où x est la clé privée)
}

// ElgamalPrivateKey représente une paire de clés
type ElgamalPrivateKey struct {
	ElgamalPublicKey

	X *big.Int // X est généré aléatoirement lors de la création des clés
}

func appendWithSize(fields ...[]byte) []byte {
	var out []byte
	for _, v := range fields {
		out = append(append(out, byte(len(v))), v...)
	}
	return out
}

// GetBytes renvoie sous forme d'octets la clé privée
func (pub *ElgamalPublicKey) GetBytes() []byte {
	return appendWithSize(pub.Q.Bytes(), pub.G.Bytes(), pub.H.Bytes())
}

// GetBytes renvoie sous forme d'octets la clé privée
func (priv *ElgamalPrivateKey) GetBytes() []byte {
	return append(priv.ElgamalPublicKey.GetBytes(), appendWithSize(priv.X.Bytes())...)
}

func readSizeValueBytes(bytes []byte) [][]byte {
	var res [][]byte
	k, s, l := 0, 1, 0

	for {
		l = int(bytes[k])
		res = append(res, bytes[s:s+l])

		k = k + l + 1
		s = k + 1
		if k >= len(bytes) {
			break
		}
	}

	return res
}

func LoadPrivateKey(b []byte) *ElgamalPrivateKey {
	v := readSizeValueBytes(b)
	return &ElgamalPrivateKey{
		ElgamalPublicKey: ElgamalPublicKey{
			Q: new(big.Int).SetBytes(v[0]),
			G: new(big.Int).SetBytes(v[1]),
			H: new(big.Int).SetBytes(v[2]),
		},
		X: new(big.Int).SetBytes(v[3]),
	}
}

func LoadPublicKey(b []byte) *ElgamalPublicKey {
	v := readSizeValueBytes(b)
	return &ElgamalPublicKey{
		Q: new(big.Int).SetBytes(v[0]),
		G: new(big.Int).SetBytes(v[1]),
		H: new(big.Int).SetBytes(v[2]),
	}
}

// Génère un groupe cyclique Zp, trouve un générateur g et renvoie (p, g)
// p est un nombre entier de size bits (size est multiple de 8)
// Le nombre p est également supérieur à la taille maximale d'un message + 1
func generateCyclicGroup(size int) (p, g *big.Int) {
	var (
		n       = new(big.Int)
		T       = new(big.Int)
		pMinus1 = new(big.Int)
		pmin    = new(big.Int)
	)

	p = new(big.Int)
	pmin.SetBit(pmin, elgamalMinSize+1, 1)

	for {
		n = generateRandomPrime(size / 8)

		// p = 2n + 1
		pMinus1.Mul(n, big2)
		p.Add(pMinus1, big1)

		// p < pmin
		if p.Cmp(pmin) == -1 {
			continue
		}

		// p n'est pas premier
		if !probablyPrime(p, 25) {
			continue
		}

		// On cherche un générateur g dans Zp
		for {
			g = randRange(big2, pMinus1)

			// Si g^(p-1) != 1 alors g n'est pas générateur
			if T.Exp(g, pMinus1, p).Cmp(big1) != 0 {
				continue
			}

			// Si g^2 == 1 alors g n'est pas générateur
			if T.Exp(g, big2, p).Cmp(big1) == 0 {
				continue
			}

			return p, g
		}
	}
}

// GenerateElgamalKeys génère une paire de clés et la renvoie
func GenerateElgamalKeys(size int) *ElgamalPrivateKey {
	p, g := generateCyclicGroup(size)

	// Calcul de l'ordre de Zp
	q := new(big.Int).Sub(p, big1)

	// Calcul de x
	x := randRange(big1, new(big.Int).Sub(q, big1))

	// Calcul de h
	h := new(big.Int).Exp(g, x, p)

	return &ElgamalPrivateKey{
		ElgamalPublicKey: ElgamalPublicKey{G: g, Q: q, H: h},
		X:                x,
	}
}

func elgamalEncryptBytes(pubkey *ElgamalPublicKey, plaintext []byte) (c1bytes, c2bytes []byte) {
	var (
		c2     = new(big.Int)
		m      = new(big.Int)
		c2b    []byte
		offset int
	)

	// Calcul du nombre de d'élément de Zp
	p := new(big.Int).Add(pubkey.Q, big1)

	// Calcul de la taille de p en octets
	pLen := (p.BitLen() + 7) / 8

	// On choisit aléatoirement un nombre entre 1 et (q-1)
	y := randRange(big1, new(big.Int).Sub(pubkey.Q, big1))

	// Calcul de la première partie du message chiffré
	c1 := new(big.Int).Exp(pubkey.G, y, p)

	// Calcul du secret partagé
	s := new(big.Int).Exp(pubkey.H, y, p)

	// Calcul de la taille d'un bloc en clair et d'un bloc chiffré
	plainBlockSize, cipherBlockSize := pLen-1, pLen

	// On ajoute un padding au message en clair pour que sa taille soit un multiple
	// de la taille de la clé
	plaintext = addPadding(plaintext, plainBlockSize*8)

	// Calcul du nombre de bloc à chiffrer
	nblock := len(plaintext) / plainBlockSize

	c2bytes = make([]byte, cipherBlockSize*nblock)

	// Chiffrement du message bloc par bloc
	for i := 0; i < nblock; i++ {
		// Traduit le bloc en un nombre dans Zp
		m.SetBytes(plaintext[i*plainBlockSize : (i+1)*plainBlockSize])

		// Calcul de c2 = m * s
		c2.Mul(m, s)
		c2.Mod(c2, p)

		// Copie de c2 dans le chiffré final
		c2b = c2.Bytes()
		offset = cipherBlockSize - len(c2b)
		copy(c2bytes[(i*cipherBlockSize)+offset:(i+1)*cipherBlockSize], c2b)
	}

	return c1.Bytes(), c2bytes
}

func elgamalDecryptBytes(priv *ElgamalPrivateKey, c1bytes, c2bytes []byte) (plaintext []byte) {
	var (
		c2     = new(big.Int)
		m      = new(big.Int)
		mb     []byte
		offset int
	)

	c1 := new(big.Int).SetBytes(c1bytes)

	// Calcul du nombre de d'élément de Zp
	p := new(big.Int).Add(priv.Q, big1)

	// Calcul de la taille de p en octets
	pLen := (p.BitLen() + 7) / 8

	// Calcul de la taille d'un bloc en clair et d'un bloc chiffré
	plainBlockSize, cipherBlockSize := pLen-1, pLen

	// Calcul du nombre de bloc
	nblock := len(c2bytes) / cipherBlockSize

	plaintext = make([]byte, nblock*plainBlockSize)

	// Calcul du secret partagé
	s := new(big.Int).Exp(c1, priv.X, p)

	// Calcul de l'inverse de s dans Zp
	sInverse := new(big.Int).ModInverse(s, p)

	// Chiffrement du message bloc par bloc
	for i := 0; i < nblock; i++ {
		// Lecture d'un block et conversion en entier dans Zp
		c2.SetBytes(c2bytes[i*cipherBlockSize : (i+1)*cipherBlockSize])

		// Calcul de c2 * sInverse dans Zp
		m.Mul(c2, sInverse)
		m.Mod(m, p)

		// Copie du résultat dans le tableau de sortie
		mb = m.Bytes()
		offset = plainBlockSize - len(mb)
		copy(plaintext[i*plainBlockSize+offset:(i+1)*plainBlockSize], mb)
	}

	// Supprime le padding
	plaintext = removePadding(plaintext)

	return plaintext
}

// ElgamalDecrypt déchiffre les messages chiffrés avec la
// fonction ElgamalEncrypt
func ElgamalDecrypt(priv *ElgamalPrivateKey, ciphertext []byte) (plaintext []byte) {
	// Récupère la taille de c1
	c1size := ciphertext[len(ciphertext)-1]

	// Récupère c1 et c2 sous la forme de tableau d'octets
	c1bytes, c2bytes := ciphertext[0:c1size], ciphertext[c1size:len(ciphertext)-1]

	// Déchiffre le message chiffré
	plaintext = elgamalDecryptBytes(priv, c1bytes, c2bytes)

	return plaintext
}

// ElgamalEncrypt chiffre les messages d'une taille quelconque et renvoie le
// résultat sous la forme de bytes représentant c1 et c2 :
// ciphertext = c1 | c2 | len(c1)
func ElgamalEncrypt(pubkey *ElgamalPublicKey, plaintext []byte) (ciphertext []byte) {
	c1, c2 := elgamalEncryptBytes(pubkey, plaintext)

	// Concataine la taille de c1 en mot de 8 bits, c1 et c2 dans un même tableau
	ciphertext = append(append(c1, c2...), byte(len(c1)))

	return
}
