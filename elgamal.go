package main

import (
	"math/big"
)

// ElgamalPublicKey représente une clé publique
type ElgamalPublicKey struct {
	Q *big.Int // Q est l'ordre du corps Zp
	G *big.Int // G est le générateur du corps Zp
	H *big.Int // H = G^X (où x est la clé privée)
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
	one := big.NewInt(1)
	pMinus1 := new(big.Int).Sub(p, one)

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
		ElgamalPublicKey{G: g, Q: q, H: h},
		ElgamalPrivateKey{X: x},
	}
}
