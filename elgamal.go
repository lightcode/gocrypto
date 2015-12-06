package main

import (
	"math/big"
)

// Teste si le nombre x peut être mis sous la forme
// x = 2 * m   où m est premier
// Revoie :
//    - (décomposition, true) si la factorisation a fonctionné
//    - ([], false) si la factorisation n'a pas fonctionné
func factorize(x *big.Int) ([]*big.Int, bool) {
	T := new(big.Int)
	res := make([]*big.Int, 0)
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
	p_1 := new(big.Int).Sub(p, one)

	if new(big.Int).Exp(g, p_1, p).Cmp(N_ONE) != 0 {
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
