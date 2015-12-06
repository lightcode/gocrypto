package main

import (
	"math/big"
)

var (
	N_ZERO  = big.NewInt(0)
	N_ONE   = big.NewInt(1)
	N_TWO   = big.NewInt(2)
	N_THREE = big.NewInt(3)
)

func decompose(n *big.Int) (uint, *big.Int) {
	exp := uint(0)
	y, z := new(big.Int), new(big.Int).Set(n)

	for y.Mod(z, N_TWO).Cmp(N_ZERO) == 0 { // => (z%2 == 0)
		z.Div(z, N_TWO)
		exp++
	}

	return exp, z
}

func isWitness(w, p *big.Int, exp uint, remainder *big.Int) bool {
	T := new(big.Int)

	w.Exp(w, remainder, p)

	// w == 1 || w == p-1
	if w.Cmp(N_ONE) == 0 || w.Cmp(T.Sub(p, N_ONE)) == 0 {
		return false
	}

	for i := uint(0); i < exp; i++ {
		w.Exp(w, N_TWO, p)

		// w == p-1
		if w.Cmp(T.Sub(p, N_ONE)) == 0 {
			return false
		}
	}
	return true
}

func probablyPrime(p *big.Int, accuracy uint) bool {
	T, w := new(big.Int), new(big.Int)

	// p == 2 || p == 3
	if p.Cmp(N_TWO) == 0 || p.Cmp(N_THREE) == 0 {
		return true
	}

	// p < 2
	if p.Cmp(N_TWO) == -1 {
		return false
	}

	exp, remainder := decompose(T.Sub(p, N_ONE))

	p_1 := new(big.Int).Sub(p, N_ONE)

	for i := uint(0); i < accuracy; i++ {
		w = randRange(N_TWO, p_1)
		if isWitness(w, p, exp, remainder) {
			return false
		}
	}

	return true
}

func generateRandomPrime(size int) *big.Int {
	for {
		n := randomBigInt(size)
		if probablyPrime(n, 25) {
			return n
		}
	}
}
