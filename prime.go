package main

import (
	"math/big"
)

var (
	big0 = big.NewInt(0)
	big1 = big.NewInt(1)
	big2 = big.NewInt(2)
	big3 = big.NewInt(3)
)

func decompose(n *big.Int) (uint, *big.Int) {
	exp := uint(0)
	y, z := new(big.Int), new(big.Int).Set(n)

	for y.Mod(z, big2).Cmp(big0) == 0 { // => (z%2 == 0)
		z.Div(z, big2)
		exp++
	}

	return exp, z
}

func isWitness(w, p *big.Int, exp uint, remainder *big.Int) bool {
	T := new(big.Int)

	w.Exp(w, remainder, p)

	// w == 1 || w == p-1
	if w.Cmp(big1) == 0 || w.Cmp(T.Sub(p, big1)) == 0 {
		return false
	}

	for i := uint(0); i < exp; i++ {
		w.Exp(w, big2, p)

		// w == p-1
		if w.Cmp(T.Sub(p, big1)) == 0 {
			return false
		}
	}
	return true
}

func probablyPrime(p *big.Int, accuracy uint) bool {
	T, w := new(big.Int), new(big.Int)

	// p == 2 || p == 3
	if p.Cmp(big2) == 0 || p.Cmp(big3) == 0 {
		return true
	}

	// p < 2
	if p.Cmp(big2) == -1 {
		return false
	}

	exp, remainder := decompose(T.Sub(p, big1))

	pMinus1 := new(big.Int).Sub(p, big1)

	for i := uint(0); i < accuracy; i++ {
		w = randRange(big2, pMinus1)
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
