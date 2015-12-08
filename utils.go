package main

import (
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"math/big"
	mrand "math/rand"
	"os"
	"time"
)

var seed = mrand.New(mrand.NewSource(time.Now().UnixNano()))

func CompareSlice(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Renvoie un nombre de type "big.Int" compris entre [min,max]
func randRange(min, max *big.Int) *big.Int {
	n := new(big.Int).Rand(seed, new(big.Int).Sub(max, min))
	n.Add(n, min)
	return n
}

// Returns n bytes randomly
func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		fmt.Println("error:", err)
		return nil
	}
	return b
}

func randomBigInt(size int) *big.Int {
	b := new(big.Int)
	b.SetBytes(randomBytes(size))
	return b
}

func WriteBytes(b []byte, path string) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0600)
	defer f.Close()

	if err != nil {
		fmt.Println("Erreur lors de l'ouverture du fichier:", err)
		os.Exit(1)
	}

	f.Write(b)
}

func ReadBytes(path string) []byte {
	b, err := ioutil.ReadFile(path)

	if err != nil {
		fmt.Println("Erreur lors de l'ouverture du fichier:", err)
		os.Exit(1)
	}

	return b
}

// Ajoute un padding sur le texte clair pour que sa
// longueur soit un multiple de bsize bits
func addPadding(b []byte, bsize int) []byte {
	bsize = bsize / 8

	newSize := ((len(b) / bsize) + 1) * bsize

	r := make([]byte, newSize)

	for i := range b {
		r[i] = b[i]
	}

	copy(r[len(b):], randomBytes(newSize-len(b)))

	r[len(r)-1] = byte(len(r) - len(b) - 1)

	return r
}

// Retire le padding ajouté par la fonction addPadding
func removePadding(b []byte) []byte {
	r := make([]byte, len(b)-int(b[len(b)-1])-1)

	for i := range r {
		r[i] = b[i]
	}
	return r
}
