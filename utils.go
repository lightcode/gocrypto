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
		fmt.Println("Erreur :", err)
		return nil
	}
	return b
}

func randomBigInt(size int) *big.Int {
	b := new(big.Int).SetBytes(randomBytes(size))
	return b
}

func intToBytes(n int) []byte {
	res := make([]byte, 4)

	for i := 0; i < 4; i++ {
		res[i] = byte(n & 0xFF)
		n = n >> 8
	}

	return res
}

func bytesToInt(b []byte) int {
	res := 0

	for i := 0; i < 4; i++ {
		res += int(b[i]) << uint(8*i)
	}

	return res
}

// Sérialisation de plusieurs tableau de byte à la suite
// pour en former un.
// Chaque tableau est concatainé sous la forme : "len(d) | d..."
func serialize(fields ...[]byte) []byte {
	var out []byte
	for _, v := range fields {
		out = append(out, intToBytes(len(v))...)
		out = append(out, v...)
	}
	return out
}

// Renvoie les différents tableaux sérialisé avec la fonction
// serialize.
func deserialize(bytes []byte) [][]byte {
	var res [][]byte
	k, l := 0, 0

	for {
		s := k + 4
		l = bytesToInt(bytes[k : k+4])
		res = append(res, bytes[s:s+l])

		k = s + l
		if k >= len(bytes) {
			break
		}
	}

	return res
}

func writeBytes(b []byte, path string) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0600)

	if err == nil {
		defer f.Close()
	} else {
		fmt.Println("Erreur lors de l'ouverture du fichier:", err)
		os.Exit(1)
	}

	f.Write(b)
}

func readBytes(path string) []byte {
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
	bsize = (bsize + 7) / 8

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
