package main

import (
	"flag"
	"fmt"
	"os"
)

func usage() {
	fmt.Println("Usage: commande [aes|elgamal]")
}

func aes() {
	cmd := os.Args[2]
	switch cmd {
	case "genkey":
		fs := flag.NewFlagSet("genkey", flag.ExitOnError)
		keySize := fs.Int("size", 128, "Taille de la clé")
		fs.Parse(os.Args[3:])
		if fs.Arg(0) == "" {
			usage()
			os.Exit(1)
		}

		fmt.Printf("Géneration de la clé de %d bits... ", *keySize)
		key := GenerateAESKey(*keySize / 8)
		fmt.Println("Terminé")

		filename := fs.Arg(0)
		WriteBytes(key, filename)
	case "encrypt":
		fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
		fs.Parse(os.Args[3:])

		if fs.Arg(0) == "" || fs.Arg(1) == "" || fs.Arg(2) == "" {
			usage()
			os.Exit(1)
		}

		keyPath, dataPath, cipherPath := fs.Arg(0), fs.Arg(1), fs.Arg(2)

		data := ReadBytes(dataPath)
		key := ReadBytes(keyPath)

		c := AESEncrypt(data, key)
		WriteBytes(c, cipherPath)
	case "decrypt":
		fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
		fs.Parse(os.Args[3:])

		if fs.Arg(0) == "" || fs.Arg(1) == "" {
			usage()
			os.Exit(1)
		}

		keyPath, cipherPath, dataPath := fs.Arg(0), fs.Arg(1), fs.Arg(2)

		cipher := ReadBytes(cipherPath)
		key := ReadBytes(keyPath)

		d := AESDecrypt(cipher, key)
		if dataPath == "" {
			os.Stdout.Write(d)
		} else {
			WriteBytes(d, dataPath)
		}
	default:
		usage()
		os.Exit(1)
	}

}

func elgamal() {}

func cli() {
	if len(os.Args) < 3 {
		usage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "aes":
		aes()
	case "elgamal":
		elgamal()
	default:
		usage()
		os.Exit(1)
	}
}

func main() {
	// cli()

	pair := GenerateElgamalKeyPair(160)
	m := []byte{125, 14, 46, 78, 79}
	fmt.Println(m)

	d := ElgamalEncrypt(&pair.ElgamalPublicKey, m)

	message := ElgamalDecrypt(pair, d)
	fmt.Println(message)
}
