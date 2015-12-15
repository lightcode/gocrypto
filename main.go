package main

import (
	"flag"
	"fmt"
	"os"
)

func usage() {
	fmt.Println(`
Usage: gocrypto { aes | elgamal }

    * gocrypto aes
            genkey [-size=128] <key-file>
            encrypt <key-file> <plain-file> <cipher-file>
            decrypt <key-file> <cipher-file> [ <plain-file> ]

    * gocrypto elgamal
            genkey [-size=160] <priv-key-file>
            encrypt <pub-key-file> <plain-file> <cipher-file>
            decrypt <priv-key-file> <cipher-file> [ <plain-file> ]
            sign <priv-key-file> <file>
            check <pub-key-file> <file>
`[1:])
	os.Exit(255)
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
		}

		fmt.Printf("Géneration de la clé de %d bits... ", *keySize)
		key := GenerateAESKey(*keySize / 8)
		fmt.Println("Terminé")

		filename := fs.Arg(0)
		writeBytes(key, filename)
	case "encrypt":
		fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
		fs.Parse(os.Args[3:])

		if fs.Arg(0) == "" || fs.Arg(1) == "" || fs.Arg(2) == "" {
			usage()
		}

		keyPath, dataPath, cipherPath := fs.Arg(0), fs.Arg(1), fs.Arg(2)

		data := readBytes(dataPath)
		key := readBytes(keyPath)

		c := AESEncrypt(data, key)
		writeBytes(c, cipherPath)
	case "decrypt":
		fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
		fs.Parse(os.Args[3:])

		if fs.Arg(0) == "" || fs.Arg(1) == "" {
			usage()
		}

		keyPath, cipherPath, dataPath := fs.Arg(0), fs.Arg(1), fs.Arg(2)

		cipher := readBytes(cipherPath)
		key := readBytes(keyPath)

		d := AESDecrypt(cipher, key)
		if dataPath == "" {
			os.Stdout.Write(d)
		} else {
			writeBytes(d, dataPath)
		}
	default:
		usage()
	}
}

func elgamal() {
	cmd := os.Args[2]
	switch cmd {
	case "genkey":
		fs := flag.NewFlagSet("genkey", flag.ExitOnError)
		keySize := fs.Int("size", 160, "Taille de la clé")
		fs.Parse(os.Args[3:])

		if fs.Arg(0) == "" {
			usage()
		}

		fmt.Printf("Géneration de la clé de %d bits... ", *keySize)
		priv := GenerateElgamalKeys(*keySize)
		pub := priv.ElgamalPublicKey
		fmt.Println("Terminé")

		filename := fs.Arg(0)
		writeBytes(priv.GetBytes(), filename)
		writeBytes(pub.GetBytes(), filename+".pub")
	case "encrypt":
		fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
		fs.Parse(os.Args[3:])

		if fs.Arg(0) == "" || fs.Arg(1) == "" || fs.Arg(2) == "" {
			usage()
		}

		pubKeyPath, dataPath, cipherPath := fs.Arg(0), fs.Arg(1), fs.Arg(2)

		data := readBytes(dataPath)
		pub := LoadPublicKey(readBytes(pubKeyPath))

		c := ElgamalEncrypt(pub, data)
		writeBytes(c, cipherPath)
	case "decrypt":
		fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
		fs.Parse(os.Args[3:])

		if fs.Arg(0) == "" || fs.Arg(1) == "" {
			usage()
		}

		privateKeyPath, cipherPath, dataPath := fs.Arg(0), fs.Arg(1), fs.Arg(2)

		cipher := readBytes(cipherPath)
		priv := LoadPrivateKey(readBytes(privateKeyPath))

		d := ElgamalDecrypt(priv, cipher)
		if dataPath == "" {
			os.Stdout.Write(d)
		} else {
			writeBytes(d, dataPath)
		}
	default:
		usage()
	}
}

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
	cli()
}
