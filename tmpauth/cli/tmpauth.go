package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

func main() {
	if len(os.Args) == 1 {
		fmt.Println(usage)
		os.Exit(1)
	}

	switch os.Args[1] {
	case "convert":
		data, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			panic(err)
		}

		for len(data) > 4 {
			var block *pem.Block
			block, data = pem.Decode(data)
			switch block.Type {
			case "PRIVATE KEY":
				privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
				if err != nil {
					log.Fatalln("failed to parse private key:", err)
				}

				ecKey := privKey.(*ecdsa.PrivateKey)
				pub := elliptic.MarshalCompressed(elliptic.P256(), ecKey.X, ecKey.Y)
				priv := ecKey.D.Bytes()
				fmt.Println(base64.StdEncoding.EncodeToString(priv) + "." + base64.StdEncoding.EncodeToString(pub))
			case "PUBLIC KEY":
				pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
				if err != nil {
					log.Fatalln("failed to parse public key:", err)
				}

				ecKey := pubKey.(*ecdsa.PublicKey)
				pub := elliptic.MarshalCompressed(elliptic.P256(), ecKey.X, ecKey.Y)

				fmt.Println(base64.StdEncoding.EncodeToString(pub))
			default:
				log.Fatalln("unsupported PEM block type:", block.Type)
			}
		}

	}
}

var usage = `Usage: tmpauth <subcommand>
Subcommands:
	convert
		stdins a PEM encoded public or private key, stdouts it to minified tmpauth key format
`
