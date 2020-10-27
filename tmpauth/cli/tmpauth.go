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
	"math/big"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
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
				pub := elliptic.Marshal(elliptic.P256(), ecKey.X, ecKey.Y)
				priv := ecKey.D.Bytes()
				fmt.Println(base64.StdEncoding.EncodeToString(priv) + "." + base64.StdEncoding.EncodeToString(pub))
			case "PUBLIC KEY":
				pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
				if err != nil {
					log.Fatalln("failed to parse public key:", err)
				}

				ecKey := pubKey.(*ecdsa.PublicKey)
				pub := elliptic.Marshal(elliptic.P256(), ecKey.X, ecKey.Y)

				fmt.Println(base64.StdEncoding.EncodeToString(pub))
			default:
				log.Fatalln("unsupported PEM block type:", block.Type)
			}
		}
	case "create-secret":
		privateKey := os.Getenv("TMPAUTH_PRIVATE_KEY")
		if privateKey == "" {
			log.Fatalln("you must provide a tmpauth private key via env variable TMPAUTH_PRIVATE_KEY")
		}

		keyParts := strings.SplitN(privateKey, ".", 2)
		priv, err := base64.StdEncoding.DecodeString(keyParts[0])
		if err != nil {
			panic(err)
		}
		pub, err := base64.StdEncoding.DecodeString(keyParts[1])
		if err != nil {
			panic(err)
		}

		privNum := new(big.Int).SetBytes(priv)
		x, y := elliptic.Unmarshal(elliptic.P256(), pub)

		privKey := &ecdsa.PrivateKey{
			D: privNum,
			PublicKey: ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     x,
				Y:     y,
			},
		}

		token, err := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
			"secret": "awduiafh8awrdf98aw8324",
			"sub":    "e06804e0258f2075812d8f829eb0c9abebc4c380a6a70f3a12616a359ce44a11",
			"iss":    "https://auth.tmpim.pw:central",
			"aud":    "https://auth.tmpim.pw:server:key:e06804e0258f2075812d8f829eb0c9abebc4c380a6a70f3a12616a359ce44a11",
		}).SignedString(privKey)
		if err != nil {
			panic(err)
		}

		fmt.Println(token)
	}
}

var usage = `Usage: tmpauth <subcommand>
Subcommands:
	convert
		stdins a PEM encoded public or private key, stdouts it to minified tmpauth key format
	create-secret
		register a new client for debugging purposes using the private key specified by environment variable TMPAUTH_PRIVATE_KEY
`
