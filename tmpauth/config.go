package tmpauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/tmpim/casket"
)

type Config struct {
	PublicKey    *ecdsa.PublicKey
	ClientID     string
	Secret       []byte
	Token        string
	AllowedUsers []string
	IDFormats    []string
	Except       []string
	Include      []string
	Headers      map[string]*HeaderOption
	Debug        bool
}

func parseConfig(c *casket.Controller) (*Config, error) {
	var config *Config

	found := false

	for c.Next() {
		if found {
			return nil, errors.New("tmpauth: only one tmpauth block can be specified for a listener")
		}

		found = true
		if len(c.RemainingArgs()) > 0 {
			return nil, errors.New("tmpauth: tmpauth directive does not support arguments, only config blocks")
		}

		var cfgBlock configBlock
		cfgBlock.Headers = make(map[string]*HeaderOption)
		cfgBlock.IDFormats = []string{"token.sub", "whomst.discord", "whomst.name"}

		for c.NextBlock() {
			val := c.Val()
			args := c.RemainingArgs()

			switch val {
			case "public_key":
				if len(args) == 0 {
					return nil, fmt.Errorf("tmpauth: public_key option must have a value")
				}
				cfgBlock.PublicKey = args[0]
			case "secret":
				if len(args) == 0 {
					return nil, fmt.Errorf("tmpauth: secret option must have a value")
				}
				cfgBlock.Token = args[0]
			case "allowed_users":
				cfgBlock.AllowedUsers = args
			case "id_formats":
				cfgBlock.IDFormats = args
				if len(args) == 0 {
					return nil, fmt.Errorf("tmpauth: id_format must have at least 1 format value")
				}
			case "except":
				cfgBlock.Except = args
			case "include":
				cfgBlock.Include = args
			case "debug":
				cfgBlock.Debug = true
			default:
				headerName := strings.ToLower(val)
				if !strings.HasPrefix(headerName, "x-") {
					return nil, fmt.Errorf("tmpauth: unknown config option (headers must start with \"X-\"): %v", val)
				}

				if len(args) == 0 {
					return nil, fmt.Errorf("tmpauth: header option %q must have a format value", val)
				}

				cfgBlock.Headers[headerName] = &HeaderOption{
					Format:   args[0],
					Optional: len(args) > 1 && args[1] == "optional",
				}
			}
		}

		var err error
		config, err = cfgBlock.validate()
		if err != nil {
			return nil, fmt.Errorf("tmpauth: failed to parse configuration: %w", err)
		}
	}

	return config, nil
}

type configBlock struct {
	PublicKey    string
	Token        string
	AllowedUsers []string
	IDFormats    []string
	Except       []string
	Include      []string
	Headers      map[string]*HeaderOption
	Debug        bool
}

type configClaims struct {
	Secret   string `json:"secret"`
	clientID []byte `json:"-"`
	jwt.StandardClaims
}

func (c *configClaims) Valid() error {
	if c.Subject == "" {
		return fmt.Errorf("tmpauth: subject cannot be empty")
	}

	if !c.VerifyIssuer(TmpAuthHost+":central", true) {
		return fmt.Errorf("tmpauth: issuer invalid, got: %v", c.Issuer)
	}

	if !c.VerifyAudience(TmpAuthHost+":server:key:"+c.Subject, true) {
		return fmt.Errorf("tmpauth: audience invalid, got: %v", c.Audience)
	}

	return nil
}

func (c *configBlock) validate() (*Config, error) {
	if len(c.PublicKey) == 0 || len(c.Token) == 0 {
		return nil, fmt.Errorf("tmpauth: both public_key and secret must be specified")
	}

	pubKeyData, err := base64.StdEncoding.DecodeString(c.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("tmpauth: invalid public_key: %w", err)
	}

	x, y := elliptic.Unmarshal(elliptic.P256(), pubKeyData)
	if x == nil {
		return nil, fmt.Errorf("tmpauth: invalid public_key")
	}

	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	token, err := jwt.ParseWithClaims(c.Token, &configClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("tmpauth: invalid secret signing method: %v", token.Header["alg"])
		}

		return pubKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("tmpauth: invalid secret: %w", err)
	}

	claims := token.Claims.(*configClaims)

	if len(c.Except) != 0 && len(c.Include) != 0 {
		return nil, fmt.Errorf("tmpauth: both exclude and include cannot be specified at the same time")
	}

	if claims.Secret == "" {
		return nil, fmt.Errorf("tmpauth: secret cannot be empty")
	}

	return &Config{
		PublicKey:    pubKey,
		ClientID:     claims.Subject,
		Token:        c.Token,
		Secret:       []byte(claims.Secret),
		Include:      c.Include,
		Except:       c.Except,
		AllowedUsers: c.AllowedUsers,
		IDFormats:    c.IDFormats,
		Headers:      c.Headers,
		Debug:        c.Debug,
	}, nil
}
