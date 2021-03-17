package flagvars

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"strings"
)

// rsaPrivateKeyValue adapts rsa.PrivateKey for use as a flag. Value of flag
// is PEM encoded.
type rsaPrivateKeyValue struct {
	dst *rsa.PrivateKey
}

// String implements flag.Value.String.
func (v rsaPrivateKeyValue) String() string {
	return "<redacted>"
}

// Set implements flag.Value.Set.
func (v *rsaPrivateKeyValue) Set(value string) error {
	value = strings.ReplaceAll(value, `\n`, "\n")
	block, _ := pem.Decode([]byte(value))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return errors.New("failed to find a suitable pem block type")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	*v.dst = *priv

	return nil
}

// Type implements flag.Value.Type.
func (*rsaPrivateKeyValue) Type() string {
	return "rsaPrivateKey"
}

// RSAPrivateKey creates and returns a new flag.Value compliant RSA
// PrivateKey parser.
func RSAPrivateKey(p *rsa.PrivateKey) flag.Value {
	return &rsaPrivateKeyValue{dst: p}
}

// rsaPublicKeyValue adapts rsa.PublicKey for use as a flag. Value of flag
// is PEM encoded.
type rsaPublicKeyValue struct {
	dst *rsa.PublicKey
}

// String implements flag.Value.String.
func (v rsaPublicKeyValue) String() string {
	publicKeyDer, _ := x509.MarshalPKIXPublicKey(v.dst)
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDer,
	}))
}

// Set implements flag.Value.Set.
func (v *rsaPublicKeyValue) Set(value string) error {
	value = strings.ReplaceAll(value, `\n`, "\n")
	block, _ := pem.Decode([]byte(value))
	if block == nil || block.Type != "PUBLIC KEY" {
		return errors.New("failed to find a suitable pem block type")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		*v.dst = *pub
	default:
		return errors.New("unknown type of public key")
	}

	return nil
}

// Type implements flag.Value.Type.
func (*rsaPublicKeyValue) Type() string {
	return "rsaPublicKey"
}

// RSAPublicKey creates and returns a new flag.Value compliant RSA PublicKey
// parser.
func RSAPublicKey(p *rsa.PublicKey) flag.Value {
	return &rsaPublicKeyValue{dst: p}
}
