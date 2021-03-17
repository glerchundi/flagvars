package flagvars

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"strings"
)

// ecdsaPrivateKeyValue adapts ecdsa.PrivateKey for use as a flag. Value of flag
// is PEM encoded.
type ecdsaPrivateKeyValue struct {
	dst *ecdsa.PrivateKey
}

// String implements flag.Value.String.
func (v ecdsaPrivateKeyValue) String() string {
	return "<redacted>"
}

// Set implements flag.Value.Set.
func (v *ecdsaPrivateKeyValue) Set(value string) error {
	value = strings.ReplaceAll(value, `\n`, "\n")
	block, _ := pem.Decode([]byte(value))
	if block == nil || (block.Type != "PRIVATE KEY" && block.Type != "EC PRIVATE KEY") {
		return errors.New("failed to find a suitable pem block type")
	}

	priv, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	*v.dst = *priv

	return nil
}

// Type implements flag.Value.Type.
func (*ecdsaPrivateKeyValue) Type() string {
	return "ecdsaPrivateKey"
}

// ECDSAPrivateKey creates and returns a new flag.Value compliant ECDSA
// PrivateKey parser.
func ECDSAPrivateKey(p *ecdsa.PrivateKey) flag.Value {
	return &ecdsaPrivateKeyValue{dst: p}
}

// ecdsaPublicKeyValue adapts ecdsa.PublicKey for use as a flag. Value of flag
// is PEM encoded.
type ecdsaPublicKeyValue struct {
	dst *ecdsa.PublicKey
}

// String implements flag.Value.String.
func (v ecdsaPublicKeyValue) String() string {
	publicKeyDer, _ := x509.MarshalPKIXPublicKey(v.dst)
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDer,
	}))
}

// Set implements flag.Value.Set.
func (v *ecdsaPublicKeyValue) Set(value string) error {
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
	case *ecdsa.PublicKey:
		*v.dst = *pub
	default:
		return errors.New("unknown type of public key")
	}

	return nil
}

// Type implements flag.Value.Type.
func (*ecdsaPublicKeyValue) Type() string {
	return "ecdsaPublicKey"
}

// ECDSAPublicKey creates and returns a new flag.Value compliant ECDSA PublicKey
// parser.
func ECDSAPublicKey(p *ecdsa.PublicKey) flag.Value {
	return &ecdsaPublicKeyValue{dst: p}
}
