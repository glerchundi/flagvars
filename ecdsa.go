package flagvars

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"strings"
)

// ecdsaPrivateKeyValue adapts ecdsa.PrivateKey for use as a flag. Value of flag
// is HEX encoded.
type ecdsaPrivateKeyValue ecdsa.PrivateKey

// String implements flag.Value.String.
func (ecdsaPrivateKey ecdsaPrivateKeyValue) String() string {
	return "<redacted>"
}

// Set implements flag.Value.Set.
func (ecdsaPrivateKey *ecdsaPrivateKeyValue) Set(value string) error {
	data, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return err
	}

	if len(data)*8 != ecdsaPrivateKey.Params().BitSize {
		return fmt.Errorf("invalid length expected %d bits", ecdsaPrivateKey.Params().BitSize)
	}

	// https://golang.org/src/crypto/ecdsa/ecdsa.go?s=2956:3027#L95
	k := (&big.Int{}).SetBytes(data)
	ecdsaPrivateKey.D = k
	ecdsaPrivateKey.PublicKey.X, ecdsaPrivateKey.PublicKey.Y = ecdsaPrivateKey.Curve.ScalarBaseMult(k.Bytes())

	return nil
}

// Type implements flag.Value.Type.
func (*ecdsaPrivateKeyValue) Type() string {
	return "ecdsaPrivateKey"
}

// ECDSAPrivateKey creates and returns a new flag.Value compliant ECDSA
// PrivateKey parser.
func ECDSAPrivateKey(p *ecdsa.PrivateKey, c elliptic.Curve, value string) flag.Value {
	epk := &ecdsaPrivateKeyValue{
		PublicKey: ecdsa.PublicKey{
			Curve: c,
		},
	}
	if value != "" {
		_ = epk.Set(value)
	}
	*p = ecdsa.PrivateKey(*epk)
	return epk
}

// ecdsaPublicKeyValue adapts ecdsa.PublicKey for use as a flag. Value of flag
// is HEX encoded.
type ecdsaPublicKeyValue ecdsa.PublicKey

// String implements flag.Value.String.
func (ecdsaPublicKey ecdsaPublicKeyValue) String() string {
	return hex.EncodeToString(elliptic.Marshal(ecdsaPublicKey.Curve, ecdsaPublicKey.X, ecdsaPublicKey.Y))
}

// Set implements flag.Value.Set.
func (ecdsaPublicKey *ecdsaPublicKeyValue) Set(value string) error {
	data, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return err
	}
	ecdsaPublicKey.X, ecdsaPublicKey.Y = elliptic.Unmarshal(ecdsaPublicKey.Curve, data)
	return nil
}

// Type implements flag.Value.Type.
func (*ecdsaPublicKeyValue) Type() string {
	return "ecdsaPrivateKey"
}

// ECDSAPublicKey creates and returns a new flag.Value compliant ECDSA PublicKey
// parser.
func ECDSAPublicKey(p *ecdsa.PublicKey, c elliptic.Curve, value string) flag.Value {
	epk := &ecdsaPublicKeyValue{
		Curve: c,
	}
	if value != "" {
		_ = epk.Set(value)
	}
	*p = ecdsa.PublicKey(*epk)
	return epk
}
