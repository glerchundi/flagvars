package flagvars

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"flag"
	"math/big"
	"strings"
)

// ecdsaPrivateKeyValue adapts ecdsa.PrivateKey for use as a flag. Value of flag
// is HEX encoded.
type ecdsaPrivateKeyValue struct {
	dst *ecdsa.PrivateKey
}

// String implements flag.Value.String.
func (v ecdsaPrivateKeyValue) String() string {
	return "<redacted>"
}

// Set implements flag.Value.Set.
func (v *ecdsaPrivateKeyValue) Set(value string) error {
	data, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return err
	}

	// https://golang.org/src/crypto/ecdsa/ecdsa.go?s=2956:3027#L95
	priv := ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256()}}
	k := (&big.Int{}).SetBytes(data)
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = priv.Curve.ScalarBaseMult(k.Bytes())
	*v.dst = priv

	return nil
}

// Type implements flag.Value.Type.
func (*ecdsaPrivateKeyValue) Type() string {
	return "ecdsaPrivateKey"
}

// ECDSAPrivateKey creates and returns a new flag.Value compliant ECDSA
// PrivateKey parser.
func ECDSAPrivateKey(p *ecdsa.PrivateKey, c elliptic.Curve, value string) flag.Value {
	epk := &ecdsaPrivateKeyValue{dst: p}
	if value != "" {
		_ = epk.Set(value)
	}
	return epk
}

// ecdsaPublicKeyValue adapts ecdsa.PublicKey for use as a flag. Value of flag
// is HEX encoded.
type ecdsaPublicKeyValue struct {
	dst *ecdsa.PublicKey
}

// String implements flag.Value.String.
func (v ecdsaPublicKeyValue) String() string {
	if v.dst != nil || v.dst.Curve == nil || v.dst.X == nil || v.dst.Y == nil {
		return ""
	}
	return hex.EncodeToString(elliptic.Marshal(v.dst.Curve, v.dst.X, v.dst.Y))
}

// Set implements flag.Value.Set.
func (v *ecdsaPublicKeyValue) Set(value string) error {
	data, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return err
	}
	pub := ecdsa.PublicKey{Curve: elliptic.P256()}
	pub.X, pub.Y = elliptic.Unmarshal(pub.Curve, data)
	*v.dst = pub

	return nil
}

// Type implements flag.Value.Type.
func (*ecdsaPublicKeyValue) Type() string {
	return "ecdsaPrivateKey"
}

// ECDSAPublicKey creates and returns a new flag.Value compliant ECDSA PublicKey
// parser.
func ECDSAPublicKey(p *ecdsa.PublicKey, c elliptic.Curve, value string) flag.Value {
	epk := &ecdsaPublicKeyValue{dst: p}
	if value != "" {
		_ = epk.Set(value)
	}
	return epk
}
