package flagvars

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"strings"
)

// certificateValue adapts x509.Certificate for use as a flag. Value of flag
// is PEM encoded.
type certificateValue struct {
	dst *x509.Certificate
}

// String implements flag.Value.String.
func (v certificateValue) String() string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: v.dst.Raw,
	}))
}

// Set implements flag.Value.Set.
func (v *certificateValue) Set(value string) error {
	value = strings.Replace(value, `\n`, "\n", -1)
	block, _ := pem.Decode([]byte(value))
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("failed to find a suitable pem block type")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	*v.dst = *cert
	return nil
}

// Type implements flag.Value.Type.
func (*certificateValue) Type() string {
	return "certificate"
}

// Certificate creates and returns a new flag.Value compliant Certificate
// parser.
func Certificate(c *x509.Certificate) flag.Value {
	return &certificateValue{dst: c}
}
