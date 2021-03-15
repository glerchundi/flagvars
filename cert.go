package flagvars

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"strings"
)

// certificateValue adapts x509.Certificate for use as a flag. Value of flag
// is PEM encoded.
type certificateValue struct {
	dst *x509.Certificate
}

// String implements flag.Value.String.
func (v certificateValue) String() string {
	if v.dst == nil {
		return ""
	}
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

// Certificate creates and returns a new flag.Value compliant Certificates
// parser.
func Certificate(c *x509.Certificate) flag.Value {
	return &certificateValue{dst: c}
}

// certificatesValue adapts arrays of x509.Certificate for use as a flag.
// Value of flag is PEM encoded.
type certificatesValue struct {
	dst *[]*x509.Certificate
}

// String implements flag.Value.String.
func (v certificatesValue) String() string {
	var buf bytes.Buffer
	for _, c := range *v.dst {
		fmt.Fprintln(&buf, string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.Raw,
		})))
	}
	return buf.String()
}

// Set implements flag.Value.Set.
func (v *certificatesValue) Set(value string) error {
	data := []byte(value)
	var blocks []byte
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode([]byte(data))
		if block == nil || block.Type != "CERTIFICATE" {
			return errors.New("failed to find a suitable pem block type")
		}
		blocks = append(blocks, block.Bytes...)
	}

	certs, err := x509.ParseCertificates(blocks)
	if err != nil {
		return err
	}
	*v.dst = certs
	return nil
}

// Type implements flag.Value.Type.
func (*certificatesValue) Type() string {
	return "certificates"
}

// Certificates creates and returns a new flag.Value compliant Certificates
// parser.
func Certificates(c *[]*x509.Certificate) flag.Value {
	return &certificatesValue{dst: c}
}
