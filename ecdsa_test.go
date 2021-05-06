package flagvars

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"reflect"
	"testing"
)

func TestECDSAPrivateKey(t *testing.T) {
	privPEM := `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIF6liKVb+9+rKJPm/bcm1C712j+Um5aIdj1A9WuSYaz2oAoGCCqGSM49
AwEHoUQDQgAEFXfT0IAJhNSHKV+U6WE78PD7qnmOYh0aD0NY2qZxSALwbsuNXZMl
ELIrWAret2yxju6fMs2Jg7vhcoH++MfgRw==
-----END EC PRIVATE KEY-----`

	var gotPriv ecdsa.PrivateKey
	privKeyValue := ECDSAPrivateKey(&gotPriv)
	privKeyValue.Set(privPEM)

	block, _ := pem.Decode([]byte(privPEM))
	expectedPriv, _ := x509.ParseECPrivateKey(block.Bytes)

	if !reflect.DeepEqual(gotPriv, *expectedPriv) {
		t.Fatalf("got: %v, expected %v", gotPriv, expectedPriv)
	}
}

func TestECDSAPublicKey(t *testing.T) {
	pubPEM := `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFXfT0IAJhNSHKV+U6WE78PD7qnmO
Yh0aD0NY2qZxSALwbsuNXZMlELIrWAret2yxju6fMs2Jg7vhcoH++MfgRw==
-----END PUBLIC KEY-----`

	var gotPub ecdsa.PublicKey
	pubKeyValue := ECDSAPublicKey(&gotPub)
	pubKeyValue.Set(pubPEM)

	block, _ := pem.Decode([]byte(pubPEM))
	expectedPub, _ := x509.ParsePKIXPublicKey(block.Bytes)

	if !reflect.DeepEqual(gotPub, *expectedPub.(*ecdsa.PublicKey)) {
		t.Fatalf("got: %v, expected %v", gotPub, expectedPub)
	}
}

func TestECDSAPublicKeyVar(t *testing.T) {
	var pub ecdsa.PublicKey
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	fs.Var(ECDSAPublicKey(&pub), "public-key", "public key")
}

func TestECDSAPrivateKeyVar(t *testing.T) {
	var priv ecdsa.PrivateKey
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	fs.Var(ECDSAPrivateKey(&priv), "private-key", "private key")
}
