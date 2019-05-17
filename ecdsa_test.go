package flagvars

import (
	"fmt"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"math/big"
	"reflect"
	"testing"
)

func TestECDSAPrivateKey(t *testing.T) {
	var gotPriv ecdsa.PrivateKey
	_ = ECDSAPrivateKey(&gotPriv, elliptic.P256(), "75ea374d8435f0332284bd31081f4fcca15e4fc5e712c24455b142784f794c19")

	privData, _ := hex.DecodeString("0709b4a77069b4aa058082a3fba9598420ac82d11b6c946a49276eb98f1b402d3b4771c0c815ea68")
	expectedPriv, err := ecdsa.GenerateKey(elliptic.P256(), bytes.NewReader(privData))
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(gotPriv, *expectedPriv) {
		t.Fatalf("got: %v, expected %v", gotPriv, expectedPriv)
	}
}

func TestECDSAPublicKey(t *testing.T) {
	var gotPub ecdsa.PublicKey
	_ = ECDSAPublicKey(&gotPub, elliptic.P256(), "04a36af3acb87ca443a18f324fe903c80706763513a76f1cbef841963bcfc1b7fc6950a2972c72d74109e653ab30042e7d99ba4ec7e7497b587e575b11c360efd6")

	expectedPub := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     bigint("73915961888840763171356037475693787615110721015667185068062180264366888302588", 10),
		Y:     bigint("47635319024966351949879913400613681164194278637841723803947724495437902704598", 10),
	}

	if !reflect.DeepEqual(gotPub, expectedPub) {
		t.Fatalf("got: %v, expected %v", gotPub, expectedPub)
	}
}

func bigint(s string, base int) *big.Int {
	bi, ok := (&big.Int{}).SetString(s, base)
	if !ok {
		panic("unable to set big int")
	}
	return bi
}
