package flagvars

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"reflect"
	"testing"
)

func TestRSAPrivateKey(t *testing.T) {
	privPEM := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA10UIaWvtbSGfNLY5Pq54YXSifAkxl/rpL+VPnRMIOfZpT6bv
TMKTFN0mzrYP7WDpXOG4Aue8APM33IWpSeDuM/pmfJU5Voj9eSi9FrzAVOOMY/yw
lzBKZ+qSFPccArUq0rqmniDBdV3lO5VfO4tNG5wDXDicM9Qf1kfmtlZk3XYmBEyt
PN6VDIU1zRguxoV/W8kVglfFEPRd2cGdksmBWPB+Av3itjWYfYC0kdOflmRDqCh5
qymW9tlsMkMfev6dag5cV2dWd10iCWtsBixD++gsKsEO3w9LbDkb89LobQPvUg4e
8/LVwnie6ZHH9Ha56zEENoCrHdjrHP7SFfCEVQIDAQABAoIBAQCTFsxEnEZCxzJt
ZgV/Wt9OV8+eSPnmCr/CxkC75wE7+a7DiiEApgKxwtp9a9E+NXW+zUxaT9UaIRYO
TBX8MQER6wqUHbJr+naXjsqE+rvARSrsNwDCjXCJyLHAOYieIQP9sSOf8Gm/tESp
jcrgeLJbJyL0pIm2sD6Av+hYtnd9CbiFos3GGfQNlUrp762gZP0S0Wq7BsFvsZmo
AXTTjv4Xhhb3TQO2IJ3uQDuhDddJ9Pe5Zmx1JJMayhRJtgU1hcRUxDCdrQBVatYg
o13s6NfiqaxSv+Ma7APE//uflZVwFl0h/Y3oYvurBcrCT+P6zonBZltRrb9kCGkP
a5bu7NUBAoGBAPab0s3Y/VxzUlf43mct/q0DIvYE+j+IttQb6TCSMCIOOwbEjpTv
SHl1u7FeXnDBXJpFQ+Du7gu6JsQNvQGwVWokcFPASceU5ZAOXTcgQoWlcuuIRxNV
Imh7QiasaKFABMByn3zSSCSJ8QykjBMvRTLlhYDH/X/5eak7yfKKkMUlAoGBAN93
r8wVvlviqe8ZJ+w6mHGqCt4h3VMYfj60Yiat70aDGUR+R9FKxwv3J8/D1XPY0w6h
ICfLwO2AcnNX2Q/7fRQctGPSAzQWYXXJymnEDbWVFTFJy7MroBr7vJL/YEd2p1e2
O5I0abP0FElvvwhtL30whdLrHEg99jiqRoNrnNNxAoGABywM+3OeGrw33tscDMAn
sfxvXdxTMtnVB2Iwa/s0bykeylmZE/fJkc68wLHP6VOWT95H1Rjdz3WAfx8vKgdo
1IduxODIxIcuDfx89Yd4p85iAzuZZZSKRaOgDuPgvx/Pg5FR1h1/f6CLZCS89inf
x1Uphs9KLhihUyyr+OPSxgkCgYEAgGtpjWDZejhx68OLG8g4nulXQXw4km467pH+
7bd7EAx60s+3OeE9LfUk3dLusZpi/788mWIQRuxP2VUcmoCtyocMa2jfCmnqLCSA
u/M85aL9AMwl0Zs6cQdFwTwc+jSHynIhHc4dCJs1pVYgdBk69ziRTzppkGJ7Qukn
iJKpFyECgYB1qvOkHVvWJi1uBIWY16/zdp5ZeLRzB50lV+D2Mo7xlDX2DNFTWD9q
htj3AL2AjIvVB7GhiE959SQsJ1W7DQtqf7Wk+El4B+/ILJ0yZ3kECnxzmw+6TC0t
0F1zXSKRqorxK/eCiUXkTcn4mFPs30F+NGCFkof6mDzDiDp1rsr7mA==
-----END RSA PRIVATE KEY-----`

	var gotPriv rsa.PrivateKey
	privKeyValue := RSAPrivateKey(&gotPriv)
	privKeyValue.Set(privPEM)

	block, _ := pem.Decode([]byte(privPEM))
	expectedPriv, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

	if !reflect.DeepEqual(gotPriv, *expectedPriv) {
		t.Fatalf("got: %v, expected %v", gotPriv, expectedPriv)
	}
}

func TestRSAPublicKey(t *testing.T) {
	pubPEM := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA10UIaWvtbSGfNLY5Pq54
YXSifAkxl/rpL+VPnRMIOfZpT6bvTMKTFN0mzrYP7WDpXOG4Aue8APM33IWpSeDu
M/pmfJU5Voj9eSi9FrzAVOOMY/ywlzBKZ+qSFPccArUq0rqmniDBdV3lO5VfO4tN
G5wDXDicM9Qf1kfmtlZk3XYmBEytPN6VDIU1zRguxoV/W8kVglfFEPRd2cGdksmB
WPB+Av3itjWYfYC0kdOflmRDqCh5qymW9tlsMkMfev6dag5cV2dWd10iCWtsBixD
++gsKsEO3w9LbDkb89LobQPvUg4e8/LVwnie6ZHH9Ha56zEENoCrHdjrHP7SFfCE
VQIDAQAB
-----END PUBLIC KEY-----`

	var gotPub rsa.PublicKey
	pubKeyValue := RSAPublicKey(&gotPub)
	pubKeyValue.Set(pubPEM)

	block, _ := pem.Decode([]byte(pubPEM))
	expectedPub, _ := x509.ParsePKIXPublicKey(block.Bytes)

	if !reflect.DeepEqual(gotPub, *expectedPub.(*rsa.PublicKey)) {
		t.Fatalf("got: %v, expected %v", gotPub, expectedPub)
	}
}
