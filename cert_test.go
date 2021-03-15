package flagvars

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"reflect"
	"testing"
)

func TestCertificate(t *testing.T) {
	certPEM := `-----BEGIN CERTIFICATE-----
MIIDADCCAeigAwIBAgIRAMlZFfrjDjpriu1r+XIr1kwwDQYJKoZIhvcNAQELBQAw
EjEQMA4GA1UEChMHQWNtZSBDbzAeFw0xODA4MDIxMTI0MTlaFw0xOTA4MDIxMTI0
MTlaMBIxEDAOBgNVBAoTB0FjbWUgQ28wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDHYGCQkL4xc4djNNtjWcuPAGLmiRLI+uompmccJ7f9vUZgu/gO9oVS
nQlVRNX4LS0TnZjyQMso+9ZNt9sdyDohkMVmS0O27kD9gz2Pz+otYg0w4TVX0pJp
c3jwvSoXdqNxrj+Fk9aptIFsfipN2cE7uFA40+rZSlyND+lSB/VvNKILSrp6Ugmo
CpRRFJ0O8VjYV+qU7RZh9HFIvtW6w9uLeN2jD+k7VGVt6hADpdoSzQiAerZ5+8ee
IcmAj/G5COGbGAnbuy73/Bmo9b728UXo6b+7GdyXYij/pev/0OcIoT7WKFQJJyVz
owc+yyEHhKpuKqCy9KNzPQqm7je//BptAgMBAAGjUTBPMA4GA1UdDwEB/wQEAwIF
oDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMBoGA1UdEQQTMBGC
CWxvY2FsaG9zdIcEfwAAATANBgkqhkiG9w0BAQsFAAOCAQEAlDF2c4ktrz1BJcQL
PhyynqOmLCJiPw/A9vSCOuaH2RduHufiO80RKW9KRiLsAAvSToAsFrTNlTL3Jdjp
UnWjal+gMh3fU+Fw3lGlq/UeYxMjZsTATazy2D2dJWwv0PUWo7dE0w/Thh1SdhEU
cNpoIDTsrnfa4P300XK+ej5A6gVYa++adAh3QdjLAzOfDxIInMwinMIQy9kACPvd
XNZ4AfD+wsH0dHTFPr5k12ZJbPMljCFe/rmbDoEpxOwimBcnRohEgOIbKjwEUXRi
B+q7AnJ0Q1rK/J7ikSDFBBGlg8wHWz+FCINmyyv62qClErI4aA/WN6+ilINJV/gG
qgNGqQ==
-----END CERTIFICATE-----`

	var gotCert x509.Certificate
	certValue := Certificate(&gotCert)
	certValue.Set(certPEM)

	block, _ := pem.Decode([]byte(certPEM))
	expectedCert, _ := x509.ParseCertificate(block.Bytes)

	if !reflect.DeepEqual(gotCert, *expectedCert) {
		t.Fatalf("got: %v, expected %v", gotCert, expectedCert)
	}
}

func TestCertificates(t *testing.T) {
	certPEM := `-----BEGIN CERTIFICATE-----
MIIDADCCAeigAwIBAgIRAMlZFfrjDjpriu1r+XIr1kwwDQYJKoZIhvcNAQELBQAw
EjEQMA4GA1UEChMHQWNtZSBDbzAeFw0xODA4MDIxMTI0MTlaFw0xOTA4MDIxMTI0
MTlaMBIxEDAOBgNVBAoTB0FjbWUgQ28wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDHYGCQkL4xc4djNNtjWcuPAGLmiRLI+uompmccJ7f9vUZgu/gO9oVS
nQlVRNX4LS0TnZjyQMso+9ZNt9sdyDohkMVmS0O27kD9gz2Pz+otYg0w4TVX0pJp
c3jwvSoXdqNxrj+Fk9aptIFsfipN2cE7uFA40+rZSlyND+lSB/VvNKILSrp6Ugmo
CpRRFJ0O8VjYV+qU7RZh9HFIvtW6w9uLeN2jD+k7VGVt6hADpdoSzQiAerZ5+8ee
IcmAj/G5COGbGAnbuy73/Bmo9b728UXo6b+7GdyXYij/pev/0OcIoT7WKFQJJyVz
owc+yyEHhKpuKqCy9KNzPQqm7je//BptAgMBAAGjUTBPMA4GA1UdDwEB/wQEAwIF
oDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMBoGA1UdEQQTMBGC
CWxvY2FsaG9zdIcEfwAAATANBgkqhkiG9w0BAQsFAAOCAQEAlDF2c4ktrz1BJcQL
PhyynqOmLCJiPw/A9vSCOuaH2RduHufiO80RKW9KRiLsAAvSToAsFrTNlTL3Jdjp
UnWjal+gMh3fU+Fw3lGlq/UeYxMjZsTATazy2D2dJWwv0PUWo7dE0w/Thh1SdhEU
cNpoIDTsrnfa4P300XK+ej5A6gVYa++adAh3QdjLAzOfDxIInMwinMIQy9kACPvd
XNZ4AfD+wsH0dHTFPr5k12ZJbPMljCFe/rmbDoEpxOwimBcnRohEgOIbKjwEUXRi
B+q7AnJ0Q1rK/J7ikSDFBBGlg8wHWz+FCINmyyv62qClErI4aA/WN6+ilINJV/gG
qgNGqQ==
-----END CERTIFICATE-----`

	var gotCerts []*x509.Certificate
	certValue := Certificates(&gotCerts)
	certValue.Set(fmt.Sprintf("%s\n%s", certPEM, certPEM))

	block, _ := pem.Decode([]byte(certPEM))
	expectedCerts, err := x509.ParseCertificates(append(block.Bytes, block.Bytes...))
	if err != nil {
		panic(err)
	}

	if len(gotCerts) != 2 {
		t.Fatalf("got: %d, expected %d", len(gotCerts), 2)
	}

	if !reflect.DeepEqual(gotCerts, expectedCerts) {
		t.Fatalf("got: %v, expected %v", gotCerts, expectedCerts)
	}
}
