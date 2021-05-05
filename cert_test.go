package flagvars

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
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

func TestCertPool(t *testing.T) {
	certPEM1 := `-----BEGIN CERTIFICATE-----
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
	certPEM2 := `-----BEGIN CERTIFICATE-----
MIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAwVzELMAkGA1UEBhMCQkUx
GTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jvb3QgQ0ExGzAZBgNVBAMTEkds
b2JhbFNpZ24gUm9vdCBDQTAeFw05ODA5MDExMjAwMDBaFw0yODAxMjgxMjAwMDBaMFcxCzAJBgNV
BAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYD
VQQDExJHbG9iYWxTaWduIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDa
DuaZjc6j40+Kfvvxi4Mla+pIH/EqsLmVEQS98GPR4mdmzxzdzxtIK+6NiY6arymAZavpxy0Sy6sc
THAHoT0KMM0VjU/43dSMUBUc71DuxC73/OlS8pF94G3VNTCOXkNz8kHp1Wrjsok6Vjk4bwY8iGlb
Kk3Fp1S4bInMm/k8yuX9ifUSPJJ4ltbcdG6TRGHRjcdGsnUOhugZitVtbNV4FpWi6cgKOOvyJBNP
c1STE4U6G7weNLWLBYy5d4ux2x8gkasJU26Qzns3dLlwR5EiUWMWea6xrkEmCMgZK9FGqkjWZCrX
gzT/LCrBbBlDSgeF59N89iFo7+ryUp9/k5DPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBRge2YaRQ2XyolQL30EzTSo//z9SzANBgkqhkiG9w0BAQUF
AAOCAQEA1nPnfE920I2/7LqivjTFKDK1fPxsnCwrvQmeU79rXqoRSLblCKOzyj1hTdNGCbM+w6Dj
Y1Ub8rrvrTnhQ7k4o+YviiY776BQVvnGCv04zcQLcFGUl5gE38NflNUVyRRBnMRddWQVDf9VMOyG
j/8N7yy5Y0b2qvzfvGn9LhJIZJrglfCm7ymPAbEVtQwdpf5pLGkkeB6zpxxxYu7KyJesF12KwvhH
hm4qxFYxldBniYUr+WymXUadDKqC5JlR3XC321Y9YeRq4VzW9v493kHMB65jUr9TU/Qr6cf9tveC
X4XSQRjbgbMEHMUfpIBvFSDJ3gyICh3WZlXi/EjJKSZp4A==
-----END CERTIFICATE-----`

	var gotCertPool x509.CertPool
	certPoolValue := CertPool(&gotCertPool)
	certPoolValue.Set(fmt.Sprintf("%s\n%s", certPEM1, certPEM2))

	block1, _ := pem.Decode([]byte(certPEM1))
	cert1, _ := x509.ParseCertificate(block1.Bytes)
	block2, _ := pem.Decode([]byte(certPEM2))
	cert2, _ := x509.ParseCertificate(block2.Bytes)
	expectedCertPool := x509.NewCertPool()
	expectedCertPool.AddCert(cert1)
	expectedCertPool.AddCert(cert2)

	if len(gotCertPool.Subjects()) != 2 {
		t.Fatalf("got: %d, expected %d", len(gotCertPool.Subjects()), 2)
	}

	if !reflect.DeepEqual(gotCertPool.Subjects(), expectedCertPool.Subjects()) {
		t.Fatalf("got: %v, expected %v", gotCertPool, expectedCertPool)
	}
}

func TestTLSCertificate(t *testing.T) {
	keyPEM := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAx2BgkJC+MXOHYzTbY1nLjwBi5okSyPrqJqZnHCe3/b1GYLv4
DvaFUp0JVUTV+C0tE52Y8kDLKPvWTbfbHcg6IZDFZktDtu5A/YM9j8/qLWINMOE1
V9KSaXN48L0qF3ajca4/hZPWqbSBbH4qTdnBO7hQONPq2UpcjQ/pUgf1bzSiC0q6
elIJqAqUURSdDvFY2FfqlO0WYfRxSL7VusPbi3jdow/pO1RlbeoQA6XaEs0IgHq2
efvHniHJgI/xuQjhmxgJ27su9/wZqPW+9vFF6Om/uxncl2Io/6Xr/9DnCKE+1ihU
CSclc6MHPsshB4SqbiqgsvSjcz0Kpu43v/wabQIDAQABAoIBADbktjGXaIY9BL2v
w+eqxXzt4k0O2Hk1fFp/3kvGM8ZM4p+noTidbz+7tOIhPbhC1/Japc2tQUJbdDmZ
sV6VzkuHjJIJju9C0en6xGxgFl3AbVlT6FfxxhX6kQXXT0t+gqm+DAc/GQ9If4nb
gtJEbgt/R7cdwb9p1emQw/Ct+ElRe+xTZ36Vw1wgyLUmJJB3IAj5JTqeBwqFQOvt
fV3zuS/zzzfXuhShwJMpsdHVJJzULeZPU1nhxAeTKGSF8XwBOL0hSL4ikS0s/U0P
RoTL4flKsC3YwFOVq3Cn8bZW0xI5h/UmISJhkyj8th6PV72NNCBJ5ogLAr24TqH4
Emvj14ECgYEA1uLZXRue7vScYbpEUud+crM6ejBNOhib968J/Au1yf6aS9dgALVP
MaZXg2GKRJWLHr3om4vJOUP14970NkJKlCkqJD8uUjKtGchcaNELPQjwM7HjmBAW
VHANjHFJTEIGG/v9wwVE/ZUf9ljqE7jFA+DkJ5GrSfomwU1eKEthmQkCgYEA7YXc
9zD/dmHg4LpbBP7R8syC4Ijl+ux/huuBh6GIbyLKCagtL3TFSNInDPO6rT1YdgLZ
7WZSXaQ98aq2Q0vNRiXMccrsx6nPj20arRaZROZgz7s5W62Eexbz/b5rUrAuXzJF
CVF6raZUxUKlF1b2ybc93ScqqjfWfoyZebE8w0UCgYEApxz+O+maHW2AHIR2VB8R
+HOoG5Rqyq6OxP2Mf0ZAFxn4ttiFIaffMdaSImt90z6VVdANEMKSOAXBOXiPZY8C
XtzwmAXGqUgd1Ho8W4uO+OV1oE5MmFqScxI9hyYnAbYq+CJtw/faIneRxsx5JeNA
3HZOGPOxSTPQZe4cNqwA97kCgYBfVvYk+rPwDsW3LtZOIQKg1NpLymeV2swtmeZ6
TKp5AZvbWHgarmJqIoCuQD7UPuV9KRPUqNey4rRChuV2Cb0xxQZVPsDgPBcmWQL2
KzYGY/rEJ0CUvgeJaOMzHPXzUOisKX9wiBYYEcXBEEk4Hx4cRcM9O/VyMcuVLFaG
dFARiQKBgQCHKrb0SzYVnaEWFR+GP+sJMfxrhq/N8m+WcCpoQ/UIvguMWmFKtVtC
WVTd3XNizIpuNpDgGI4qvIwmEs7UhAzemxasYoP3y3FO2dT0QGC+T1SX/BsW6AiO
fi06KUiLh/4rJtf2wph2wN8SPAY4yQkopFlDYTJNmhhYsKTGIhrpww==
-----END RSA PRIVATE KEY-----`
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

	var gotCert tls.Certificate
	certValue := TLSCertificate(&gotCert)
	certValue.Set(fmt.Sprintf("%s\n%s", keyPEM, certPEM))

	expectedCert, _ := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))

	if !reflect.DeepEqual(gotCert, expectedCert) {
		t.Fatalf("got: %v, expected %v", gotCert, expectedCert)
	}
}

func TestCertificateVar(t *testing.T) {
	var cert x509.Certificate
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	fs.Var(Certificate(&cert), "cert", "certificate")
}

func TestCertificatesVar(t *testing.T) {
	var certs []*x509.Certificate
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	fs.Var(Certificates(&certs), "certs", "certificates")
}

func TestCertPoolVar(t *testing.T) {
	var certPool x509.CertPool
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	fs.Var(CertPool(&certPool), "cert-pool", "certificate pool")
}

func TestTLSCertificateVar(t *testing.T) {
	var tlsCert tls.Certificate
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	fs.Var(TLSCertificate(&tlsCert), "tls-cert", "TLS certificate")
}
