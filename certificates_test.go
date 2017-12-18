package pki

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"testing"

	"crypto/rand"
	"crypto/rsa"

	"crypto/ecdsa"

	"crypto/elliptic"

	"crypto"
	"io"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertificateToPem(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/cert.pem")
	require.Nil(t, err)

	block, rem := pem.Decode(data)
	require.NotNil(t, block)
	require.Len(t, rem, 0)

	der := block.Bytes
	cert, err := x509.ParseCertificate(der)
	require.Nil(t, err)

	result := CertificateToPem(cert)
	require.EqualValues(t, data, result)
}

func TestPemToCertificate(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/cert.pem")
	require.Nil(t, err)

	_, err = ParsePemCertificate(data)
	require.Nil(t, err)

	baddata := []byte("baddata")
	_, err = ParsePemCertificate(baddata)
	require.NotNil(t, err)

	data, err = ioutil.ReadFile("testdata/key.pem")
	require.Nil(t, err)
	_, err = ParsePemCertificate(data)
	require.NotNil(t, err)
}

func TestCreateSimpleCertRequest(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.Nil(t, err)

	subject := Subject{
		Country:            "GB",
		Province:           "England",
		Locality:           "Cambridge",
		Organization:       "github.com/dmjones500",
		OrganizationalUnit: "pki",
		CommonName:         "Test Cert 2",
		EmailAddress:       "djones@apache.org",
	}

	req, err := CreateSimpleCertRequest(subject, key)
	require.Nil(t, err)

	require.Nil(t, req.CheckSignature())

	require.Equal(t, subject.Country, req.Subject.Country[0])
	require.Equal(t, subject.Province, req.Subject.Province[0])
	require.Equal(t, subject.Locality, req.Subject.Locality[0])
	require.Equal(t, subject.Organization, req.Subject.Organization[0])
	require.Equal(t, subject.OrganizationalUnit, req.Subject.OrganizationalUnit[0])
	require.Equal(t, subject.CommonName, req.Subject.CommonName)
	require.Equal(t, subject.EmailAddress, req.EmailAddresses[0])
}

func TestCreateSimpleCertRequest_Empty(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.Nil(t, err)

	subject := Subject{
		CommonName: "Test Cert 3",
	}

	req, err := CreateSimpleCertRequest(subject, key)
	require.Nil(t, err)

	require.Nil(t, req.CheckSignature())

	require.Nil(t, req.Subject.Country)
	require.Nil(t, req.Subject.Province)
	require.Nil(t, req.Subject.Locality)
	require.Nil(t, req.Subject.Organization)
	require.Nil(t, req.Subject.OrganizationalUnit)
	require.Equal(t, subject.CommonName, req.Subject.CommonName)
	require.Nil(t, req.EmailAddresses)
}

func TestPrivateKeyToPem(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.Nil(t, err)

	pemBytes, err := PrivateKeyToPem(key, nil)
	require.Nil(t, err)

	block, _ := pem.Decode(pemBytes)
	_, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	require.Nil(t, err)

	eckey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.Nil(t, err)

	pemBytes, err = PrivateKeyToPem(eckey, nil)
	require.Nil(t, err)

	block, _ = pem.Decode(pemBytes)
	_, err = x509.ParseECPrivateKey(block.Bytes)
	require.Nil(t, err)
}

func TestPrivateKeyToPemWithPassword(t *testing.T) {
	const password = "foobar1234"

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.Nil(t, err)

	pemBytes, err := PrivateKeyToPem(key, []byte(password))
	require.Nil(t, err)

	block, _ := pem.Decode(pemBytes)
	der, err := x509.DecryptPEMBlock(block, []byte(password))
	require.Nil(t, err)

	_, err = x509.ParsePKCS1PrivateKey(der)
	require.Nil(t, err)

	eckey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.Nil(t, err)

	pemBytes, err = PrivateKeyToPem(eckey, []byte(password))
	require.Nil(t, err)

	block, _ = pem.Decode(pemBytes)
	der, err = x509.DecryptPEMBlock(block, []byte(password))
	require.Nil(t, err)
	_, err = x509.ParseECPrivateKey(der)
	require.Nil(t, err)
}

type badKey int

func (badKey) Public() crypto.PublicKey {
	return nil
}

func (badKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return nil, nil
}

func TestPrivateKeyToPemBadKey(t *testing.T) {
	_, err := PrivateKeyToPem(badKey(0), nil)
	assert.NotNil(t, err)
}
