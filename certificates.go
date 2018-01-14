// Package pki provides helper methods for manipulating X.509 objects.
package pki

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"

	"github.com/pkg/errors"
)

const (
	certificateType    = "CERTIFICATE"
	encryptedKeyType   = "ENCRYPTED PRIVATE KEY"
	unencryptedKeyType = "PRIVATE KEY"
)

// CertificateToPem converts a certificate into PEM format
func CertificateToPem(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  certificateType,
			Bytes: cert.Raw,
		})
}

// ParsePemCertificate reads a certificate from PEM format. Only the
// first PEM object in the input data is read.
func ParsePemCertificate(pemCert []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemCert)

	if block == nil {
		return nil, errors.New("no PEM data found in input")
	}
	if block.Type != certificateType {
		return nil, errors.Errorf("expected type '%s', but found '%s", certificateType, block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	return cert, errors.WithMessage(err, "failed to parse certificate")
}

// Subject contains the basic subject info for a certificate request
type Subject struct {
	Country            string
	Province           string
	Locality           string
	Organization       string
	OrganizationalUnit string
	CommonName         string
	EmailAddress       string
}

func subjectToName(s Subject) pkix.Name {
	return pkix.Name{
		Country:            makeSlice(s.Country),
		Province:           makeSlice(s.Province),
		Locality:           makeSlice(s.Locality),
		Organization:       makeSlice(s.Organization),
		OrganizationalUnit: makeSlice(s.OrganizationalUnit),
		CommonName:         s.CommonName,
	}
}

func makeSlice(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

// CreateSimpleCertRequest makes a certificate request for the supplied subject.
func CreateSimpleCertRequest(subject Subject, key crypto.Signer) (*x509.CertificateRequest, error) {

	// Go selects good defaults for signature algorithm
	template := x509.CertificateRequest{
		Subject: subjectToName(subject),
	}

	if subject.EmailAddress != "" {
		template.EmailAddresses = []string{subject.EmailAddress}
	}

	data, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to create request")
	}

	result, err := x509.ParseCertificateRequest(data)
	return result, errors.WithMessage(err, "failed to create request")
}

// PrivateKeyToPem converts an RSA or ECDSA private key to a PEM file, encrypting
// it with the password if supplied (and non-empty).
func PrivateKeyToPem(key crypto.Signer, password []byte) ([]byte, error) {
	var keyData []byte
	var err error

	switch k := key.(type) {
	case *rsa.PrivateKey:
		keyData = x509.MarshalPKCS1PrivateKey(k)
	case *ecdsa.PrivateKey:
		keyData, err = x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, errors.WithMessage(err, "could not marshal private key")
		}
	default:
		return nil, errors.New("unknown private key type")
	}

	if password != nil && len(password) > 0 {
		block, err := x509.EncryptPEMBlock(rand.Reader, encryptedKeyType, keyData, password, x509.PEMCipher3DES)
		if err != nil {
			return nil, errors.WithMessage(err, "could not encrypted private key")
		}
		return pem.EncodeToMemory(block), nil
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  unencryptedKeyType,
		Bytes: keyData,
	}), nil
}

// IsRootCACert tests whether a certificate is a root CA certificate by checking the
// certificate is self-signed and validating the Basic Constraints, if present.
//
// WARNING: Do not use this function to determine whether to trust the certificate.
func IsRootCACert(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawSubject, cert.RawIssuer) && (!cert.BasicConstraintsValid || cert.IsCA)
}
