// Package cert manages a self-signed CA for agent mTLS enrollment.
package cert

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// CAManager manages a self-signed CA for agent mTLS enrollment.
// In production, replace with your PKI solution.
type CAManager struct {
	caCert   *x509.Certificate
	caKey    crypto.PrivateKey
	caPEM    []byte
	caKeyPEM []byte
}

// NewCAManager creates or loads a CA from PEM files at certDir.
// If files don't exist, generates a new 4096-bit RSA CA cert valid 10 years.
func NewCAManager(certDir string) (*CAManager, error) {
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return nil, fmt.Errorf("CA証明書ディレクトリの作成に失敗しました: %w", err)
	}

	certPath := filepath.Join(certDir, "ca.crt")
	keyPath := filepath.Join(certDir, "ca.key")

	// Try to load existing CA files.
	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)

	if certErr == nil && keyErr == nil {
		// Parse existing CA.
		certBlock, _ := pem.Decode(certPEM)
		if certBlock == nil {
			return nil, fmt.Errorf("CA証明書PEMの解析に失敗しました")
		}
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("CA証明書の解析に失敗しました: %w", err)
		}

		keyBlock, _ := pem.Decode(keyPEM)
		if keyBlock == nil {
			return nil, fmt.Errorf("CA秘密鍵PEMの解析に失敗しました")
		}
		key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			// Try PKCS1 as fallback.
			rsaKey, err2 := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
			if err2 != nil {
				return nil, fmt.Errorf("CA秘密鍵の解析に失敗しました: %w", err)
			}
			key = rsaKey
		}

		return &CAManager{
			caCert:   cert,
			caKey:    key,
			caPEM:    certPEM,
			caKeyPEM: keyPEM,
		}, nil
	}

	// Generate new CA.
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("CA秘密鍵の生成に失敗しました: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("シリアル番号の生成に失敗しました: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "EDR Platform CA",
			Organization: []string{"EDR Platform"},
		},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("CA証明書の生成に失敗しました: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("生成されたCA証明書の解析に失敗しました: %w", err)
	}

	// Encode to PEM.
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("CA秘密鍵のエンコードに失敗しました: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	// Persist to disk.
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return nil, fmt.Errorf("CA証明書の保存に失敗しました: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return nil, fmt.Errorf("CA秘密鍵の保存に失敗しました: %w", err)
	}

	return &CAManager{
		caCert:   cert,
		caKey:    key,
		caPEM:    certPEM,
		caKeyPEM: keyPEM,
	}, nil
}

// SignAgent signs a CSR (PEM) for an agent, returns cert PEM valid 1 year.
func (m *CAManager) SignAgent(csrPEM []byte, agentID string) ([]byte, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, fmt.Errorf("CSR PEMのデコードに失敗しました")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("CSRの解析に失敗しました: %w", err)
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR署名の検証に失敗しました: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("シリアル番号の生成に失敗しました: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "agent:" + agentID,
			Organization: []string{"EDR Platform"},
		},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, m.caCert, csr.PublicKey, m.caKey)
	if err != nil {
		return nil, fmt.Errorf("エージェント証明書の署名に失敗しました: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), nil
}

// CAPem returns the CA certificate PEM for agents to trust.
func (m *CAManager) CAPem() []byte {
	return m.caPEM
}

// TLSConfig returns a *tls.Config requiring client certs signed by this CA.
func (m *CAManager) TLSConfig() *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(m.caCert)
	return &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  pool,
		MinVersion: tls.VersionTLS12,
	}
}
