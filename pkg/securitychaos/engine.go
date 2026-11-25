// Package securitychaos contains the Kubernetes Secret backed implementation of security faults.
package securitychaos

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/chaos-mesh/chaos-mesh/api/v1alpha1"
)

const (
	defaultCertificateKey = "tls.crt"
	defaultPrivateKeyKey  = "tls.key"
	backupLabelName       = "chaos-mesh.org/security-chaos-backup"
)

// Options controls how a security fault is materialized.
type Options struct {
	CertificateKey   string
	PrivateKeyKey    string
	CommonName       string
	DNSNames         []string
	KeyFailureMode   v1alpha1.SecurityChaosKeyFailureMode
	Now              func() time.Time
	BackupSecretName string
}

// Engine applies and recovers security faults on Kubernetes secrets.
type Engine struct {
	Client client.Client
	Now    func() time.Time
}

// NewEngine creates a security fault engine.
func NewEngine(client client.Client) *Engine {
	return &Engine{Client: client, Now: time.Now}
}

// Apply injects one security fault and returns the backup secret name.
func (e *Engine) Apply(ctx context.Context, target types.NamespacedName, action v1alpha1.SecurityChaosAction, options Options) (string, error) {
	if e == nil || e.Client == nil {
		return "", errors.New("security chaos engine client is required")
	}
	if options.Now == nil {
		options.Now = e.Now
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.BackupSecretName == "" {
		options.BackupSecretName = BackupName(target.Namespace, target.Name, target.Namespace, target.Name)
	}
	action = v1alpha1.NormalizeSecurityChaosAction(action)
	switch action {
	case v1alpha1.CertificateExpirationAction,
		v1alpha1.KeyRotationFailureAction,
		v1alpha1.CertificateCorruptionAction:
	default:
		return "", fmt.Errorf("unsupported security chaos action %q", action)
	}
	if action == v1alpha1.KeyRotationFailureAction {
		if options.KeyFailureMode == "" {
			options.KeyFailureMode = v1alpha1.MismatchedKeyFailure
		}
		switch options.KeyFailureMode {
		case v1alpha1.MismatchedKeyFailure, v1alpha1.CorruptedKeyFailure, v1alpha1.MissingKeyFailure:
		default:
			return "", fmt.Errorf("unsupported key rotation failure mode %q", options.KeyFailureMode)
		}
	}

	backupName := types.NamespacedName{Namespace: target.Namespace, Name: options.BackupSecretName}
	if _, err := ensureBackup(ctx, e.Client, target, backupName); err != nil {
		return "", err
	}

	err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		secret := &corev1.Secret{}
		if err := e.Client.Get(ctx, target, secret); err != nil {
			return err
		}
		if secret.Data == nil {
			secret.Data = make(map[string][]byte)
		}

		var err error
		switch action {
		case v1alpha1.CertificateExpirationAction:
			err = injectExpiredCertificate(secret, options, options.Now())
		case v1alpha1.KeyRotationFailureAction:
			err = injectKeyRotationFailure(secret, options)
		case v1alpha1.CertificateCorruptionAction:
			injectCorruptedCertificate(secret, options)
		}
		if err != nil {
			return err
		}
		return e.Client.Update(ctx, secret)
	})
	if err != nil {
		return "", err
	}

	return options.BackupSecretName, nil
}

// Recover restores the target secret from its backup and removes the backup.
func (e *Engine) Recover(ctx context.Context, target types.NamespacedName, backupName string) error {
	if e == nil || e.Client == nil {
		return errors.New("security chaos engine client is required")
	}
	if backupName == "" {
		backupName = BackupName(target.Namespace, target.Name, target.Namespace, target.Name)
	}
	backupKey := types.NamespacedName{Namespace: target.Namespace, Name: backupName}

	backup := &corev1.Secret{}
	err := e.Client.Get(ctx, backupKey, backup)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}

	targetSecret := &corev1.Secret{}
	err = e.Client.Get(ctx, target, targetSecret)
	switch {
	case apierrors.IsNotFound(err):
		return e.Client.Delete(ctx, backup)
	case err != nil:
		return err
	}

	err = retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		current := &corev1.Secret{}
		if err := e.Client.Get(ctx, target, current); err != nil {
			return err
		}
		current.Data = maps.Clone(backup.Data)
		if current.Data == nil {
			current.Data = map[string][]byte{}
		}
		return e.Client.Update(ctx, current)
	})
	if err != nil {
		return err
	}

	return e.Client.Delete(ctx, backup)
}

// BackupName returns a stable, DNS-safe backup secret name.
func BackupName(chaosNamespace, chaosName, targetNamespace, targetName string) string {
	sum := hashString(chaosNamespace + "/" + chaosName + "|" + targetNamespace + "/" + targetName)
	return "security-chaos-backup-" + sum[:16]
}

func ensureBackup(ctx context.Context, c client.Client, target, backupKey types.NamespacedName) (*corev1.Secret, error) {
	existing := &corev1.Secret{}
	err := c.Get(ctx, backupKey, existing)
	if err == nil {
		return existing, nil
	}
	if !apierrors.IsNotFound(err) {
		return nil, err
	}

	targetSecret := &corev1.Secret{}
	if err := c.Get(ctx, target, targetSecret); err != nil {
		return nil, fmt.Errorf("get target secret: %w", err)
	}

	backup := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      backupKey.Name,
			Namespace: backupKey.Namespace,
			Labels: map[string]string{
				backupLabelName: "true",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: maps.Clone(targetSecret.Data),
	}
	if backup.Data == nil {
		backup.Data = map[string][]byte{}
	}
	if err := c.Create(ctx, backup); err != nil && !apierrors.IsAlreadyExists(err) {
		return nil, fmt.Errorf("create backup secret: %w", err)
	}
	if err := c.Get(ctx, backupKey, existing); err != nil {
		return nil, err
	}
	return existing, nil
}

func injectExpiredCertificate(secret *corev1.Secret, options Options, now time.Time) error {
	certKey := certificateKey(options)
	keyKey := privateKeyKey(options)

	signer, replacementKeyPEM, err := loadOrCreateSigner(secret.Data[keyKey])
	if err != nil {
		return fmt.Errorf("load private key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: options.CommonName},
		NotBefore:             now.Add(-48 * time.Hour),
		NotAfter:              now.Add(-24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	if existing, parseErr := parseCertificate(secret.Data[certKey]); parseErr == nil {
		if template.Subject.CommonName == "" {
			template.Subject = existing.Subject
		}
		if len(options.DNSNames) == 0 {
			template.DNSNames = existing.DNSNames
		} else {
			template.DNSNames = options.DNSNames
		}
		template.IPAddresses = existing.IPAddresses
	} else {
		template.DNSNames = options.DNSNames
		if template.Subject.CommonName == "" && len(template.DNSNames) > 0 {
			template.Subject.CommonName = template.DNSNames[0]
		}
		if template.Subject.CommonName == "" {
			template.Subject.CommonName = "security-chaos-expired"
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		return fmt.Errorf("create expired certificate: %w", err)
	}
	secret.Data[certKey] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if len(secret.Data[keyKey]) == 0 || replacementKeyChanged(secret.Data[keyKey], replacementKeyPEM) {
		secret.Data[keyKey] = replacementKeyPEM
	}
	return nil
}

func injectKeyRotationFailure(secret *corev1.Secret, options Options) error {
	keyKey := privateKeyKey(options)
	mode := options.KeyFailureMode
	if mode == "" {
		mode = v1alpha1.MismatchedKeyFailure
	}

	switch mode {
	case v1alpha1.MissingKeyFailure:
		delete(secret.Data, keyKey)
		return nil
	case v1alpha1.CorruptedKeyFailure:
		secret.Data[keyKey] = []byte("-----BEGIN PRIVATE KEY-----\nY29ycnVwdGVkLWtleS1tYXRlcmlhbA==\n-----END PRIVATE KEY-----\n")
		return nil
	case v1alpha1.MismatchedKeyFailure:
		if len(secret.Data[certificateKey(options)]) == 0 {
			return errors.New("mismatched-key rotation failure requires an existing certificate")
		}
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("generate mismatched key: %w", err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return err
		}
		secret.Data[keyKey] = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		return nil
	default:
		return fmt.Errorf("unsupported key rotation failure mode %q", mode)
	}
}

func injectCorruptedCertificate(secret *corev1.Secret, options Options) {
	certKey := certificateKey(options)
	secret.Data[certKey] = []byte("-----BEGIN CERTIFICATE-----\naW52YWxpZC1jZXJ0aWZpY2F0ZS1tYXRlcmlhbA==\n-----END CERTIFICATE-----\n")
}

func loadOrCreateSigner(keyPEM []byte) (crypto.Signer, []byte, error) {
	if key, err := parsePrivateKey(keyPEM); err == nil {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, nil, err
		}
		return key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return key, keyPEM, nil
}

func parsePrivateKey(keyPEM []byte) (crypto.Signer, error) {
	if len(keyPEM) == 0 {
		return nil, errors.New("empty private key")
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("unsupported private key type %T", key)
	}
	return signer, nil
}

func parseCertificate(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("failed to decode certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func randomSerial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return big.NewInt(time.Now().UnixNano())
	}
	return serial
}

func certificateKey(options Options) string {
	if options.CertificateKey != "" {
		return options.CertificateKey
	}
	return defaultCertificateKey
}

func privateKeyKey(options Options) string {
	if options.PrivateKeyKey != "" {
		return options.PrivateKeyKey
	}
	return defaultPrivateKeyKey
}

func replacementKeyChanged(original, replacement []byte) bool {
	return string(original) != string(replacement)
}

func hashString(value string) string {
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%x", sum)
}
