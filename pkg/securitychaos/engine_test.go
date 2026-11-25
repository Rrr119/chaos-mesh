package securitychaos

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/chaos-mesh/chaos-mesh/api/v1alpha1"
)

var testTime = time.Date(2026, time.November, 25, 4, 0, 0, 0, time.UTC)

func TestCertificateExpirationInjectAndRecover(t *testing.T) {
	ctx := context.Background()
	secret, originalCertPEM := newTLSTestSecret(t, "default", "tls-secret")
	client := newFakeClient(t, secret)
	engine := NewEngine(client)
	target := types.NamespacedName{Namespace: secret.Namespace, Name: secret.Name}
	options := Options{Now: fixedNow, BackupSecretName: "security-backup-test"}

	backup, err := engine.Apply(ctx, target, v1alpha1.CertificateExpirationAction, options)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if backup != options.BackupSecretName {
		t.Fatalf("backup name = %q, want %q", backup, options.BackupSecretName)
	}

	injected := getSecret(t, client, target)
	certBlock, _ := pem.Decode(injected.Data["tls.crt"])
	if certBlock == nil {
		t.Fatal("injected tls.crt is not valid PEM")
	}
	injectedCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("parse injected certificate: %v", err)
	}
	if !injectedCert.NotAfter.Before(testTime) {
		t.Fatalf("NotAfter = %v, want before %v", injectedCert.NotAfter, testTime)
	}
	if _, err := tls.X509KeyPair(injected.Data["tls.crt"], injected.Data["tls.key"]); err != nil {
		t.Fatalf("expired certificate should still match its key: %v", err)
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(originalCertPEM) {
		t.Fatal("append original certificate to root pool")
	}
	_, err = injectedCert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: testTime})
	if err == nil {
		t.Fatal("injected certificate should fail verification at the injection time")
	}

	if err := engine.Recover(ctx, target, backup); err != nil {
		t.Fatalf("Recover() error = %v", err)
	}
	recovered := getSecret(t, client, target)
	assertSecretDataEqual(t, secret.Data, recovered.Data)
	if _, err := tls.X509KeyPair(recovered.Data["tls.crt"], recovered.Data["tls.key"]); err != nil {
		t.Fatalf("recovered key pair should be valid: %v", err)
	}
	assertBackupDeleted(t, client, target.Namespace, backup)
}

func TestKeyRotationFailureInjectAndRecover(t *testing.T) {
	for _, mode := range []v1alpha1.SecurityChaosKeyFailureMode{
		v1alpha1.MismatchedKeyFailure,
		v1alpha1.CorruptedKeyFailure,
		v1alpha1.MissingKeyFailure,
	} {
		t.Run(string(mode), func(t *testing.T) {
			ctx := context.Background()
			secret, _ := newTLSTestSecret(t, "default", "tls-secret-"+string(mode))
			client := newFakeClient(t, secret)
			engine := NewEngine(client)
			target := types.NamespacedName{Namespace: secret.Namespace, Name: secret.Name}
			backupName := "security-backup-" + string(mode)

			backup, err := engine.Apply(ctx, target, v1alpha1.KeyRotationFailedAction, Options{
				KeyFailureMode:   mode,
				BackupSecretName: backupName,
			})
			if err != nil {
				t.Fatalf("Apply() error = %v", err)
			}

			injected := getSecret(t, client, target)
			switch mode {
			case v1alpha1.MismatchedKeyFailure:
				if _, err := tls.X509KeyPair(injected.Data["tls.crt"], injected.Data["tls.key"]); err == nil {
					t.Fatal("mismatched key should not form a valid key pair")
				}
			case v1alpha1.CorruptedKeyFailure:
				if _, err := tls.X509KeyPair(injected.Data["tls.crt"], injected.Data["tls.key"]); err == nil {
					t.Fatal("corrupted key should not parse")
				}
			case v1alpha1.MissingKeyFailure:
				if _, ok := injected.Data["tls.key"]; ok {
					t.Fatal("tls.key should be removed")
				}
			}

			if err := engine.Recover(ctx, target, backup); err != nil {
				t.Fatalf("Recover() error = %v", err)
			}
			recovered := getSecret(t, client, target)
			assertSecretDataEqual(t, secret.Data, recovered.Data)
			if _, err := tls.X509KeyPair(recovered.Data["tls.crt"], recovered.Data["tls.key"]); err != nil {
				t.Fatalf("recovered key pair should be valid: %v", err)
			}
			assertBackupDeleted(t, client, target.Namespace, backupName)
		})
	}
}

func TestCertificateCorruptionInjectAndRecover(t *testing.T) {
	ctx := context.Background()
	secret, _ := newTLSTestSecret(t, "default", "tls-corrupt")
	client := newFakeClient(t, secret)
	engine := NewEngine(client)
	target := types.NamespacedName{Namespace: secret.Namespace, Name: secret.Name}

	backup, err := engine.Apply(ctx, target, v1alpha1.CertificateRevocationAction, Options{
		BackupSecretName: "security-backup-corrupt",
	})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	injected := getSecret(t, client, target)
	if _, err := tls.X509KeyPair(injected.Data["tls.crt"], injected.Data["tls.key"]); err == nil {
		t.Fatal("corrupted certificate should not form a valid key pair")
	}

	if err := engine.Recover(ctx, target, backup); err != nil {
		t.Fatalf("Recover() error = %v", err)
	}
	recovered := getSecret(t, client, target)
	assertSecretDataEqual(t, secret.Data, recovered.Data)
	assertBackupDeleted(t, client, target.Namespace, backup)
}

func TestApplyIsIdempotentAndPreservesOriginalBackup(t *testing.T) {
	ctx := context.Background()
	secret, _ := newTLSTestSecret(t, "default", "tls-idempotent")
	client := newFakeClient(t, secret)
	engine := NewEngine(client)
	target := types.NamespacedName{Namespace: secret.Namespace, Name: secret.Name}
	options := Options{Now: fixedNow, BackupSecretName: "security-backup-idempotent"}

	if _, err := engine.Apply(ctx, target, v1alpha1.CertificateExpirationAction, options); err != nil {
		t.Fatalf("first Apply() error = %v", err)
	}
	if _, err := engine.Apply(ctx, target, v1alpha1.CertificateExpirationAction, options); err != nil {
		t.Fatalf("second Apply() error = %v", err)
	}
	secondInjection := getSecret(t, client, target)
	certBlock, _ := pem.Decode(secondInjection.Data["tls.crt"])
	if certBlock == nil {
		t.Fatal("second injection did not produce PEM certificate")
	}

	backup := getSecret(t, client, types.NamespacedName{Namespace: target.Namespace, Name: options.BackupSecretName})
	assertSecretDataEqual(t, secret.Data, backup.Data)
}

func TestApplyRejectsUnsupportedFaultBeforeCreatingBackup(t *testing.T) {
	ctx := context.Background()
	secret, _ := newTLSTestSecret(t, "default", "tls-invalid")
	client := newFakeClient(t, secret)
	engine := NewEngine(client)
	target := types.NamespacedName{Namespace: secret.Namespace, Name: secret.Name}

	_, err := engine.Apply(ctx, target, "not-a-security-fault", Options{
		BackupSecretName: "security-backup-invalid-action",
	})
	if err == nil {
		t.Fatal("Apply() should reject an unsupported action")
	}

	backup := &corev1.Secret{}
	err = client.Get(ctx, types.NamespacedName{Namespace: target.Namespace, Name: "security-backup-invalid-action"}, backup)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("unsupported action should not create a backup, Get() error = %v", err)
	}

	_, err = engine.Apply(ctx, target, v1alpha1.KeyRotationFailureAction, Options{
		KeyFailureMode:   "not-a-mode",
		BackupSecretName: "security-backup-invalid-mode",
	})
	if err == nil {
		t.Fatal("Apply() should reject an unsupported key failure mode")
	}

	err = client.Get(ctx, types.NamespacedName{Namespace: target.Namespace, Name: "security-backup-invalid-mode"}, backup)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("unsupported mode should not create a backup, Get() error = %v", err)
	}
}

func newTLSTestSecret(t *testing.T, namespace, name string) (*corev1.Secret, []byte) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "security-chaos.test"},
		NotBefore:             testTime.Add(-time.Hour),
		NotAfter:              testTime.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"security-chaos.test"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": certPEM,
			"tls.key": keyPEM,
		},
	}, certPEM
}

func newFakeClient(t *testing.T, objects ...runtime.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objects...).Build()
}

func getSecret(t *testing.T, c client.Client, key types.NamespacedName) *corev1.Secret {
	t.Helper()
	secret := &corev1.Secret{}
	if err := c.Get(context.Background(), key, secret); err != nil {
		t.Fatalf("get secret %s: %v", key, err)
	}
	return secret
}

func assertSecretDataEqual(t *testing.T, want, got map[string][]byte) {
	t.Helper()
	if len(want) != len(got) {
		t.Fatalf("data length = %d, want %d: %#v", len(got), len(want), got)
	}
	for key, expected := range want {
		if string(expected) != string(got[key]) {
			t.Fatalf("data key %q was not restored", key)
		}
	}
}

func assertBackupDeleted(t *testing.T, c client.Client, namespace, name string) {
	t.Helper()
	err := c.Get(context.Background(), types.NamespacedName{Namespace: namespace, Name: name}, &corev1.Secret{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("backup %s should be deleted, err=%v", name, err)
	}
}

func fixedNow() time.Time {
	return testTime
}
