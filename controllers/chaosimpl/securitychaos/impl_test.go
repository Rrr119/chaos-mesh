package securitychaos

import (
	"context"
	"testing"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/chaos-mesh/chaos-mesh/api/v1alpha1"
)

func TestSecurityChaosImplApplyAndRecover(t *testing.T) {
	tests := []struct {
		name   string
		action v1alpha1.SecurityChaosAction
		mode   v1alpha1.SecurityChaosKeyFailureMode
	}{
		{name: "certificate expiration", action: v1alpha1.CertificateExpirationAction},
		{name: "key rotation failure", action: v1alpha1.KeyRotationFailureAction, mode: v1alpha1.MismatchedKeyFailure},
		{name: "certificate corruption", action: v1alpha1.CertificateCorruptionAction},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "chaos-system", Name: "tls-target"},
				Data: map[string][]byte{
					"tls.crt": []byte("original-certificate"),
					"tls.key": []byte("original-key"),
					"other":   []byte("preserved"),
				},
			}
			k8sClient := newControllerFakeClient(t, secret)
			pair := NewImpl(k8sClient, logr.Discard())

			chaos := &v1alpha1.SecurityChaos{
				ObjectMeta: metav1.ObjectMeta{Namespace: "chaos-system", Name: "security-drill"},
				Spec: v1alpha1.SecurityChaosSpec{
					Action:                 tt.action,
					KeyRotationFailureMode: tt.mode,
					SecuritySelector: v1alpha1.SecuritySelector{
						SecretName: "tls-target",
					},
				},
			}
			records := []*v1alpha1.Record{{Id: "."}}

			phase, err := pair.Impl.Apply(ctx, 0, records, chaos)
			if err != nil {
				t.Fatalf("Apply() error = %v", err)
			}
			if phase != v1alpha1.Injected {
				t.Fatalf("Apply() phase = %q, want %q", phase, v1alpha1.Injected)
			}

			target := types.NamespacedName{Namespace: secret.Namespace, Name: secret.Name}
			injected := &corev1.Secret{}
			if err := k8sClient.Get(ctx, target, injected); err != nil {
				t.Fatalf("get injected secret: %v", err)
			}
			if string(injected.Data["other"]) != "preserved" {
				t.Fatal("non-credential data should be preserved")
			}
			if tt.action == v1alpha1.KeyRotationFailureAction && tt.mode == v1alpha1.MismatchedKeyFailure {
				if string(injected.Data["tls.key"]) == "original-key" {
					t.Fatal("key rotation failure should replace the private key")
				}
			}

			phase, err = pair.Impl.Recover(ctx, 0, records, chaos)
			if err != nil {
				t.Fatalf("Recover() error = %v", err)
			}
			if phase != v1alpha1.NotInjected {
				t.Fatalf("Recover() phase = %q, want %q", phase, v1alpha1.NotInjected)
			}

			recovered := &corev1.Secret{}
			if err := k8sClient.Get(ctx, target, recovered); err != nil {
				t.Fatalf("get recovered secret: %v", err)
			}
			if string(recovered.Data["tls.crt"]) != "original-certificate" {
				t.Fatal("tls.crt was not restored")
			}
			if string(recovered.Data["tls.key"]) != "original-key" {
				t.Fatal("tls.key was not restored")
			}
			if string(recovered.Data["other"]) != "preserved" {
				t.Fatal("other data was not restored")
			}
		})
	}
}

func TestRecoverIsIdempotentWithoutBackup(t *testing.T) {
	k8sClient := newControllerFakeClient(t)
	pair := NewImpl(k8sClient, logr.Discard())
	chaos := &v1alpha1.SecurityChaos{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "missing-backup"},
		Spec: v1alpha1.SecurityChaosSpec{
			Action:           v1alpha1.KeyRotationFailureAction,
			SecuritySelector: v1alpha1.SecuritySelector{SecretName: "target"},
		},
	}

	phase, err := pair.Impl.Recover(context.Background(), 0, nil, chaos)
	if err != nil {
		t.Fatalf("Recover() without backup should be idempotent, got error = %v", err)
	}
	if phase != v1alpha1.NotInjected {
		t.Fatalf("phase = %q, want %q", phase, v1alpha1.NotInjected)
	}
}

func newControllerFakeClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
}
