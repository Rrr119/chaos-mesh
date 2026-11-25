package v1alpha1

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestSecurityChaosWebhookDefaultsAndValidation(t *testing.T) {
	securityChaos := &SecurityChaos{
		ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "cert-drill"},
		Spec: SecurityChaosSpec{
			Action:           KeyRotationFailedAction,
			SecuritySelector: SecuritySelector{SecretName: "tls"},
		},
	}

	if err := securityChaos.Default(context.Background(), securityChaos); err != nil {
		t.Fatalf("Default() error = %v", err)
	}
	if securityChaos.Spec.SecretNamespace != "demo" {
		t.Fatalf("SecretNamespace = %q, want demo", securityChaos.Spec.SecretNamespace)
	}
	if securityChaos.Spec.CertificateKey != "tls.crt" {
		t.Fatalf("CertificateKey = %q, want tls.crt", securityChaos.Spec.CertificateKey)
	}
	if securityChaos.Spec.PrivateKeyKey != "tls.key" {
		t.Fatalf("PrivateKeyKey = %q, want tls.key", securityChaos.Spec.PrivateKeyKey)
	}
	if securityChaos.Spec.KeyRotationFailureMode != MismatchedKeyFailure {
		t.Fatalf("KeyRotationFailureMode = %q, want %q", securityChaos.Spec.KeyRotationFailureMode, MismatchedKeyFailure)
	}
	if _, err := securityChaos.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	securityChaos.Spec.Action = "not-a-security-fault"
	if _, err := securityChaos.Validate(); err == nil {
		t.Fatal("Validate() should reject an unknown action")
	}
}

func TestSecurityChaosWorkflowCompatibility(t *testing.T) {
	spec := SecurityChaosSpec{
		Action: CertificateExpirationAction,
		SecuritySelector: SecuritySelector{
			SecretName:      "service-tls",
			SecretNamespace: "demo",
		},
	}

	if !IsChaosTemplateType(TypeSecurityChaos) {
		t.Fatal("SecurityChaos should be a workflow chaos template type")
	}

	embed := &EmbedChaos{SecurityChaos: &spec}
	object, err := embed.SpawnNewObject(TypeSecurityChaos)
	if err != nil {
		t.Fatalf("SpawnNewObject() error = %v", err)
	}
	securityChaos, ok := object.(*SecurityChaos)
	if !ok {
		t.Fatalf("spawned object type = %T, want *SecurityChaos", object)
	}
	if securityChaos.Spec.Action != CertificateExpirationAction {
		t.Fatalf("spawned action = %q, want %q", securityChaos.Spec.Action, CertificateExpirationAction)
	}
	if securityChaos.Spec.SecretName != "service-tls" {
		t.Fatalf("spawned secretName = %q", securityChaos.Spec.SecretName)
	}

	workflow := &Workflow{
		Spec: WorkflowSpec{
			Entry: "security",
			Templates: []Template{{
				Name:       "expire-certificate",
				Type:       TypeSecurityChaos,
				EmbedChaos: embed,
			}},
		},
	}
	template := workflow.Spec.Templates[0]
	if template.Type != TypeSecurityChaos || template.SecurityChaos == nil {
		t.Fatal("workflow template should contain inline SecurityChaos spec")
	}

	restored := &EmbedChaos{SecurityChaos: &SecurityChaosSpec{}}
	if err := restored.RestoreChaosSpec(securityChaos); err != nil {
		t.Fatalf("RestoreChaosSpec() error = %v", err)
	}
	if restored.SecurityChaos.SecretName != spec.SecretName {
		t.Fatalf("restored secretName = %q, want %q", restored.SecurityChaos.SecretName, spec.SecretName)
	}
}

func TestSecurityChaosScheduleCompatibility(t *testing.T) {
	spec := SecurityChaosSpec{
		Action:                 KeyRotationFailureAction,
		KeyRotationFailureMode: MissingKeyFailure,
		SecuritySelector:       SecuritySelector{SecretName: "service-tls"},
	}
	item := &ScheduleItem{EmbedChaos: EmbedChaos{SecurityChaos: &spec}}

	object, err := item.SpawnNewObject(ScheduleTypeSecurityChaos)
	if err != nil {
		t.Fatalf("SpawnNewObject() error = %v", err)
	}
	securityChaos, ok := object.(*SecurityChaos)
	if !ok {
		t.Fatalf("spawned object type = %T, want *SecurityChaos", object)
	}
	if securityChaos.Spec.KeyRotationFailureMode != MissingKeyFailure {
		t.Fatalf("mode = %q, want %q", securityChaos.Spec.KeyRotationFailureMode, MissingKeyFailure)
	}
	if _, ok := AllScheduleItemKinds()[KindSecurityChaos]; !ok {
		t.Fatal("SecurityChaos should be registered as a schedule item kind")
	}
	if _, ok := AllKinds()[KindSecurityChaos]; !ok {
		t.Fatal("SecurityChaos should be registered as a chaos kind")
	}
}
