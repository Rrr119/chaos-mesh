package v1alpha1

import (
	"encoding/json"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:printcolumn:name="action",type=string,JSONPath=`.spec.action`
// +kubebuilder:printcolumn:name="duration",type=string,JSONPath=`.spec.duration`
// +chaos-mesh:experiment
// +genclient

// SecurityChaos is the Schema for security credential fault injection.
type SecurityChaos struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SecurityChaosSpec   `json:"spec"`
	Status SecurityChaosStatus `json:"status,omitempty"`
}

var _ InnerObjectWithSelector = (*SecurityChaos)(nil)
var _ InnerObject = (*SecurityChaos)(nil)

// SecurityChaosAction describes the supported security fault.
type SecurityChaosAction string

const (
	// CertificateExpirationAction replaces the selected certificate with an expired one.
	CertificateExpirationAction SecurityChaosAction = "certificate-expiration"
	// CertificateExpiredAction is an alias of CertificateExpirationAction.
	CertificateExpiredAction SecurityChaosAction = "certificate-expired"
	// CertExpireAction is a short alias of CertificateExpirationAction.
	CertExpireAction SecurityChaosAction = "cert-expire"

	// KeyRotationFailureAction makes the rotated private key inconsistent with the certificate.
	KeyRotationFailureAction SecurityChaosAction = "key-rotation-failure"
	// KeyRotationFailedAction is an alias of KeyRotationFailureAction.
	KeyRotationFailedAction SecurityChaosAction = "key-rotation-failed"

	// CertificateCorruptionAction replaces the certificate PEM with invalid material.
	CertificateCorruptionAction SecurityChaosAction = "certificate-corruption"
	// CertificateRevocationAction is an operational alias for certificate trust failures.
	CertificateRevocationAction SecurityChaosAction = "certificate-revocation"
)

// SecurityChaosKeyFailureMode describes how a key rotation fails.
type SecurityChaosKeyFailureMode string

const (
	// MismatchedKeyFailure replaces the key with a new key that does not match the certificate.
	MismatchedKeyFailure SecurityChaosKeyFailureMode = "mismatched-key"
	// CorruptedKeyFailure replaces the key with invalid PEM material.
	CorruptedKeyFailure SecurityChaosKeyFailureMode = "corrupted-key"
	// MissingKeyFailure removes the private key from the secret.
	MissingKeyFailure SecurityChaosKeyFailureMode = "missing-key"
)

// SecurityChaosSpec defines the desired state of SecurityChaos.
type SecurityChaosSpec struct {
	// Action defines the security fault to inject.
	// +kubebuilder:validation:Enum=certificate-expiration;certificate-expired;cert-expire;key-rotation-failure;key-rotation-failed;certificate-corruption;certificate-revocation
	Action SecurityChaosAction `json:"action"`

	// Duration represents the duration of the chaos action.
	// +optional
	Duration *string `json:"duration,omitempty" webhook:"Duration"`

	SecuritySelector `json:",inline"`

	// KeyRotationFailureMode defines how key-rotation-failure breaks the credential.
	// +optional
	// +kubebuilder:validation:Enum=mismatched-key;corrupted-key;missing-key
	KeyRotationFailureMode SecurityChaosKeyFailureMode `json:"keyRotationFailureMode,omitempty"`

	// CommonName is used when a replacement certificate needs to be generated from scratch.
	// +optional
	CommonName string `json:"commonName,omitempty"`

	// DNSNames are used when a replacement certificate needs to be generated from scratch.
	// +optional
	DNSNames []string `json:"dnsNames,omitempty"`

	// RemoteCluster represents the remote cluster where the chaos will be deployed.
	// +optional
	RemoteCluster string `json:"remoteCluster,omitempty"`
}

// SecurityChaosStatus represents the observed state of SecurityChaos.
type SecurityChaosStatus struct {
	ChaosStatus `json:",inline"`
}

// SecuritySelector selects the Kubernetes secret that stores credential material.
type SecuritySelector struct {
	// SecretName is the name of the target secret.
	SecretName string `json:"secretName"`

	// SecretNamespace defaults to the namespace of the SecurityChaos.
	// +optional
	SecretNamespace string `json:"secretNamespace,omitempty"`

	// CertificateKey is the key in the secret that contains the PEM certificate.
	// +optional
	CertificateKey string `json:"certificateKey,omitempty"`

	// PrivateKeyKey is the key in the secret that contains the PEM private key.
	// +optional
	PrivateKeyKey string `json:"privateKeyKey,omitempty"`
}

// Id returns a stable selector identity for records and target selection.
func (selector *SecuritySelector) Id() string {
	data, _ := json.Marshal(selector)
	return string(data)
}

func (obj *SecurityChaos) GetSelectorSpecs() map[string]any {
	return map[string]any{
		".": &obj.Spec.SecuritySelector,
	}
}

// NormalizeSecurityChaosAction maps supported aliases to one of the canonical actions.
func NormalizeSecurityChaosAction(action SecurityChaosAction) SecurityChaosAction {
	switch action {
	case CertificateExpirationAction, CertificateExpiredAction, CertExpireAction:
		return CertificateExpirationAction
	case KeyRotationFailureAction, KeyRotationFailedAction:
		return KeyRotationFailureAction
	case CertificateCorruptionAction, CertificateRevocationAction:
		return CertificateCorruptionAction
	default:
		return action
	}
}
