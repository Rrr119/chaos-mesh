package v1alpha1

import (
	"reflect"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

const (
	defaultCertificateKey = "tls.crt"
	defaultPrivateKeyKey  = "tls.key"
)

// Default fills conventional TLS secret keys and the chaos namespace.
func (selector *SecuritySelector) Default(root any, _ *reflect.StructField) {
	if selector == nil {
		return
	}
	if selector.SecretNamespace == "" {
		if object, err := meta.Accessor(root); err == nil {
			selector.SecretNamespace = object.GetNamespace()
		}
	}
	if selector.CertificateKey == "" {
		selector.CertificateKey = defaultCertificateKey
	}
	if selector.PrivateKeyKey == "" {
		selector.PrivateKeyKey = defaultPrivateKeyKey
	}
}

// Validate checks that the selector identifies a secret.
func (selector *SecuritySelector) Validate(_ any, path *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	if selector == nil {
		return append(allErrs, field.Required(path, "security selector is required"))
	}
	if selector.SecretName == "" {
		allErrs = append(allErrs, field.Required(path.Child("secretName"), "secretName is required"))
	}
	if selector.CertificateKey == "" {
		allErrs = append(allErrs, field.Required(path.Child("certificateKey"), "certificateKey is required"))
	}
	if selector.PrivateKeyKey == "" {
		allErrs = append(allErrs, field.Required(path.Child("privateKeyKey"), "privateKeyKey is required"))
	}
	return allErrs
}

// Validate checks the action enum, including supported aliases.
func (action *SecurityChaosAction) Validate(_ any, path *field.Path) field.ErrorList {
	if action == nil {
		return field.ErrorList{field.Required(path, "action is required")}
	}

	switch NormalizeSecurityChaosAction(*action) {
	case CertificateExpirationAction, KeyRotationFailureAction, CertificateCorruptionAction:
		return nil
	default:
		return field.ErrorList{field.NotSupported(path, *action, []string{
			string(CertificateExpirationAction),
			string(KeyRotationFailureAction),
			string(CertificateCorruptionAction),
		})}
	}
}

// Validate checks the key rotation failure mode enum.
func (mode *SecurityChaosKeyFailureMode) Validate(_ any, path *field.Path) field.ErrorList {
	if mode == nil || *mode == "" {
		return nil
	}
	switch *mode {
	case MismatchedKeyFailure, CorruptedKeyFailure, MissingKeyFailure:
		return nil
	default:
		return field.ErrorList{field.NotSupported(path, *mode, []string{
			string(MismatchedKeyFailure),
			string(CorruptedKeyFailure),
			string(MissingKeyFailure),
		})}
	}
}

// Default sets the default failure mode for key rotation faults.
func (mode *SecurityChaosKeyFailureMode) Default(_ any, _ *reflect.StructField) {
	if mode != nil && *mode == "" {
		*mode = MismatchedKeyFailure
	}
}
