package securitychaos

import (
	"context"

	"github.com/go-logr/logr"
	"go.uber.org/fx"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/chaos-mesh/chaos-mesh/api/v1alpha1"
	impltypes "github.com/chaos-mesh/chaos-mesh/controllers/chaosimpl/types"
	securityengine "github.com/chaos-mesh/chaos-mesh/pkg/securitychaos"
)

var _ impltypes.ChaosImpl = (*Impl)(nil)

// Impl injects and recovers Secret backed security faults.
type Impl struct {
	client.Client
	Log    logr.Logger
	engine *securityengine.Engine
}

func (impl *Impl) Apply(ctx context.Context, _ int, _ []*v1alpha1.Record, object v1alpha1.InnerObject) (v1alpha1.Phase, error) {
	securityChaos, ok := object.(*v1alpha1.SecurityChaos)
	if !ok {
		return v1alpha1.NotInjected, incorrectTypeError(object)
	}

	target := targetSecret(securityChaos)
	backup := backupSecretName(securityChaos, target)
	options := securityengine.Options{
		CertificateKey:   securityChaos.Spec.CertificateKey,
		PrivateKeyKey:    securityChaos.Spec.PrivateKeyKey,
		CommonName:       securityChaos.Spec.CommonName,
		DNSNames:         securityChaos.Spec.DNSNames,
		KeyFailureMode:   securityChaos.Spec.KeyRotationFailureMode,
		BackupSecretName: backup,
	}

	if _, err := impl.engine.Apply(ctx, target, securityChaos.Spec.Action, options); err != nil {
		impl.Log.Error(err, "apply security chaos", "namespacedName", target)
		return v1alpha1.NotInjected, err
	}
	return v1alpha1.Injected, nil
}

func (impl *Impl) Recover(ctx context.Context, _ int, _ []*v1alpha1.Record, object v1alpha1.InnerObject) (v1alpha1.Phase, error) {
	securityChaos, ok := object.(*v1alpha1.SecurityChaos)
	if !ok {
		return v1alpha1.NotInjected, incorrectTypeError(object)
	}

	target := targetSecret(securityChaos)
	backup := backupSecretName(securityChaos, target)
	if err := impl.engine.Recover(ctx, target, backup); err != nil {
		if apierrors.IsNotFound(err) {
			return v1alpha1.NotInjected, nil
		}
		impl.Log.Error(err, "recover security chaos", "namespacedName", target)
		return v1alpha1.Injected, err
	}
	return v1alpha1.NotInjected, nil
}

func targetSecret(securityChaos *v1alpha1.SecurityChaos) types.NamespacedName {
	namespace := securityChaos.Spec.SecretNamespace
	if namespace == "" {
		namespace = securityChaos.Namespace
	}
	return types.NamespacedName{Namespace: namespace, Name: securityChaos.Spec.SecretName}
}

func backupSecretName(securityChaos *v1alpha1.SecurityChaos, target types.NamespacedName) string {
	return securityengine.BackupName(securityChaos.Namespace, securityChaos.Name, target.Namespace, target.Name)
}

func incorrectTypeError(object any) error {
	return &unexpectedTypeError{object: object}
}

type unexpectedTypeError struct {
	object any
}

func (err *unexpectedTypeError) Error() string {
	return "chaos object is not a SecurityChaos"
}

// NewImpl builds the common chaos implementation pair.
func NewImpl(client client.Client, logger logr.Logger) *impltypes.ChaosImplPair {
	impl := &Impl{
		Client: client,
		Log:    logger.WithName("securitychaos"),
		engine: securityengine.NewEngine(client),
	}
	return &impltypes.ChaosImplPair{
		Name:   "securitychaos",
		Object: &v1alpha1.SecurityChaos{},
		Impl:   impl,
	}
}

var Module = fx.Provide(
	fx.Annotated{
		Group:  "impl",
		Target: NewImpl,
	},
)
